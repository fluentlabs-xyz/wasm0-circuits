use eth_types::{GethExecStep, ToBigEndian, U256};
use eth_types::evm_types::MemoryAddress;

use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::Error;
use crate::operation::CallContextField;

use super::Opcode;

pub const CHAIN_ID_BYTE_LENGTH: usize = 32;

#[derive(Debug, Copy, Clone)]
pub(crate) struct ChainId;

impl Opcode for ChainId {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let geth_second_step = &geth_steps[1];
        let mut exec_step = state.new_step(geth_step)?;
        let chain_id = U256::from_big_endian(&geth_second_step.memory.0);
        let chain_id = chain_id.to_be_bytes();

        // Read dest offset as the last stack element
        let dest_offset = geth_step.stack.nth_last(0)?;
        state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(0), dest_offset)?;
        let offset_addr = MemoryAddress::try_from(dest_offset)?;

        // Copy result to memory
        for i in 0..CHAIN_ID_BYTE_LENGTH {
            state.memory_write(&mut exec_step, offset_addr.map(|a| a + i), chain_id[i])?;
        }
        let call_ctx = state.call_ctx_mut()?;
        call_ctx.memory = geth_second_step.memory.clone();

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod chainid_tests {
    use pretty_assertions::assert_eq;

    use eth_types::{bytecode, evm_types::{OpcodeId, StackAddress}, geth_types::GethData, StackWord, ToBigEndian, Word};
    use eth_types::evm_types::MemoryAddress;
    use mock::test_ctx::{helpers::*, TestContext};

    use crate::{circuit_input_builder::ExecState, mocks::BlockData, operation::StackOp};
    use crate::evm::opcodes::chainid::CHAIN_ID_BYTE_LENGTH;
    use crate::operation::{CallContextField, CallContextOp, MemoryOp, RW};

    #[test]
    fn chainid_opcode_impl() {
        let res_mem_address = 0x7f;
        let code = bytecode! {
            I32Const[res_mem_address]
            CHAINID
        };

        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code, None),
            tx_from_1_to_0,
            |block, _tx| block,
        )
            .unwrap()
            .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();

        let step = builder.block.txs()[0]
            .steps()
            .iter()
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::CHAINID))
            .unwrap();

        assert_eq!(step.bus_mapping_instance.len(), CHAIN_ID_BYTE_LENGTH + 2);
        let chain_id = block.eth_block.transactions[0].chain_id.unwrap();
        let chain_id_bytes = chain_id.to_be_bytes();
        assert_eq!(
            {
                let operation =
                    &builder.block.container.call_context[step.bus_mapping_instance[0].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::READ,
                &CallContextOp::new(1, CallContextField::TxId, Word::one())
            )
        );
        assert_eq!(
            {
                let operation =
                    &builder.block.container.stack[step.bus_mapping_instance[1].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::READ,
                &StackOp::new(1, StackAddress::from(1023), StackWord::from(res_mem_address))
            )
        );

        for idx in 0..CHAIN_ID_BYTE_LENGTH {
            assert_eq!(
                {
                    let operation =
                        &builder.block.container.memory[step.bus_mapping_instance[2 + idx].as_usize()];
                    (operation.rw(), operation.op())
                },
                (
                    RW::WRITE,
                    &MemoryOp::new(1, MemoryAddress::from(res_mem_address + idx as i32), chain_id_bytes[idx])
                )
            );
        }
    }
}
