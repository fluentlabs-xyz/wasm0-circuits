use eth_types::{GethExecStep, U256};
use eth_types::evm_types::MemoryAddress;

use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::Error;
use crate::operation::CallContextField;

use super::Opcode;

pub const ADDRESS_BYTE_LENGTH: usize = 20;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Address;

impl Opcode for Address {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let geth_second_step = &geth_steps[1];
        let mut exec_step = state.new_step(geth_step)?;

        // Get address result from next step.
        let address = &geth_second_step.memory.0;
        if address.len() != ADDRESS_BYTE_LENGTH {
            return Err(Error::InvalidGethExecTrace("there is no address bytes in memory for address opcode"));
        }

        // Read the callee address in call context.
        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::CalleeAddress,
            U256::from_big_endian(address),
        );

        // Read dest offset as the last stack element
        let dest_offset = geth_step.stack.nth_last(0)?;
        state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(0), dest_offset)?;
        let offset_addr = MemoryAddress::try_from(dest_offset)?;

        // Copy result to memory
        for i in 0..ADDRESS_BYTE_LENGTH {
            state.memory_write(&mut exec_step, offset_addr.map(|a| a + i), address[i])?;
        }
        let call_ctx = state.call_ctx_mut()?;
        call_ctx.memory = geth_second_step.memory.clone();

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod address_tests {
    use pretty_assertions::assert_eq;

    use eth_types::{bytecode, Bytecode, evm_types::{OpcodeId, StackAddress}, geth_types::GethData, ToWord, Word};
    use mock::test_ctx::{helpers::*, TestContext};

    use crate::{
        circuit_input_builder::ExecState, mocks::BlockData, operation::CallContextOp,
        operation::RW, operation::StackOp,
    };
    use crate::operation::MemoryOp;

    use super::*;

    #[test]
    fn address_opcode_impl() {
        let res_mem_address = 0x7f;
        let code = bytecode! {
            I32Const[res_mem_address]
            ADDRESS
        };

        // Get the execution steps from the external tracer.
        let wasm_bytecode = Bytecode::from_raw_unchecked(code.wasm_binary());
        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(wasm_bytecode),
            tx_from_1_to_0,
            |block, _tx| block.number(0xcafe_u64),
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
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::ADDRESS))
            .unwrap();

        let call_id = builder.block.txs()[0].calls()[0].call_id;
        let address = block.eth_block.transactions[0].to.unwrap();
        let address_bytes = address.to_fixed_bytes();
        assert_eq!(step.bus_mapping_instance.len(), ADDRESS_BYTE_LENGTH + 2);
        assert_eq!(
            {
                let operation =
                    &builder.block.container.call_context[step.bus_mapping_instance[0].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::READ,
                &CallContextOp {
                    call_id,
                    field: CallContextField::CalleeAddress,
                    value: address.to_word(),
                }
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
                &StackOp::new(1, StackAddress::from(1022), Word::from(res_mem_address))
            )
        );
        for idx in 0..ADDRESS_BYTE_LENGTH {
            assert_eq!(
                {
                    let operation =
                        &builder.block.container.memory[step.bus_mapping_instance[2 + idx].as_usize()];
                    (operation.rw(), operation.op())
                },
                (
                    RW::WRITE,
                    &MemoryOp::new(1, MemoryAddress::from(res_mem_address + idx as i32), address_bytes[idx])
                )
            );
        }
    }
}
