use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::operation::CallContextField;
use crate::Error;
use eth_types::{GethExecStep, U256};
use eth_types::evm_types::MemoryAddress;
use crate::evm::Opcode;

pub const NUMBER_BYTE_LENGTH: usize = 8;

#[derive(Debug, Copy, Clone)]
pub(crate) struct Number;

impl Opcode for Number {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let step = &geth_steps[0];
        let second_step = &geth_steps[1];
        let mut exec_step = state.new_step(step)?;
        let value = &second_step.memory.0;

        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::Value,
            U256::from_big_endian(value),
        );

        // Read dest offset as the last stack element
        let dest_offset = step.stack.nth_last(0)?;
        state.stack_read(&mut exec_step, step.stack.nth_last_filled(0), dest_offset)?;
        let offset_addr = MemoryAddress::try_from(dest_offset)?;

        // Copy result to memory
        for i in 0..NUMBER_BYTE_LENGTH {
            state.memory_write(&mut exec_step, offset_addr.map(|a| a + i), value[i])?;
        }
        let call_ctx = state.call_ctx_mut()?;
        call_ctx.memory = second_step.memory.clone();

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod number_tests {
    use crate::{
        circuit_input_builder::ExecState,
        evm::OpcodeId,
        mocks::BlockData,
        operation::{StackOp, RW},
        Error,
    };
    use eth_types::{bytecode, evm_types::StackAddress, geth_types::GethData, StackWord, Word};
    use mock::test_ctx::{helpers::*, TestContext};
    use pretty_assertions::assert_eq;
    use eth_types::evm_types::MemoryAddress;
    use crate::evm::opcodes::number::NUMBER_BYTE_LENGTH;
    use crate::operation::MemoryOp;

    #[test]
    fn number_opcode_impl() -> Result<(), Error> {
        let res_mem_address = 0x7f;
        let code = bytecode! {
            I32Const[res_mem_address]
            NUMBER
        };
        let block_number: u64 = 0xcafe;
        let block_number_bytes = block_number.to_be_bytes();
        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code, None),
            tx_from_1_to_0,
            |block, _tx| block.number(block_number),
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
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::NUMBER))
            .unwrap();

        let op_number = &builder.block.container.stack[step.bus_mapping_instance[1].as_usize()];
        assert_eq!(
            (op_number.rw(), op_number.op()),
            (
                RW::READ,
                &StackOp::new(1, StackAddress(1023usize), StackWord::from(res_mem_address))
            )
        );

        for idx in 0..NUMBER_BYTE_LENGTH {
            assert_eq!(
                {
                    let operation =
                        &builder.block.container.memory[step.bus_mapping_instance[2 + idx].as_usize()];
                    (operation.rw(), operation.op())
                },
                (
                    RW::WRITE,
                    &MemoryOp::new(
                        1,
                        MemoryAddress::from(res_mem_address + idx as i32),
                        block_number_bytes[idx]
                    )
                )
            );
        }

        Ok(())
    }
}
