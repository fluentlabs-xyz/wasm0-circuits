use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    operation::CallContextField,
    Error,
};

use eth_types::{GethExecStep, U256};
use eth_types::evm_types::MemoryAddress;

use super::Opcode;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Calldatasize;
impl Opcode for Calldatasize {
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
            CallContextField::CallDataLength,
            U256::from_big_endian(value),
        );

        // Read dest offset as the last stack element
        let dest_offset = step.stack.nth_last(0)?;
        state.stack_read(&mut exec_step, step.stack.nth_last_filled(0), dest_offset)?;
        let offset_addr = MemoryAddress::try_from(dest_offset)?;

        // Copy result to memory
        for i in 0..4 {
            state.memory_write(&mut exec_step, offset_addr.map(|a| a + i), value[i])?;
        }
        let call_ctx = state.call_ctx_mut()?;
        call_ctx.memory = second_step.memory.clone();

        Ok(vec![exec_step])
    }
}
#[cfg(test)]
mod calldatasize_tests {
    use crate::{
        circuit_input_builder::ExecState,
        mock::BlockData,
        operation::{CallContextField, CallContextOp, StackOp, RW},
    };
    use eth_types::{bytecode, evm_types::{OpcodeId, StackAddress}, geth_types::GethData, U256};
    use mock::test_ctx::{helpers::*, TestContext};
    use pretty_assertions::assert_eq;
    #[test]
    fn calldatasize_opcode_impl() {
        let code = bytecode! {
            I32Const[0x79]
            CALLDATASIZE
        };
        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
            tx_from_1_to_0,
            |block, _tx| block.number(0xcafeu64),
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
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::CALLDATASIZE))
            .unwrap();
        let call_id = builder.block.txs()[0].calls()[0].call_id;
        let call_data_size = block.eth_block.transactions[0].input.as_ref().len().into();
        assert_eq!(step.bus_mapping_instance.len(), 6);
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
                    field: CallContextField::CallDataLength,
                    value: call_data_size,
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
                &StackOp::new(1, StackAddress::from(1022), U256::from(0x79))
            )
        );
    }
}