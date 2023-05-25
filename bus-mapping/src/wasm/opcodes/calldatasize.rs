use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    operation::CallContextField,
    Error,
};

use eth_types::{GethExecStep, ToBigEndian, ToU256};
use eth_types::evm_types::MemoryAddress;

use super::Opcode;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Calldatasize;

impl Opcode for Calldatasize {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;
        let dest = geth_step.stack.last()?;
        let value = geth_steps[1].global_memory.read_u32(dest)?;
        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::CallDataLength,
            value.to_u256(),
        );
        state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(0), dest)?;
        let dest_addr = MemoryAddress::try_from(dest)?;
        let values_bytes = value.to_be_bytes();
        for i in 0..8 {
            state.memory_write(&mut exec_step, dest_addr.map(|a| a + i), values_bytes[24+i])?;
        }
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
    use eth_types::{
        bytecode,
        evm_types::{OpcodeId, StackAddress},
        geth_types::GethData,
    };

    use mock::test_ctx::{helpers::*, TestContext};
    use pretty_assertions::assert_eq;

    #[test]
    fn calldatasize_opcode_impl() {
        let code = bytecode! {
            CALLDATASIZE
            STOP
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
                RW::WRITE,
                &StackOp::new(1, StackAddress::from(1023), call_data_size)
            )
        );
    }
}
