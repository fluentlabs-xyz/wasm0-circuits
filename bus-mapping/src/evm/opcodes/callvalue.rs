use eth_types::evm_types::MemoryAddress;
use super::Opcode;
use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::operation::CallContextField;
use crate::Error;
use eth_types::{GethExecStep, U256};

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the [`OpcodeId::PC`](crate::evm::OpcodeId::PC) `OpcodeId`.
#[derive(Debug, Copy, Clone)]
pub(crate) struct Callvalue;

impl Opcode for Callvalue {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let geth_second_step = &geth_steps[1];
        let mut exec_step = state.new_step(geth_step)?;
        // Get call_value result from next step
        let value = &geth_second_step.memory.0;
        // CallContext read of the call_value
        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::Value,
            U256::from_big_endian(value),
        );

        // Read dest offset as the last stack element
        let dest_offset = geth_step.stack.nth_last(0)?;
        state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(0), dest_offset)?;
        let offset_addr = MemoryAddress::try_from(dest_offset)?;

        // Copy result to memory
        for i in 0..32 {
            state.memory_write(&mut exec_step, offset_addr.map(|a| a + i), value[i])?;
        }
        let call_ctx = state.call_ctx_mut()?;
        call_ctx.memory = geth_second_step.memory.clone();

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod callvalue_tests {
    use crate::{
        circuit_input_builder::ExecState,
        mock::BlockData,
        operation::{CallContextField, CallContextOp, StackOp, RW},
    };
    use eth_types::{bytecode, evm_types::{OpcodeId, StackAddress}, geth_types::GethData, ToWord, Word};
    use mock::test_ctx::{helpers::*, TestContext};
    use pretty_assertions::assert_eq;

    #[test]
    fn callvalue_opcode_impl() {
        let mem_address = 0x7f;
        let code = bytecode! {
            I32Const[mem_address]
            CALLVALUE
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
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::CALLVALUE))
            .unwrap();

        let call_id = builder.block.txs()[0].calls()[0].call_id;
        let call_value = block.eth_block.transactions[0].value;
        assert_eq!(step.bus_mapping_instance.len(), 34);
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
                    field: CallContextField::Value,
                    value: call_value.to_word(),
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
                &StackOp::new(1, StackAddress::from(1022), Word::from(mem_address))
            )
        );
    }
}
