use eth_types::evm_types::MemoryAddress;
use super::Opcode;
use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::operation::CallContextField;
use crate::Error;
use eth_types::GethExecStep;

/// Placeholder structure used to implement [`Opcode`] trait over it
/// corresponding to the [`OpcodeId::PC`](crate::evm::OpcodeId::PC) `OpcodeId`.
#[derive(Debug, Copy, Clone)]
pub(crate) struct GasPrice;

impl Opcode for GasPrice {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let step = &geth_steps[0];
        let second_step = &geth_steps[1];
        let mut exec_step = state.new_step(step)?;
        // Get gasprice result from next step
        let value = &second_step.memory.0;
        let tx_id = state.tx_ctx.id();

        // CallContext read of the TxId
        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::TxId,
            tx_id.into(),
        );

        // Read dest offset as the last stack element
        let dest_offset = step.stack.nth_last(0)?;
        state.stack_read(&mut exec_step, step.stack.nth_last_filled(0), dest_offset)?;
        let offset_addr = MemoryAddress::try_from(dest_offset)?;

        // Copy result to memory
        for i in 0..20 {
            state.memory_write(&mut exec_step, offset_addr.map(|a| a + i), value[i])?;
        }
        let call_ctx = state.call_ctx_mut()?;
        call_ctx.memory = second_step.memory.clone();

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod gasprice_tests {
    use std::fs;
    use crate::{
        circuit_input_builder::ExecState,
        evm::OpcodeId,
        mock::BlockData,
        operation::{CallContextField, CallContextOp, StackOp, RW},
        Error,
    };
    use eth_types::{bytecode, evm_types::StackAddress, geth_types::GethData, ToBigEndian, Word};
    use mock::test_ctx::{helpers::*, TestContext};
    use pretty_assertions::assert_eq;
    use eth_types::evm_types::MemoryAddress;
    use crate::operation::MemoryOp;

    #[test]
    fn gasprice_opcode_impl() -> Result<(), Error> {
        let mem_address = 0x7f;
        let code = bytecode! {
            I32Const[mem_address]
            GASPRICE
        };

        let two_gwei = Word::from(2_000_000_000u64);

        // Get the execution steps from the external tracer
        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(code),
            |mut txs, accs| {
                txs[0]
                    .from(accs[1].address)
                    .to(accs[0].address)
                    .gas_price(two_gwei);
            },
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
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::GASPRICE))
            .unwrap();

        let op_gasprice = &builder.block.container.stack[step.bus_mapping_instance[1].as_usize()];
        let gas_price = block.eth_block.transactions[0].gas_price.unwrap();
        let gas_price_bytes = gas_price.to_be_bytes();
        assert_eq!(step.bus_mapping_instance.len(), 22);
        assert_eq!(
            (op_gasprice.rw(), op_gasprice.op()),
            (
                RW::READ,
                &StackOp::new(1, StackAddress(1022usize), Word::from(mem_address))
            )
        );

        let call_id = builder.block.txs()[0].calls()[0].call_id;
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
                    field: CallContextField::TxId,
                    value: Word::one(),
                }
            )
        );
        for idx in 0..20 {
            assert_eq!(
                {
                    let operation =
                        &builder.block.container.memory[step.bus_mapping_instance[2 + idx].as_usize()];
                    (operation.rw(), operation.op())
                },
                (
                    RW::WRITE,
                    &MemoryOp::new(1, MemoryAddress::from(mem_address + idx as i32), gas_price_bytes[idx])
                )
            );
        }

        Ok(())
    }
}
