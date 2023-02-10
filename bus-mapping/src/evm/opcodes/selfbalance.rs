use std::io::Read;
use super::Opcode;
use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::operation::{AccountField, CallContextField};
use crate::Error;
use eth_types::{GethExecStep, ToBigEndian, ToWord, U256};
use eth_types::evm_types::MemoryAddress;

#[derive(Debug, Copy, Clone)]
pub(crate) struct Selfbalance;

impl Opcode for Selfbalance {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let geth_second_step = &geth_steps[1];
        let mut exec_step = state.new_step(geth_step)?;
        // let self_balance = geth_second_step.stack.last()?;
        let self_balance = &geth_second_step.memory.0;;
        let callee_address = state.call()?.address;

        // CallContext read of the callee_address
        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::CalleeAddress,
            callee_address.to_word(),
        );

        // Account read for the balance of the callee_address
        state.account_read(
            &mut exec_step,
            callee_address,
            AccountField::Balance,
            U256::from_big_endian(self_balance),
            U256::from_big_endian(self_balance),
        )?;

        // Copy result to memory
        // Read dest offset as the last stack element
        let dest_offset = geth_step.stack.nth_last(0)?;
        state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(0), dest_offset)?;
        let offset_addr = MemoryAddress::try_from(dest_offset)?;

        // Copy result to memory
        for i in 0..32 {
            state.memory_write(&mut exec_step, offset_addr.map(|a| a + i), self_balance[i])?;
        }
        let call_ctx = state.call_ctx_mut()?;
        call_ctx.memory = geth_second_step.memory.clone();

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod selfbalance_tests {
    use std::fs;
    use super::*;
    use crate::{
        circuit_input_builder::ExecState,
        mock::BlockData,
        operation::{AccountOp, CallContextField, CallContextOp, StackOp, RW},
    };
    use eth_types::{
        bytecode,
        evm_types::{OpcodeId, StackAddress},
        geth_types::GethData,
    };
    use mock::test_ctx::{helpers::*, TestContext};
    use pretty_assertions::assert_eq;

    #[test]
    fn selfbalance_opcode_impl() {
        let res_mem_address = 0x7f;
        let code = bytecode! {
            I32Const[res_mem_address]
            SELFBALANCE
        };

        // TODO dies inside [external-tracer/src/lib.rs:74] on low level string transformation (detect some unconvertable chars/bytes?
        // TODO compared [trace_string] with [gasprice]'s trace_string - visually the same (expect some data that must be different) + checked with hex reader - the same
        // TODO tried to clean data from spaces and new lines '\n' - didnt help. when cleaned whitespaces from [gasprice] trace - it started to fatal too
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
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::SELFBALANCE))
            .unwrap();

        let call_id = builder.block.txs()[0].calls()[0].call_id;
        let callee_address = builder.block.txs()[0].to;
        let self_balance = builder.sdb.get_account(&callee_address).1.balance;

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
                    value: callee_address.to_word(),
                }
            )
        );
        assert_eq!(
            {
                let operation =
                    &builder.block.container.account[step.bus_mapping_instance[1].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::READ,
                &AccountOp {
                    address: callee_address,
                    field: AccountField::Balance,
                    value: self_balance,
                    value_prev: self_balance,
                }
            )
        );
        assert_eq!(
            {
                let operation =
                    &builder.block.container.stack[step.bus_mapping_instance[2].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::WRITE,
                &StackOp::new(1, StackAddress::from(1023), self_balance)
            )
        );
    }
}
