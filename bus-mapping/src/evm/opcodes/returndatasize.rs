use eth_types::evm_types::MemoryAddress;
use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    operation::CallContextField,
    Error,
};

use eth_types::{GethExecStep, U256};

use super::Opcode;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Returndatasize;

impl Opcode for Returndatasize {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let geth_second_step = &geth_steps[1];
        let mut exec_step = state.new_step(geth_step)?;
        let value = &geth_second_step.memory.0;
        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::LastCalleeReturnDataLength,
            U256::from_big_endian(value),
        );

        // Read dest offset as the last stack element
        let dest_offset = geth_step.stack.nth_last(0)?;
        state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(0), dest_offset)?;
        let offset_addr = MemoryAddress::try_from(dest_offset)?;

        // Copy result to memory
        for i in 0..20 {
            state.memory_write(&mut exec_step, offset_addr.map(|a| a + i), value[i])?;
        }
        let call_ctx = state.call_ctx_mut()?;
        call_ctx.memory = geth_second_step.memory.clone();

        // state.stack_write(
        //     &mut exec_step,
        //     geth_step.stack.last_filled().map(|a| a - 1),
        //     value,
        // )?;

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod returndatasize_tests {
    use std::fs;
    use crate::circuit_input_builder::CircuitsParams;
    use crate::{
        circuit_input_builder::ExecState,
        mock::BlockData,
        operation::{CallContextField, CallContextOp, StackOp, RW},
    };
    use eth_types::{bytecode, Bytecode, evm_types::{OpcodeId, StackAddress}, geth_types::GethData, Word};
    use mock::test_ctx::{helpers::*, TestContext};
    use pretty_assertions::assert_eq;

    #[test]
    fn test_ok() {
        let res_mem_address = 0x7f;
        let return_data_size = 0x20;

        // // // deployed contract
        // // PUSH1 0x20
        // // PUSH1 0
        // // PUSH1 0
        // // CALLDATACOPY
        // // PUSH1 0x20
        // // PUSH1 0
        // // RETURN
        // //
        // // bytecode: 0x6020600060003760206000F3
        // //
        // // // constructor
        // // PUSH12 0x6020600060003760206000F3
        // // PUSH1 0
        // // MSTORE
        // // PUSH1 0xC
        // // PUSH1 0x14
        // // RETURN
        // //
        // // bytecode: 0x6B6020600060003760206000F3600052600C6014F3
        // let code = bytecode! {
        //     PUSH21(word!("6B6020600060003760206000F3600052600C6014F3"))
        //     PUSH1(0)
        //     MSTORE
        //
        //     PUSH1 (0x15)
        //     PUSH1 (0xB)
        //     PUSH1 (0)
        //     CREATE
        //
        //     PUSH1 (0x20)
        //     PUSH1 (0x20)
        //     PUSH1 (0x20)
        //     PUSH1 (0)
        //     PUSH1 (0)
        //     DUP6
        //     PUSH2 (0xFFFF)
        //     CALL
        //
        //     RETURNDATASIZE
        //
        //     STOP
        // };

        let code = bytecode! {
            I32Const[res_mem_address+20]
            ADDRESS

            I32Const[res_mem_address]
            RETURNDATASIZE
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

        let mut builder = BlockData::new_from_geth_data_with_params(
            block.clone(),
            CircuitsParams {
                max_rws: 512,
                ..Default::default()
            },
        )
        .new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();

        let step = builder.block.txs()[0]
            .steps()
            .iter()
            .find(|step| step.exec_state == ExecState::Op(OpcodeId::RETURNDATASIZE))
            .unwrap();

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
                    field: CallContextField::LastCalleeReturnDataLength,
                    value: Word::from(return_data_size),
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
                &StackOp::new(
                    call_id,
                    StackAddress::from(1021),
                    Word::from(return_data_size)
                )
            )
        );
    }
}
