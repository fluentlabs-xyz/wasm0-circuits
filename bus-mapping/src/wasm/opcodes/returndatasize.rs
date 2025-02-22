use eth_types::evm_types::MemoryAddress;
use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    operation::CallContextField,
    Error,
};

const RETURN_DATA_SIZE_BYTE_LENGTH: usize = 4;

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
        let value = &geth_second_step.memory[0].0;
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
        for i in 0..RETURN_DATA_SIZE_BYTE_LENGTH {
            state.memory_write(&mut exec_step, offset_addr.map(|a| a + i), value[i])?;
        }
        let call_ctx = state.call_ctx_mut()?;
        call_ctx.memory = geth_second_step.global_memory.clone();

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
    use crate::{
        circuit_input_builder::{CircuitsParams, ExecState},
        mock::BlockData,
        operation::{CallContextField, CallContextOp, StackOp, RW},
    };
    use eth_types::{bytecode, evm_types::{OpcodeId, StackAddress}, geth_types::GethData, StackWord, Word};
    use mock::test_ctx::{helpers::*, TestContext};
    use pretty_assertions::assert_eq;
    use eth_types::evm_types::MemoryAddress;
    use crate::operation::MemoryOp;

    #[test]
    fn test_ok() {
        let address_mem_offset = 0x00;
        let res_mem_offset = 0x7f;
        let return_data_size = [0u8; 4];

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
            // I32Const[10]
            // I32Const[20]
            // ADDRESS
            I32Const[res_mem_offset]
            BALANCE

            I32Const[res_mem_offset]
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

        let container = &builder.block.container;
        let bm = &step.bus_mapping_instance;

        let call_id = builder.block.txs()[0].calls()[0].call_id;
        assert_eq!(
            {
                let operation =
                    &container.call_context[bm[0].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::READ,
                &CallContextOp {
                    call_id,
                    field: CallContextField::LastCalleeReturnDataLength,
                    value: Word::from(0),
                }
            )
        );
        assert_eq!(
            {
                let operation =
                    &container.stack[bm[1].as_usize()];
                (operation.rw(), operation.op())
            },
            (
                RW::READ,
                &StackOp::new(
                    call_id,
                    StackAddress::from(1023),
                    StackWord::from(res_mem_offset)
                )
            )
        );
        for idx in 0..4 {
            assert_eq!(
                {
                    let operation = &container.memory[bm[2 + idx].as_usize()];
                    (operation.rw(), operation.op())
                },
                (
                    RW::WRITE,
                    &MemoryOp::new(
                        call_id,
                        MemoryAddress(res_mem_offset + idx),
                        return_data_size[idx]
                    )
                )
            );
        }
    }
}
