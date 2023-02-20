#[cfg(test)]
mod selfbalance_tests {
    use super::*;
    use crate::{
        circuit_input_builder::ExecState,
        mock::BlockData,
        operation::{AccountOp, CallContextField, CallContextOp, StackOp, RW},
    };
    use eth_types::{bytecode, Bytecode, evm_types::{OpcodeId, StackAddress}, geth_types::GethData, ToBigEndian, Word};
    use mock::test_ctx::{helpers::*, TestContext};
    use pretty_assertions::assert_eq;
    use crate::operation::MemoryOp;

    #[test]
    fn selfbalance_opcode_impl() {
        let res_mem_address = 0x7f;
        let code = bytecode! {
            I32Const[res_mem_address]
            SELFBALANCE
        };

        // Get the execution steps from the external tracer
        let wasm_bytecode = Bytecode::from_raw_unchecked(code.wasm_binary());
        let block: GethData = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(wasm_bytecode),
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
        let self_balance_bytes = self_balance.to_be_bytes();

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
                RW::READ,
                &StackOp::new(1, StackAddress::from(1022), Word::from(res_mem_address))
            )
        );
        for idx in 0..SELF_BALANCE_BYTE_LENGTH {
            let mem_address = MemoryAddress::from(res_mem_address + idx as i32);
            assert_eq!(
                {
                    let operation =
                        &builder.block.container.memory[step.bus_mapping_instance[3 + idx].as_usize()];
                    (operation.rw(), operation.op())
                },
                (
                    RW::WRITE,
                    &MemoryOp::new(
                        1,
                        mem_address,
                        self_balance_bytes[idx]
                    )
                )
            );
        }
    }
}