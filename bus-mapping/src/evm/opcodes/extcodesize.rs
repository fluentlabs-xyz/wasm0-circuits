use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::evm::Opcode;
use crate::operation::CallContextField;
use crate::Error;
use eth_types::{GethExecStep, ToBigEndian, ToLittleEndian};
use eth_types::ToWord;
use eth_types::evm_types::MemoryAddress;
use crate::evm::opcodes::address::ADDRESS_BYTE_LENGTH;
use crate::evm::opcodes::balance::BALANCE_BYTE_LENGTH;

const CODESIZE_BYTE_LENGTH: usize = 4;

#[derive(Debug, Copy, Clone)]
pub(crate) struct Extcodesize;

impl Opcode for Extcodesize {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let geth_second_step = &geth_steps[1];
        let mut exec_step = state.new_step(geth_step)?;

        // Read account address from stack.
        let codesize_mem_address = geth_step.stack.last()?;
        state.stack_read(&mut exec_step, geth_step.stack.last_filled(), codesize_mem_address)?;
        let account_mem_address = geth_step.stack.nth_last(1)?;
        state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(1), account_mem_address)?;

        let account = &geth_step.global_memory.read_address(account_mem_address)?;
        let codesize = &geth_second_step.global_memory.read_u32(codesize_mem_address)?;

        // Read transaction ID, rw_counter_end_of_reversion, and is_persistent from call
        // context.
        for (field, value) in [
            (CallContextField::TxId, state.tx_ctx.id().to_word()),
            (
                CallContextField::RwCounterEndOfReversion,
                state.call()?.rw_counter_end_of_reversion.to_word(),
            ),
            (
                CallContextField::IsPersistent,
                state.call()?.is_persistent.to_word(),
            ),
        ] {
            state.call_context_read(&mut exec_step, state.call()?.call_id, field, value);
        }

        // TODO recover code below

        // Update transaction access list for account address.
        // let is_warm = state.sdb.check_account_in_access_list(&address);
        // state.push_op_reversible(
        //     &mut exec_step,
        //     RW::WRITE,
        //     TxAccessListAccountOp {
        //         tx_id: state.tx_ctx.id(),
        //         address,
        //         is_warm: true,
        //         is_warm_prev: is_warm,
        //     },
        // )?;

        // Read account code hash and get code length.
        // let account = state.sdb.get_account(&address).1;
        // let exists = !account.is_empty();
        // let code_hash = if exists {
        //     account.code_hash
        // } else {
        //     H256::zero()
        // };
        // state.account_read(
        //     &mut exec_step,
        //     address,
        //     AccountField::CodeHash,
        //     code_hash.to_word(),
        //     code_hash.to_word(),
        // );
        // let code_size = if exists {
        //     state.code(code_hash)?.len()
        // } else {
        //     0
        // };

        // Write the EXTCODESIZE result to stack.
        // debug_assert_eq!(code_size, geth_steps[1].stack.last()?.as_usize());
        // state.stack_write(
        //     &mut exec_step,
        //     geth_steps[1].stack.nth_last_filled(0),
        //     code_size.into(),
        // )?;
        //
        // Ok(vec![exec_step])

        let account_bytes = account.as_bytes();
        let account_offset_addr = MemoryAddress::try_from(account_mem_address)?;
        for i in 0..ADDRESS_BYTE_LENGTH {
            state.memory_read(&mut exec_step, account_offset_addr.map(|a| a + i), account_bytes[i])?;
        }
        let codesize_offset_addr = MemoryAddress::try_from(codesize_mem_address)?;
        let codesize_bytes = codesize.to_be_bytes();
        for i in 0..CODESIZE_BYTE_LENGTH {
            state.memory_write(&mut exec_step, codesize_offset_addr.map(|a| a + i), codesize_bytes[i])?;
        }
        let call_ctx = state.call_ctx_mut()?;
        call_ctx.memory = geth_step.global_memory.clone();

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod extcodesize_tests {
    use ethers_providers::call_raw::code;
    use super::*;
    use crate::circuit_input_builder::ExecState;
    use crate::mocks::BlockData;
    use crate::operation::CallContextOp;
    use crate::operation::MemoryOp;
    use crate::operation::RW;
    use crate::operation::StackOp;
    use eth_types::evm_types::{MemoryAddress, OpcodeId, StackAddress};
    use eth_types::geth_types::{Account, GethData};
    use eth_types::{bytecode, Bytecode, Word, U256, StackWord};
    use mock::{TestContext, MOCK_1_ETH, MOCK_ACCOUNTS, MOCK_CODES};
    use pretty_assertions::assert_eq;
    use eth_types::bytecode::WasmBinaryBytecode;

    #[test]
    fn test_extcodesize_opcode_empty_acc() {
        // let account = Account {
        //     address: MOCK_ACCOUNTS[4],
        //     code: MOCK_CODES[4].clone(),
        //     ..Default::default()
        // };

        // Test for empty account.
        test_ok(&Account::default(), false);
    }

    #[test]
    fn test_extcodesize_opcode_cold_acc() {
        let account = Account {
            address: MOCK_ACCOUNTS[4],
            code: MOCK_CODES[4].clone(),
            ..Default::default()
        };

        // Test for cold account.
        test_ok(&account, false);
    }

    // #[test]
    // fn test_extcodesize_opcode_warm_acc() {
    //     let account = Account {
    //         address: MOCK_ACCOUNTS[4],
    //         code: MOCK_CODES[4].clone(),
    //         ..Default::default()
    //     };
    //
    //     // Test for warm account.
    //     test_ok(&account, true);
    // }

    fn test_ok(account: &Account, is_warm: bool) {
        let exists = !account.is_empty();
        let account_mem_address = 0x0;
        let res_mem_address = 0x7f;

        let mut code = Bytecode::default();
        if is_warm {
            code.append(&bytecode! {
                // PUSH20(account.address.to_word())
                // EXTCODESIZE
                // POP
                I32Const[account_mem_address]
                I32Const[res_mem_address]
                EXTCODESIZE
            });
        }
        code.append(&bytecode! {
            // PUSH20(account.address.to_word())
            // EXTCODESIZE
            // STOP
            I32Const[account_mem_address]
            I32Const[res_mem_address]
            EXTCODESIZE
        });

        // Get the execution steps from the external tracer.
        code.with_global_data(0, account_mem_address, account.address.0.to_vec());
        let block: GethData = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(MOCK_ACCOUNTS[0])
                    .balance(*MOCK_1_ETH)
                    .code(code.wasm_binary());
                if exists {
                    accs[1].address(account.address).code(account.code.clone());
                } else {
                    accs[1].address(MOCK_ACCOUNTS[1]).balance(*MOCK_1_ETH);
                }
                accs[2].address(MOCK_ACCOUNTS[2]).balance(*MOCK_1_ETH);
            },
            |mut txs, accs| {
                txs[0].to(accs[0].address).from(accs[2].address);
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap()
        .into();

        let codesize = &account.code.len();
        let codesize_bytes = codesize.to_le_bytes();
        let codesize_vec = codesize_bytes[codesize_bytes.len()-CODESIZE_BYTE_LENGTH..codesize_bytes.len()].to_vec();
        assert_eq!(codesize_vec.len(), CODESIZE_BYTE_LENGTH);

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();

        // Check if account address is in access list as a result of bus mapping.
        assert!(builder.sdb.add_account_to_access_list(account.address));

        let tx_id = 1;
        let transaction = &builder.block.txs()[tx_id - 1];
        let call_id = transaction.calls()[0].call_id;

        let indices = transaction
            .steps()
            .iter()
            .filter(|step| step.exec_state == ExecState::Op(OpcodeId::EXTCODESIZE))
            .last()
            .unwrap()
            .bus_mapping_instance
            .clone();
        let container = builder.block.container;

        let mut indices_index = 0;
        let operation = &container.stack[indices[indices_index].as_usize()];
        assert_eq!(operation.rw(), RW::READ);
        assert_eq!(
            operation.op(),
            &StackOp {
                call_id,
                address: StackAddress::from(1022u32),
                value: StackWord::from(res_mem_address)
            }
        );

        indices_index += 1;
        let operation = &container.stack[indices[indices_index].as_usize()];
        assert_eq!(operation.rw(), RW::READ);
        assert_eq!(
            operation.op(),
            &StackOp {
                call_id,
                address: StackAddress::from(1023u32),
                value: StackWord::from(account_mem_address)
            }
        );

        indices_index += 1;
        let operation = &container.call_context[indices[indices_index].as_usize()];
        assert_eq!(operation.rw(), RW::READ);
        assert_eq!(
            operation.op(),
            &CallContextOp {
                call_id,
                field: CallContextField::TxId,
                value: tx_id.into()
            }
        );

        indices_index += 1;
        let operation = &container.call_context[indices[indices_index].as_usize()];
        assert_eq!(operation.rw(), RW::READ);
        assert_eq!(
            operation.op(),
            &CallContextOp {
                call_id,
                field: CallContextField::RwCounterEndOfReversion,
                value: U256::zero()
            }
        );

        indices_index += 1;
        let operation = &container.call_context[indices[indices_index].as_usize()];
        assert_eq!(operation.rw(), RW::READ);
        assert_eq!(
            operation.op(),
            &CallContextOp {
                call_id,
                field: CallContextField::IsPersistent,
                value: U256::one()
            }
        );

        // let operation = &container.tx_access_list_account[indices[4].as_usize()];
        // assert_eq!(operation.rw(), RW::WRITE);
        // assert_eq!(
        //     operation.op(),
        //     &TxAccessListAccountOp {
        //         tx_id,
        //         address: account.address,
        //         is_warm: true,
        //         is_warm_prev: is_warm
        //     }
        // );

        // let code_hash = Word::from(keccak256(account.code.clone()));
        // let operation = &container.account[indices[5].as_usize()];
        // assert_eq!(operation.rw(), RW::READ);
        // assert_eq!(
        //     operation.op(),
        //     &AccountOp {
        //         address: account.address,
        //         field: AccountField::CodeHash,
        //         value: if exists { code_hash } else { U256::zero() },
        //         value_prev: if exists { code_hash } else { U256::zero() },
        //     }
        // );
        //
        // let operation = &container.stack[indices[6].as_usize()];
        // assert_eq!(operation.rw(), RW::WRITE);
        // assert_eq!(
        //     operation.op(),
        //     &StackOp {
        //         call_id,
        //         address: 1023u32.into(),
        //         value: (if exists { account.code.len() } else { 0 }).into(),
        //     }
        // );

        for idx in 0..ADDRESS_BYTE_LENGTH {
            indices_index += 1;
            assert_eq!(
                {
                    let operation =
                        &container.memory[indices[indices_index].as_usize()];
                    (operation.rw(), operation.op())
                },
                (
                    RW::READ,
                    &MemoryOp::new(
                        1,
                        MemoryAddress::from(account_mem_address + idx as u32),
                        account.address[idx]
                    )
                )
            );
        }

        for idx in 0..CODESIZE_BYTE_LENGTH {
            indices_index += 1;
            assert_eq!(
                {
                    let operation =
                        &container.memory[indices[indices_index].as_usize()];
                    (operation.rw(), operation.op())
                },
                (
                    RW::WRITE,
                    &MemoryOp::new(
                        1,
                        MemoryAddress::from(res_mem_address + idx as u32),
                        codesize_vec[idx]
                    )
                )
            );
        }
    }
}
