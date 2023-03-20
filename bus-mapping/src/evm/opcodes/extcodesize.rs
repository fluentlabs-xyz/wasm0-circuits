use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    evm::Opcode,
    operation::{AccountField, CallContextField, TxAccessListAccountOp},
    Error,
};
use eth_types::{GethExecStep, ToWord, H256};
use eth_types::evm_types::MemoryAddress;
use crate::evm::opcodes::address::ADDRESS_BYTE_LENGTH;

const CODESIZE_BYTE_LENGTH: usize = 4;

#[derive(Debug, Copy, Clone)]
pub(crate) struct Extcodesize;

impl Opcode for Extcodesize {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;

        // Read account address from stack.
        let codesize_offset = geth_step.stack.nth_last(0)?;
        state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(0), codesize_offset)?;
        let address_offset = geth_step.stack.nth_last(1)?;
        state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(1), address_offset)?;

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

        // Update transaction access list for account address.
        let address = &geth_step.global_memory.read_address(address_offset)?;
        let is_warm = state.sdb.check_account_in_access_list(&address);
        state.push_op_reversible(
            &mut exec_step,
            TxAccessListAccountOp {
                tx_id: state.tx_ctx.id(),
                address: address.clone(),
                is_warm: true,
                is_warm_prev: is_warm,
            },
        )?;

        // Read account code hash and get code length.
        let account = state.sdb.get_account(&address).1;
        let exists = !account.is_empty();
        let code_hash = if exists {
            account.code_hash
        } else {
            H256::zero()
        };
        state.account_read(
            &mut exec_step,
            address.clone(),
            AccountField::CodeHash,
            code_hash.to_word(),
        );
        let codesize = if exists {
            state.code(code_hash)?.len()
        } else {
            0
        };

        let address_bytes = address.as_bytes();
        let address_offset_addr = MemoryAddress::try_from(address_offset)?;
        for i in 0..ADDRESS_BYTE_LENGTH {
            state.memory_read(&mut exec_step, address_offset_addr.map(|a| a + i), address_bytes[i])?;
        }
        let codesize_offset_addr = MemoryAddress::try_from(codesize_offset)?;
        let codesize_bytes = codesize.to_be_bytes();
        let codesize_bytes_base_idx = codesize_bytes.len() - CODESIZE_BYTE_LENGTH;
        for i in 0..CODESIZE_BYTE_LENGTH {
            state.memory_write(&mut exec_step, codesize_offset_addr.map(|a| a + i), codesize_bytes[codesize_bytes_base_idx + i])?;
        }
        let call_ctx = state.call_ctx_mut()?;
        call_ctx.memory = geth_step.global_memory.clone();

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod extcodesize_tests {
    use ethers_core::utils::keccak256;
    use super::*;
    use crate::{
        circuit_input_builder::ExecState,
        mock::BlockData,
        operation::{AccountOp, CallContextOp, StackOp, RW},
    };
    use eth_types::{bytecode, evm_types::{OpcodeId, StackAddress}, geth_types::{Account, GethData}, Bytecode, Word, U256, StackWord};
    use ethers_core::utils::keccak256;
    use mock::{TestContext, MOCK_1_ETH, MOCK_ACCOUNTS, MOCK_CODES};
    use pretty_assertions::assert_eq;
    use eth_types::bytecode::WasmBinaryBytecode;
    use crate::mocks::BlockData;
    use crate::operation::MemoryOp;

    #[test]
    fn test_extcodesize_opcode_empty_acc() {
        // Test for empty account.
        test_ok(&Account::default(), true);
    }

    #[test]
    fn test_extcodesize_opcode_cold_acc() {
        let account = Account {
            address: MOCK_ACCOUNTS[4],
            code: MOCK_CODES[4].clone(),
            ..Default::default()
        };

        // Test for cold account.
        test_ok(&account, true);
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
        // if is_warm {
        //     code.append(&bytecode! {
        //         // PUSH20(account.address.to_word())
        //         // EXTCODESIZE
        //         // POP
        //         I32Const[account_mem_address]
        //         I32Const[res_mem_address]
        //         EXTCODESIZE
        //     });
        // }
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
        let codesize_bytes = codesize.to_be_bytes();
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
                local_index: 0,
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
                local_index: 0,
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

        indices_index += 1;
        let operation = &container.tx_access_list_account[indices[indices_index].as_usize()];
        assert_eq!(operation.rw(), RW::WRITE);
        assert_eq!(
            operation.op(),
            &TxAccessListAccountOp {
                tx_id,
                address: account.address.clone(),
                is_warm,
                is_warm_prev: false,
            }
        );

        indices_index += 1;
        let code_hash = Word::from(keccak256(account.code.clone()));
        let operation = &container.account[indices[indices_index].as_usize()];
        assert_eq!(operation.rw(), RW::READ);
        assert_eq!(
            operation.op(),
            &AccountOp {
                address: account.address,
                field: AccountField::CodeHash,
                value: if exists { code_hash } else { U256::zero() },
                value_prev: if exists { code_hash } else { U256::zero() },
            }
        );

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
