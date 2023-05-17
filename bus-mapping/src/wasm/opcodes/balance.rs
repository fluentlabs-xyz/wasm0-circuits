use crate::{
    circuit_input_builder::{CircuitInputStateRef, ExecStep},
    evm::Opcode,
    operation::{AccountField, CallContextField, TxAccessListAccountOp},
    Error,
};
use eth_types::{GethExecStep, ToWord, H256, U256, ToBigEndian};
use eth_types::evm_types::{MemoryAddress};

use crate::evm::opcodes::address::ADDRESS_BYTE_LENGTH;

pub const BALANCE_BYTE_LENGTH: usize = 32;

#[derive(Debug, Copy, Clone)]
pub(crate) struct Balance;

impl Opcode for Balance {
    fn gen_associated_ops(
        state: &mut CircuitInputStateRef,
        geth_steps: &[GethExecStep],
    ) -> Result<Vec<ExecStep>, Error> {
        let geth_step = &geth_steps[0];
        let mut exec_step = state.new_step(geth_step)?;

        // Read account address from stack.
        let balance_offset = geth_step.stack.nth_last(0)?;
        state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(0), balance_offset)?;
        let address_offset = geth_step.stack.nth_last(1)?;
        state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(1), address_offset)?;

        // Read account & balance from memory
        let address = geth_steps[0].global_memory.read_address(address_offset)?;
        let balance = geth_steps[1].global_memory.read_u256(balance_offset)?;

        // Read transaction ID, rw_counter_end_of_reversion, and is_persistent
        // from call context.
        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::TxId,
            U256::from(state.tx_ctx.id()),
        );
        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::RwCounterEndOfReversion,
            U256::from(state.call()?.rw_counter_end_of_reversion as u64),
        );
        state.call_context_read(
            &mut exec_step,
            state.call()?.call_id,
            CallContextField::IsPersistent,
            U256::from(state.call()?.is_persistent as u64),
        );

        // Update transaction access list for account address.
        let is_warm = state.sdb.check_account_in_access_list(&address);
        state.push_op_reversible(
            &mut exec_step,
            TxAccessListAccountOp {
                tx_id: state.tx_ctx.id(),
                address,
                is_warm: true,
                is_warm_prev: is_warm,
            },
        )?;

        // Read account balance.
        let account = state.sdb.get_account(&address).1;
        let exists = !account.is_empty();
        let code_hash = if exists {
            account.code_hash
        } else {
            H256::zero()
        };
        state.account_read(
            &mut exec_step,
            address,
            AccountField::CodeHash,
            code_hash.to_word(),
        );
        if exists {
            state.account_read(&mut exec_step, address, AccountField::Balance, balance);
        }

        let address_offset_addr = MemoryAddress::try_from(address_offset)?;
        for i in 0..ADDRESS_BYTE_LENGTH {
            state.memory_read(&mut exec_step, address_offset_addr.map(|a| a + i), address[i])?;
        }
        let balance_offset_addr = MemoryAddress::try_from(balance_offset)?;
        let balance_bytes = balance.to_be_bytes();
        for i in 0..BALANCE_BYTE_LENGTH {
            state.memory_write(&mut exec_step, balance_offset_addr.map(|a| a + i), balance_bytes[i])?;
        }
        let call_ctx = state.call_ctx_mut()?;
        call_ctx.memory = geth_step.global_memory.clone();

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod balance_tests {
    use super::*;
    use crate::{
        circuit_input_builder::ExecState,
        mock::BlockData,
        operation::{AccountOp, CallContextOp, StackOp, RW},
    };
    use eth_types::{address, bytecode, evm_types::{OpcodeId, StackAddress}, geth_types::GethData, Bytecode, ToWord, Word, U256, StackWord};
    use eth_types::bytecode::WasmBinaryBytecode;
    use mock::TestContext;
    use crate::operation::MemoryOp;

    #[test]
    fn test_balance_of_non_existing_address() {
        test_ok(false, true);
    }

    #[test]
    fn test_balance_of_cold_address() {
        test_ok(true, true);
    }

    #[test]
    fn test_balance_of_warm_address() {
        test_ok(true, true);
    }

    fn test_ok(exists: bool, is_warm: bool) {
        let address_offset: u32 = 0x00;
        let balance_offset: u32 = 0x7f;
        let address = address!("0xaabbccddee000000000000000000000000000000");

        // Pop balance first for warm account.
        let mut code = Bytecode::default();
        if is_warm {
            code.append(&bytecode! {
                I32Const[address_offset]
                I32Const[balance_offset]
                BALANCE
            });
        }
        code.append(&bytecode! {
            I32Const[address_offset]
            I32Const[balance_offset]
            BALANCE
        });

        let balance = if exists {
            Word::from(800u64)
        } else {
            Word::zero()
        };

        code.with_global_data(0, address_offset, address.0.to_vec());
        let wasm_binary_vec = code.wasm_binary();
        // Get the execution steps from the external tracer.
        let block: GethData = TestContext::<3, 1>::new(
            None,
            |accs| {
                let balance_to_set = Word::from(1u64 << 20);
                accs[0]
                    .address(address!("0x0000000000000000000000000000000000000010"))
                    .balance(balance_to_set.clone())
                    .code(wasm_binary_vec);
                if exists {
                    accs[1].address(address).balance(balance);
                } else {
                    accs[1]
                        .address(address!("0x0000000000000000000000000000000000000020"))
                        .balance(balance_to_set.clone());
                }
                accs[2]
                    .address(address!("0x0000000000000000000000000000000000cafe01"))
                    .balance(balance_to_set.clone());
            },
            |mut txs, accs| {
                txs[0].to(accs[0].address).from(accs[2].address);
            },
            |block, _tx| {
                block.number(0xcafeu64)
            },
        )
            .unwrap()
            .into();

        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();

        // Check if account address is in access list as a result of bus mapping.
        assert!(builder.sdb.add_account_to_access_list(address));

        let tx_id = 1;
        let transaction = &builder.block.txs()[tx_id - 1];
        let call_id = transaction.calls()[0].call_id;
        let address_balance = builder.sdb.get_account(&address).1.balance;
        let address_balance_bytes = address_balance.to_be_bytes();
        let (account_exists, account) = builder.sdb.get_account(&address);
        assert_eq!(account_exists, true);
        let account_code_hash = if exists { account.code_hash } else { H256::zero() };

        let indices = transaction
            .steps()
            .iter()
            .filter(|step| step.exec_state == ExecState::Op(OpcodeId::BALANCE))
            .last()
            .unwrap()
            .bus_mapping_instance
            .clone();

        let container = &builder.block.container;

        let mut indices_index = 0;

        let operation = &container.stack[indices[indices_index].as_usize()];
        assert_eq!(operation.rw(), RW::READ);
        assert_eq!(
            operation.op(),
            &StackOp {
                call_id,
                address: StackAddress::from(1022u32),
                value: StackWord::from(balance_offset),
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
                value: StackWord::from(address_offset),
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
                value: U256::one(),
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
                value: U256::zero(),
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
                value: U256::one(),
            }
        );

        indices_index += 1;
        let operation = &container.tx_access_list_account[indices[indices_index].as_usize()];
        assert_eq!(operation.rw(), RW::WRITE);
        assert_eq!(
            operation.op(),
            &TxAccessListAccountOp {
                tx_id,
                address,
                is_warm,
                is_warm_prev: is_warm,
            }
        );

        indices_index += 1;
        let operation = &container.account[indices[indices_index].as_usize()];
        assert_eq!(operation.rw(), RW::READ);
        assert_eq!(
            operation.op(),
            &AccountOp {
                address,
                field: AccountField::CodeHash,
                value: account_code_hash.to_word(),
                value_prev: account_code_hash.to_word(),
            }
        );

        if exists {
            indices_index += 1;
            let operation = &container.account[indices[indices_index].as_usize()];
            assert_eq!(operation.rw(), RW::READ);
            assert_eq!(
                operation.op(),
                &AccountOp {
                    address,
                    field: AccountField::Balance,
                    value: balance.to_word(),
                    value_prev: balance.to_word(),
                }
            );
        }

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
                        MemoryAddress::from(address_offset + idx as u32),
                        address[idx],
                    )
                )
            );
        }

        for idx in 0..BALANCE_BYTE_LENGTH {
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
                        MemoryAddress::from(balance_offset + idx as u32),
                        address_balance_bytes[idx],
                    )
                )
            );
        }
    }
}
