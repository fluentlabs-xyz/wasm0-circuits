use std::io::Read;
use ethers_core::abi::{AbiEncode, Address};
use crate::circuit_input_builder::{CircuitInputStateRef, ExecStep};
use crate::evm::Opcode;
use crate::operation::{AccountField, CallContextField, TxAccessListAccountOp, RW};
use crate::Error;
use eth_types::{GethExecStep, ToAddress, ToWord, H256, U256, ToWordBytes, ToU256, ToLittleEndian, Word};
use eth_types::evm_types::MemoryAddress;
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
        let geth_second_step = &geth_steps[1];
        let mut exec_step = state.new_step(geth_step)?;

        // Read account address from stack.
        let account_mem_address = geth_step.stack.nth_last(1)?;
        state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(1), account_mem_address)?;
        let balance_mem_address = geth_step.stack.last()?;
        state.stack_read(&mut exec_step, geth_step.stack.last_filled(), balance_mem_address)?;

        // TODO zkwasm-geth reads

        // Get balance result from next step.
        let balance_vec = &geth_second_step.memory.0;
        if balance_vec.len() != BALANCE_BYTE_LENGTH {
            return Err(Error::InvalidGethExecTrace("there is no balance bytes in memory for balance opcode"));
        }
        // Read account address offset as the last stack element
        let account_address_offset = geth_step.stack.nth_last(0)?;
        state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(0), account_address_offset)?;

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

        // TODO do we need to integrate with all commented stuff below

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

        // Read account balance.
        // let account = state.sdb.get_account(&address).1;
        // let exists = !account.is_empty();
        // let balance = account.balance;
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
        // )?;
        // let mut exists = false;
        // for i in balance_vec {
        //     if *i != 0 {
        //         exists = true;
        //         break;
        //     }
        // }
        // if exists {
        //     state.account_read(
        //         &mut exec_step,
        //         address,
        //         AccountField::Balance,
        //         Word::from(balance_vec.as_slice()),
        //         Word::from(balance_vec.as_slice()),
        //     )?;
        // }

        // Write the BALANCE result to stack.
        state.stack_write(
            &mut exec_step,
            geth_steps[1].stack.nth_last_filled(0),
            geth_steps[1].stack.nth_last(0)?,
        )?;

        // Read dest offset as the (last-1) stack element
        let dest_offset = geth_step.stack.nth_last(0)?;
        state.stack_read(&mut exec_step, geth_step.stack.nth_last_filled(0), dest_offset)?;
        let offset_addr = MemoryAddress::try_from(dest_offset)?;

        // Copy result to memory
        let balance_bytes = balance_vec.as_slice();
        for i in 0..BALANCE_BYTE_LENGTH {
            state.memory_write(&mut exec_step, offset_addr.map(|a| a + i), balance_bytes[i])?;
        }
        let call_ctx = state.call_ctx_mut()?;
        call_ctx.memory = geth_second_step.memory.clone();

        Ok(vec![exec_step])
    }
}

#[cfg(test)]
mod balance_tests {
    use std::{fs, process};
    use std::io::Read;
    use ethers_providers::call_raw::state;
    use super::*;
    use crate::circuit_input_builder::ExecState;
    use crate::mock::BlockData;
    use crate::operation::{AccountOp, CallContextOp, MemoryOp, StackOp};
    use eth_types::evm_types::{OpcodeId, StackAddress};
    use eth_types::geth_types::GethData;
    use eth_types::{address, bytecode, Bytecode, ToWord, Word, U256, ToBigEndian};
    use keccak256::EMPTY_HASH_LE;
    use mock::TestContext;
    use pretty_assertions::assert_eq;
    use serde::de::Unexpected::Option;

    #[test]
    fn test_balance_of_non_existing_address() {
        test_ok(false, false);
    }

    #[test]
    fn test_balance_of_cold_address() {
        test_ok(true, false);
    }

    #[test]
    fn test_balance_of_warm_address() {
        test_ok(true, true);
    }

    fn test_ok(exists: bool, is_warm: bool) {
        let account_mem_address: i32 = 0x0;
        let res_mem_address: i32 = 0x7f;
        let address = address!("0xaabbccddee000000000000000000000000000000");

        // Pop balance first for warm account.
        let mut code = Bytecode::default();
        if is_warm {
            code.append(&bytecode! {
                I32Const[account_mem_address]
                I32Const[res_mem_address]
                BALANCE
            });
        }
        code.append(&bytecode! {
            I32Const[account_mem_address]
            I32Const[res_mem_address]
            BALANCE
        });

        let balance = if exists {
            Word::from(800u64)
        } else {
            Word::zero()
        };

        let wasm_binary_vec = code.wasm_binary_with_data_section(Some(address.0.to_vec()), account_mem_address);
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
                value: Word::from(account_mem_address)
            }
        );

        indices_index += 1;
        let operation = &container.stack[indices[indices_index].as_usize()];
        assert_eq!(operation.rw(), RW::READ);
        assert_eq!(
            operation.op(),
            &StackOp {
                call_id,
                address: StackAddress::from(1021u32),
                value: Word::from(res_mem_address)
            }
        );

        indices_index += 1;
        let operation = &container.stack[indices[indices_index].as_usize()];
        assert_eq!(operation.rw(), RW::READ);
        assert_eq!(
            operation.op(),
            &StackOp {
                call_id,
                address: StackAddress::from(1021u32),
                value: Word::from(res_mem_address)
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
                value: U256::one()
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
        let operation = &container.stack[indices[indices_index].as_usize()];
        assert_eq!(operation.rw(), RW::WRITE);
        assert_eq!(
            operation.op(),
            &StackOp {
                call_id,
                address: StackAddress::from(1023u32),
                value: Word::from(account_mem_address)
            }
        );

        indices_index += 1;
        let operation = &container.stack[indices[indices_index].as_usize()];
        assert_eq!(operation.rw(), RW::READ);
        assert_eq!(
            operation.op(),
            &StackOp {
                call_id,
                address: StackAddress::from(1021u32),
                value: Word::from(res_mem_address)
            }
        );

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
                        MemoryAddress::from(res_mem_address + idx as i32),
                        address_balance_bytes[idx]
                    )
                )
            );
        }
    }
}
