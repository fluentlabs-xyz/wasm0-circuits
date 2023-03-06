use crate::evm_circuit::execution::ExecutionGadget;
use crate::evm_circuit::param::N_BYTES_ACCOUNT_ADDRESS;
use crate::evm_circuit::param::N_BYTES_WORD;
use crate::evm_circuit::step::ExecutionState;
use crate::evm_circuit::util::common_gadget::SameContextGadget;
use crate::evm_circuit::util::constraint_builder::Transition::Delta;
use crate::evm_circuit::util::constraint_builder::{
    ConstraintBuilder, ReversionInfo, StepStateTransition,
};
use crate::evm_circuit::util::{from_bytes, math_gadget::IsZeroGadget, not, select, CachedRegion, Cell, Word, RandomLinearCombination};
use crate::evm_circuit::witness::{Block, Call, ExecStep, Transaction};
use crate::table::{AccountFieldTag, CallContextFieldTag};
use crate::util::Expr;
use eth_types::evm_types::GasCost;
use eth_types::{address, Field, ToLittleEndian, ToScalar};
use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::Error;
use halo2_proofs::plonk::Error::Synthesis;
use serde::de::IntoDeserializer;

#[derive(Clone, Debug)]
pub(crate) struct BalanceGadget<F> {
    same_context: SameContextGadget<F>,
    // address: RandomLinearCombination<F, N_BYTES_ACCOUNT_ADDRESS>,
    // reversion_info: ReversionInfo<F>,
    // tx_id: Cell<F>,
    is_warm: Cell<F>,
    code_hash: Cell<F>,
    // not_exists: IsZeroGadget<F>,
    balance: RandomLinearCombination<F, N_BYTES_WORD>,
    address_dest_offset: Cell<F>,
    balance_dest_offset: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for BalanceGadget<F> {
    const NAME: &'static str = "BALANCE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::BALANCE;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        // let address_word = cb.query_word_rlc();
        // let address = cb.query_word_rlc();
        let address_dest_offset = cb.query_cell();
        let balance_dest_offset = cb.query_cell();
        // cb.stack_pop(address_word.expr());

        // let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        // let mut reversion_info = cb.reversion_info_read(None);
        let is_warm = cb.query_bool();
        // TODO temp solution
        // cb.account_access_list_write(
        //     tx_id.expr(),
        //     address.expr(),
        //     1.expr(),
        //     is_warm.expr(),
        //     Some(&mut reversion_info),
        // );
        let code_hash = cb.query_cell();
        // For non-existing accounts the code_hash must be 0 in the rw_table.
        // cb.account_read(address.expr(), AccountFieldTag::CodeHash, code_hash.expr());
        let not_exists = IsZeroGadget::construct(cb, code_hash.expr());
        // let exists = not::expr(not_exists.expr());
        let balance = cb.query_word_rlc();
        // cb.condition(exists.expr(), |cb| {
        //     cb.account_read(address.expr(), AccountFieldTag::Balance, balance.expr());
        // });
        cb.condition(not_exists.expr(), |cb| {
            cb.require_zero("balance is zero when non_exists", balance.expr());
        });

        cb.stack_pop(address_dest_offset.expr());
        cb.stack_pop(balance_dest_offset.expr());
        // cb.memory_rlc_lookup(true.expr(), &address_dest_offset, &address);
        // cb.memory_rlc_lookup(true.expr(), &balance_dest_offset, &balance);

        let gas_cost = select::expr(
            is_warm.expr(),
            GasCost::WARM_ACCESS.expr(),
            GasCost::COLD_ACCOUNT_ACCESS.expr(),
        );
        // let gas_cost = GasCost::COLD_ACCOUNT_ACCESS.expr();

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(39.expr() /*+ exists.expr()*/),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(2.expr()),
            gas_left: Delta(-gas_cost),
            // reversible_write_counter: Delta(1.expr()),
            ..Default::default()
        };

        let opcode = cb.query_cell();
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            // address,
            // reversion_info,
            // tx_id,
            is_warm,
            code_hash,
            // not_exists,
            balance,
            address_dest_offset,
            balance_dest_offset,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        tx: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        // let address = block.rws[step.rw_indices[0]].stack_value();
        // self.address_word
        //     .assign(region, offset, Some(address.to_le_bytes()))?;
        // TODO
        // let address =
        let address_dest_offset = block.rws[step.rw_indices[0]].stack_value();
        let balance_dest_offset = block.rws[step.rw_indices[1]].stack_value();

        // self.tx_id
        //     .assign(region, offset, Value::known(F::from(tx.id as u64)))?;

        // self.reversion_info.assign(
        //     region,
        //     offset,
        //     call.rw_counter_end_of_reversion,
        //     call.is_persistent,
        // )?;

        // let (_, is_warm) = block.rws[step.rw_indices[4]].tx_access_list_value_pair();
        self.is_warm
            .assign(region, offset, Value::known(F::from(false as u64)))?; // TODO temporal hardcoded 'false'
            // .assign(region, offset, Value::known(F::from(is_warm as u64)))?;

        // let code_hash = block.rws[step.rw_indices[3]].account_value_pair().0;
        let code_hash = call.code_hash;
        // self.code_hash
        //     .assign(region, offset, region.word_rlc(code_hash))?;
        // TODO fetch balance from state
        // self.not_exists
        //     .assign_value(region, offset, region.word_rlc(code_hash))?;
        let balance = if code_hash.is_zero() {
            eth_types::Word::zero()
        } else {
            // TODO temp solution
            eth_types::Word::from(0u64 << 20)
            // block.rws[step.rw_indices[2]].account_value_pair().0
        };
        self.balance.assign(
            region,
            offset,
            Some(balance.to_le_bytes()),
        )?;
        self.balance_dest_offset.assign(
            region,
            offset,
            Value::<F>::known(balance_dest_offset.to_scalar().ok_or(Synthesis)?)
        )?;
        self.address_dest_offset.assign(
            region,
            offset,
            Value::<F>::known(address_dest_offset.to_scalar().ok_or(Synthesis)?)
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::evm_circuit::test::rand_bytes;
    use crate::test_util::CircuitTestBuilder;
    use eth_types::geth_types::Account;
    use eth_types::{address, bytecode, Address, Bytecode, ToWord, Word, U256};
    use lazy_static::lazy_static;
    use eth_types::bytecode::WasmDataSectionDescriptor;
    use mock::TestContext;

    lazy_static! {
        static ref TEST_ADDRESS: Address = address!("0xaabbccddee000000000000000000000000000000");
    }

    // #[test]
    // fn balance_gadget_non_existing_account() {
    //     test_root_ok(&None, false);
    //     test_internal_ok(0x20, 0x00, &None, false);
    //     test_internal_ok(0x1010, 0xff, &None, false);
    // }
    //
    // #[test]
    // fn balance_gadget_empty_account() {
    //     let account = Some(Account::default());
    //
    //     test_root_ok(&account, false);
    //     test_internal_ok(0x20, 0x00, &account, false);
    //     test_internal_ok(0x1010, 0xff, &account, false);
    // }

    #[test]
    fn balance_gadget_cold_account() {
        let account = Some(Account {
            address: *TEST_ADDRESS,
            balance: U256::from(900),
            ..Default::default()
        });

        test_root_ok(&account, false);
        // test_internal_ok(0x20, 0x00, &account, false);
        // test_internal_ok(0x1010, 0xff, &account, false);
    }

    // #[test]
    // fn balance_gadget_warm_account() {
    //     let account = Some(Account {
    //         address: *TEST_ADDRESS,
    //         balance: U256::from(900),
    //         ..Default::default()
    //     });
    //
    //     test_root_ok(&account, true);
    //     test_internal_ok(0x20, 0x00, &account, true);
    //     test_internal_ok(0x1010, 0xff, &account, true);
    // }

    fn test_root_ok(account: &Option<Account>, is_warm: bool) {
        let account_mem_address: u32 = 0x0;
        let res_mem_address: u32 = 0x7f;
        let address = account.as_ref().map(|a| a.address).unwrap_or(*TEST_ADDRESS);

        let mut code = Bytecode::default();
        if is_warm {
            code.append(&bytecode! {
                // PUSH20(address.to_word())
                // BALANCE
                // POP

                I32Const[account_mem_address]
                I32Const[res_mem_address]
                BALANCE
            });
        }
        code.append(&bytecode! {
            // PUSH20(address.to_word())
            // BALANCE
            // STOP
            I32Const[account_mem_address]
            I32Const[res_mem_address]
            BALANCE
        });

        let wasm_binary_vec = code.wasm_binary(Some(vec![WasmDataSectionDescriptor {
            memory_index: 0,
            mem_offset: account_mem_address as u32,
            data: address.0.to_vec(),
        }]));
        let ctx = TestContext::<3, 1>::new(
            None,
            |accs| {
                let balance_to_set = Word::from(1u64 << 20);
                accs[0]
                    .address(address!("0x000000000000000000000000000000000000cafe"))
                    .balance(Word::from(balance_to_set))
                    .code(wasm_binary_vec);
                // Set balance if account exists.
                if let Some(account) = account {
                    accs[1].address(address).balance(account.balance);
                } else {
                    accs[1]
                        .address(address!("0x0000000000000000000000000000000000000010"))
                        .balance(Word::from(balance_to_set));
                }
                accs[2]
                    .address(address!("0x0000000000000000000000000000000000000020"))
                    .balance(Word::from(balance_to_set));
            },
            |mut txs, accs| {
                txs[0].to(accs[0].address).from(accs[2].address);
            },
            |block, _tx| block,
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    fn test_internal_ok(
        call_data_offset: usize,
        call_data_length: usize,
        account: &Option<Account>,
        is_warm: bool,
    ) {
        let address = account.as_ref().map(|a| a.address).unwrap_or(*TEST_ADDRESS);
        let (addr_a, addr_b) = (mock::MOCK_ACCOUNTS[0], mock::MOCK_ACCOUNTS[1]);

        // code B gets called by code A, so the call is an internal call.
        let mut code_b = Bytecode::default();
        if is_warm {
            code_b.append(&bytecode! {
                PUSH20(address.to_word())
                BALANCE
                POP
            });
        }
        code_b.append(&bytecode! {
            PUSH20(address.to_word())
            BALANCE
            STOP
        });

        // code A calls code B.
        let pushdata = rand_bytes(8);
        let code_a = bytecode! {
            // populate memory in A's context.
            PUSH8(Word::from_big_endian(&pushdata))
            PUSH1(0x00) // offset
            MSTORE
            // call ADDR_B.
            PUSH1(0x00) // retLength
            PUSH1(0x00) // retOffset
            PUSH32(call_data_length) // argsLength
            PUSH32(call_data_offset) // argsOffset
            PUSH1(0x00) // value
            PUSH32(addr_b.to_word()) // addr
            PUSH32(0x1_0000) // gas
            CALL
            STOP
        };

        let ctx = TestContext::<4, 1>::new(
            None,
            |accs| {
                accs[0].address(addr_b).code(code_b);
                accs[1].address(addr_a).code(code_a);
                // Set balance if account exists.
                if let Some(account) = account {
                    accs[2].address(address).balance(account.balance);
                } else {
                    accs[2]
                        .address(mock::MOCK_ACCOUNTS[2])
                        .balance(Word::from(1_u64 << 20));
                }
                accs[3]
                    .address(mock::MOCK_ACCOUNTS[3])
                    .balance(Word::from(1_u64 << 20));
            },
            |mut txs, accs| {
                txs[0].to(accs[1].address).from(accs[3].address);
            },
            |block, _tx| block,
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }
}
