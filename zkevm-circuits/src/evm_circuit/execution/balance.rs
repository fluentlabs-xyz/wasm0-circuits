use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::Error;

use eth_types::{Field, N_BYTES_WORD, ToLittleEndian, ToScalar};
use eth_types::evm_types::GasCost;

use crate::evm_circuit::execution::ExecutionGadget;
use crate::evm_circuit::param::N_BYTES_ACCOUNT_ADDRESS;
use crate::evm_circuit::step::ExecutionState;
use crate::evm_circuit::util::{CachedRegion, Cell, from_bytes, math_gadget::IsZeroGadget, not, RandomLinearCombination, select, Word};
use crate::evm_circuit::util::common_gadget::SameContextGadget;
use crate::evm_circuit::util::constraint_builder::{
    ConstraintBuilder, ReversionInfo, StepStateTransition,
};
use crate::evm_circuit::util::constraint_builder::Transition::Delta;
use crate::evm_circuit::witness::{Block, Call, ExecStep, Transaction};
use crate::table::{AccountFieldTag, CallContextFieldTag, RwTableTag};
use crate::util::Expr;

#[derive(Clone, Debug)]
pub(crate) struct BalanceGadget<F> {
    same_context: SameContextGadget<F>,
    address_offset: Cell<F>,
    address_word: RandomLinearCombination<F, N_BYTES_ACCOUNT_ADDRESS>,
    reversion_info: ReversionInfo<F>,
    tx_id: Cell<F>,
    is_warm: Cell<F>,
    code_hash: Cell<F>,
    not_exists: IsZeroGadget<F>,
    balance_offset: Cell<F>,
    balance: Word<F>,
}

impl<F: Field> ExecutionGadget<F> for BalanceGadget<F> {
    const NAME: &'static str = "BALANCE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::BALANCE;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let address_word = cb.query_word_rlc();
        let address = from_bytes::expr(&address_word.cells[..N_BYTES_ACCOUNT_ADDRESS]);

        let balance_offset = cb.query_cell();
        let address_offset = cb.query_cell();

        cb.stack_pop(balance_offset.expr());
        cb.stack_pop(address_offset.expr());

        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let mut reversion_info = cb.reversion_info_read(None);
        let is_warm = cb.query_bool();
        cb.account_access_list_write(
            tx_id.expr(),
            address.expr(),
            1.expr(),
            is_warm.expr(),
            Some(&mut reversion_info),
        );
        let code_hash = cb.query_cell_phase2();
        // For non-existing accounts the code_hash must be 0 in the rw_table.
        cb.account_read(address.expr(), AccountFieldTag::CodeHash, code_hash.expr());
        let not_exists = IsZeroGadget::construct(cb, code_hash.expr());
        let exists = not::expr(not_exists.expr());
        let balance_word = cb.query_word_rlc();
        cb.condition(exists.expr(), |cb| {
            cb.account_read(address.expr(), AccountFieldTag::Balance, balance_word.expr());
        });
        cb.condition(not_exists.expr(), |cb| {
            cb.require_zero("balance is zero when non_exists", balance_word.expr());
        });

        cb.memory_rlc_lookup(0.expr(), &address_offset, &address_word);
        cb.memory_rlc_lookup(1.expr(), &balance_offset, &balance_word);

        let gas_cost = select::expr(
            is_warm.expr(),
            GasCost::WARM_ACCESS.expr(),
            GasCost::COLD_ACCOUNT_ACCESS.expr(),
        );

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(7.expr() + exists.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(2.expr()),
            gas_left: Delta(-gas_cost),
            reversible_write_counter: Delta(1.expr()),
            ..Default::default()
        };

        let opcode = cb.query_cell();
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            address_offset,
            address_word,
            reversion_info,
            tx_id,
            is_warm,
            code_hash,
            not_exists,
            balance_offset,
            balance: balance_word,
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

        let balance_offset = block.rws[step.rw_indices[0]].stack_value();
        let address_offset = block.rws[step.rw_indices[1]].stack_value();

        self.address_offset.assign(region, offset, Value::<F>::known(address_offset.to_scalar().unwrap()))?;
        self.balance_offset.assign(region, offset, Value::<F>::known(balance_offset.to_scalar().unwrap()))?;

        self.tx_id
            .assign(region, offset, Value::known(F::from(tx.id as u64)))?;

        self.reversion_info.assign(
            region,
            offset,
            call.rw_counter_end_of_reversion,
            call.is_persistent,
        )?;

        let (_, is_warm) = block.rws[step.rw_indices[5]].tx_access_list_value_pair();
        self.is_warm
            .assign(region, offset, Value::known(F::from(is_warm as u64)))?;

        let code_hash = block.rws[step.rw_indices[6]].account_value_pair().0;
        self.code_hash
            .assign(region, offset, region.word_rlc(code_hash))?;
        self.not_exists
            .assign_value(region, offset, region.word_rlc(code_hash))?;

        let address_rw_index = if code_hash.is_zero() { 7 } else { 8 };
        let balance_rw_index: usize = address_rw_index + N_BYTES_ACCOUNT_ADDRESS;

        let address = {
            let address_rw_tup_vec: Vec<(RwTableTag, usize)> = step.rw_indices[address_rw_index..(address_rw_index + N_BYTES_ACCOUNT_ADDRESS)].to_vec();
            let address_bytes_vec: Vec<u8> = address_rw_tup_vec
                .iter()
                .map(|&b| block.rws[b].memory_value())
                .collect();
            eth_types::Word::from_big_endian(address_bytes_vec.as_slice())
        };

        self.address_word
            .assign(region, offset, Some(address.to_le_bytes()[0..N_BYTES_ACCOUNT_ADDRESS].try_into().unwrap()))?;

        let balance = if code_hash.is_zero() {
            eth_types::Word::zero()
        } else {
            let balance_vec = step.rw_indices[balance_rw_index..(balance_rw_index + N_BYTES_WORD)]
                .iter()
                .map(|&b| block.rws[b].memory_value())
                .collect::<Vec<u8>>();
            eth_types::Word::from_big_endian(balance_vec.as_slice())
        };
        self.balance
            .assign(region, offset, Some(balance.to_le_bytes()))?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use lazy_static::lazy_static;

    use eth_types::{address, Address, bytecode, Bytecode, ToWord, U256, Word};
    use eth_types::bytecode::WasmBinaryBytecode;
    use eth_types::geth_types::Account;
    use mock::TestContext;

    use crate::evm_circuit::test::rand_bytes;
    use crate::test_util::CircuitTestBuilder;

    lazy_static! {
        static ref TEST_ADDRESS: Address = address!("0xaabbccddee000000000000000000000000000000");
    }

    #[test]
    fn balance_gadget_non_existing_account() {
        test_root_ok(&None, false);
        // test_internal_ok(0x20, 0x00, &None, false);
        // test_internal_ok(0x1010, 0xff, &None, false);
    }

    #[test]
    fn balance_gadget_empty_account() {
        let account = Some(Account::default());
        test_root_ok(&account, false);
        // test_internal_ok(0x20, 0x00, &account, false);
        // test_internal_ok(0x1010, 0xff, &account, false);
    }

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

    #[test]
    fn balance_gadget_warm_account() {
        let account = Some(Account {
            address: *TEST_ADDRESS,
            balance: U256::from(900),
            ..Default::default()
        });

        test_root_ok(&account, true);
        // test_internal_ok(0x20, 0x00, &account, true);
        // test_internal_ok(0x1010, 0xff, &account, true);
    }

    fn test_root_ok(account: &Option<Account>, is_warm: bool) {
        let address = account.as_ref().map(|a| a.address).unwrap_or(*TEST_ADDRESS);
        let address_mem_offset = 20;
        let result_mem_offset = 20;

        let mut code = Bytecode::default();
        code.with_global_data(0, 0, address.to_fixed_bytes().to_vec());
        if is_warm {
            code.append(&bytecode! {
                I32Const[address_mem_offset]
                I32Const[result_mem_offset]
                BALANCE
            });
        }
        code.append(&bytecode! {
            I32Const[address_mem_offset]
            I32Const[result_mem_offset]
            BALANCE
        });

        let ctx = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x000000000000000000000000000000000000cafe"))
                    .balance(Word::from(1_u64 << 20))
                    .code(code.wasm_binary());
                // Set balance if account exists.
                if let Some(account) = account {
                    accs[1].address(address).balance(account.balance);
                } else {
                    accs[1]
                        .address(address!("0x0000000000000000000000000000000000000010"))
                        .balance(Word::from(1_u64 << 20));
                }
                accs[2]
                    .address(address!("0x0000000000000000000000000000000000000020"))
                    .balance(Word::from(1_u64 << 20));
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
        code_b.with_global_data(0, 0, address.to_fixed_bytes().to_vec());
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
                accs[0].address(addr_b).code(code_b.wasm_binary());
                accs[1].address(addr_a).code(code_a.wasm_binary());
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