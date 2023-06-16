use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_ACCOUNT_ADDRESS,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ReversionInfo, StepStateTransition, Transition::Delta,
            },
            from_bytes, select, CachedRegion, Cell, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{AccountFieldTag, CallContextFieldTag},
    util::Expr,
};
use eth_types::{evm_types::GasCost, Field, ToLittleEndian, ToScalar, ToU256};
use halo2_proofs::{circuit::Value, plonk::Error};
use gadgets::util::not;
use crate::evm_circuit::param::N_BYTES_WORD;
use crate::evm_circuit::util::constraint_builder::EVMConstraintBuilder;
use crate::evm_circuit::util::math_gadget::IsZeroGadget;
use crate::evm_circuit::util::{RandomLinearCombination, rlc};
use crate::table::RwTableTag;

#[derive(Clone, Debug)]
pub(crate) struct EvmExtCodeHashGadget<F> {
    same_context: SameContextGadget<F>,
    address_offset: Cell<F>,
    address_word: RandomLinearCombination<F, N_BYTES_ACCOUNT_ADDRESS>,
    codehash_offset: Cell<F>,
    code_hash: Word<F>,
    tx_id: Cell<F>,
    reversion_info: ReversionInfo<F>,
    is_warm: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for EvmExtCodeHashGadget<F> {
    const NAME: &'static str = "EXTCODEHASH";

    const EXECUTION_STATE: ExecutionState = ExecutionState::EXTCODEHASH;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let address_word = cb.query_word_rlc();
        let address = from_bytes::expr(&address_word.cells[..N_BYTES_ACCOUNT_ADDRESS]);

        let codehash_offset = cb.query_cell();
        let address_offset = cb.query_cell();

        cb.stack_pop(codehash_offset.expr());
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

        let code_hash = cb.query_word_rlc();
        // let exprs = code_hash.clone().cells.map(|v| v.expr());

        // For non-existing accounts the code_hash must be 0 in the rw_table.
        // if cfg!(feature = "poseidon-codehash") {
        //     let codehash_rlc = rlc::expr(&exprs, 256.expr());
        //     cb.account_read(address.expr(), AccountFieldTag::KeccakCodeHash, codehash_rlc);
        // } else {
        // }
        cb.account_read(address.expr(), AccountFieldTag::KeccakCodeHash, code_hash.expr());

        cb.memory_rlc_lookup(0.expr(), &address_offset, &address_word);
        cb.memory_rlc_lookup(1.expr(), &codehash_offset, &code_hash);

        let gas_cost = select::expr(
            is_warm.expr(),
            GasCost::WARM_ACCESS.expr(),
            GasCost::COLD_ACCOUNT_ACCESS.expr(),
        );
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(cb.rw_counter_offset()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(0.expr()),
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
            codehash_offset,
            tx_id,
            reversion_info,
            is_warm,
            code_hash,
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

        let codehash_offset= block.rws[step.rw_indices[0]].stack_value();
        let address_offset = block.rws[step.rw_indices[1]].stack_value();

        self.codehash_offset.assign(region, offset, Value::<F>::known(codehash_offset.to_scalar().unwrap()))?;
        self.address_offset.assign(region, offset, Value::<F>::known(address_offset.to_scalar().unwrap()))?;

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

        let (codehash, _) = block.rws[step.rw_indices[6]].account_value_pair();
        self.code_hash
            .assign(region, offset, Some(codehash.to_le_bytes()))?;

        let address = block.rws[step.rw_indices[6]].address().unwrap().to_u256();
        self.address_word
            .assign(region, offset, Some(address.to_le_bytes()[0..N_BYTES_ACCOUNT_ADDRESS].try_into().unwrap()))?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::CircuitTestBuilder;
    use eth_types::{address, bytecode, geth_types::Account, Address, Bytecode, Bytes, ToWord, Word, U256, bytecode_internal};
    use lazy_static::lazy_static;
    use mock::TestContext;

    lazy_static! {
        static ref EXTERNAL_ADDRESS: Address =
            address!("0xaabbccddee000000000000000000000000000000");
    }

    fn test_ok(external_account: Option<Account>, is_warm: bool) {
        let external_address = external_account
            .as_ref()
            .map(|a| a.address)
            .unwrap_or(*EXTERNAL_ADDRESS);


        // Make the external account warm, if needed, by first getting its external code
        // hash.
        let mut code = Bytecode::default();
        let external_address_offset= code.fill_default_global_data(external_address.to_fixed_bytes().to_vec());
        let codehash_mem_offset = code.alloc_default_global_data(32);
        if is_warm {
            bytecode_internal! {code,
                I32Const[external_address_offset]
                I32Const[codehash_mem_offset]
                EXTCODEHASH
            }
        }
        bytecode_internal! {code,
            I32Const[external_address_offset]
            I32Const[codehash_mem_offset]
            EXTCODEHASH
        }

        // Execute the bytecode and get trace
        let ctx = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x000000000000000000000000000000000000cafe"))
                    .balance(Word::from(1u64 << 20))
                    .code(code);

                accs[1].address(external_address);
                if let Some(external_account) = external_account {
                    accs[1]
                        .balance(external_account.balance)
                        .nonce(external_account.nonce)
                        .code(external_account.code);
                }
                accs[2]
                    .address(address!("0x0000000000000000000000000000000000000010"))
                    .balance(Word::from(1u64 << 30));
            },
            |mut txs, accs| {
                txs[0].to(accs[0].address).from(accs[2].address);
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    #[test]
    fn extcodehash_warm_empty_account() {
        test_ok(None, true);
    }

    #[test]
    fn extcodehash_cold_empty_account() {
        test_ok(None, false);
    }

    #[test]
    fn extcodehash_warm_existing_account() {
        test_ok(
            Some(Account {
                address: *EXTERNAL_ADDRESS,
                nonce: U256::from(259),
                code: Bytes::from([3]),
                ..Default::default()
            }),
            true,
        );
    }

    #[test]
    fn extcodehash_cold_existing_account() {
        test_ok(
            Some(Account {
                address: *EXTERNAL_ADDRESS,
                balance: U256::from(900),
                code: Bytes::from([32, 59]),
                ..Default::default()
            }),
            false,
        );
    }

    #[test]
    fn extcodehash_nonempty_account_edge_cases() {
        // EIP-158 defines empty accounts to be those with balance = 0, nonce = 0, and
        // code = [].
        let nonce_only_account = Account {
            address: *EXTERNAL_ADDRESS,
            nonce: U256::from(200),
            ..Default::default()
        };
        // This account state is possible if another account sends ETH to a previously
        // empty account.
        let balance_only_account = Account {
            address: *EXTERNAL_ADDRESS,
            balance: U256::from(200),
            ..Default::default()
        };
        // This account state should no longer be possible because contract nonces start
        // at 1, per EIP-161. However, the requirement that the code be empty is still
        // in the yellow paper and our constraints, so we test this case
        // anyways.
        let contract_only_account = Account {
            address: *EXTERNAL_ADDRESS,
            code: Bytes::from([32, 59]),
            ..Default::default()
        };

        for account in [
            nonce_only_account,
            balance_only_account,
            contract_only_account,
        ] {
            test_ok(Some(account), false);
        }
    }
}
