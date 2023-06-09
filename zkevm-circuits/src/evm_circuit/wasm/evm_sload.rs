use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::{SameContextGadget, SloadGasGadget},
            constraint_builder::{
                ReversionInfo, StepStateTransition, Transition::Delta,
            },
            CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::CallContextFieldTag,
    util::Expr,
};
use eth_types::{Field, ToLittleEndian, ToScalar, ToU256, Word};
use halo2_proofs::{circuit::Value, plonk::Error};
use itertools::Itertools;
use crate::evm_circuit::util::constraint_builder::EVMConstraintBuilder;
use crate::evm_circuit::util::RandomLinearCombination;

#[derive(Clone, Debug)]
pub(crate) struct EvmSloadGadget<F> {
    same_context: SameContextGadget<F>,
    tx_id: Cell<F>,
    reversion_info: ReversionInfo<F>,
    callee_address: Cell<F>,
    key_offset: Cell<F>,
    key: RandomLinearCombination<F, 32>,
    value_offset: Cell<F>,
    value: RandomLinearCombination<F, 32>,
    committed_value: RandomLinearCombination<F, 32>,
    is_warm: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for EvmSloadGadget<F> {
    const NAME: &'static str = "SLOAD";

    const EXECUTION_STATE: ExecutionState = ExecutionState::SLOAD;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let mut reversion_info = cb.reversion_info_read(None);
        let callee_address = cb.call_context(None, CallContextFieldTag::CalleeAddress);

        let value_offset = cb.query_cell();
        let key_offset = cb.query_cell();

        let key = cb.query_word_rlc();
        // Pop the key from the stack
        cb.stack_pop(value_offset.expr());
        cb.stack_pop(key_offset.expr());

        let value = cb.query_word_rlc();
        let committed_value = cb.query_word_rlc();
        cb.account_storage_read(
            callee_address.expr(),
            key.expr(),
            value.expr(),
            tx_id.expr(),
            committed_value.expr(),
        );

        cb.memory_rlc_lookup(0.expr(), &key_offset, &key);
        cb.memory_rlc_lookup(1.expr(), &value_offset, &value);

        let is_warm = cb.query_bool();
        cb.account_storage_access_list_write(
            tx_id.expr(),
            callee_address.expr(),
            key.expr(),
            true.expr(),
            is_warm.expr(),
            Some(&mut reversion_info),
        );

        let gas_cost = SloadGasGadget::construct(cb, is_warm.expr()).expr();
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(8.expr()),
            program_counter: Delta(1.expr()),
            reversible_write_counter: Delta(1.expr()),
            gas_left: Delta(-gas_cost),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            tx_id,
            reversion_info,
            callee_address,
            key_offset,
            key,
            value_offset,
            value,
            committed_value,
            is_warm,
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

        self.tx_id
            .assign(region, offset, Value::known(F::from(tx.id as u64)))?;
        self.reversion_info.assign(
            region,
            offset,
            call.rw_counter_end_of_reversion,
            call.is_persistent,
        )?;
        self.callee_address.assign(
            region,
            offset,
            Value::known(
                call.callee_address
                    .to_scalar()
                    .expect("unexpected Address -> Scalar conversion failure"),
            ),
        )?;

        let [value_offset, key_offset] =
            [step.rw_indices[4], step.rw_indices[5]].map(|idx| block.rws[idx].stack_value());
        self.value_offset.assign(region, offset, Value::known(F::from(value_offset.as_u64())))?;
        self.key_offset.assign(region, offset, Value::known(F::from(key_offset.as_u64())))?;

        let (key, value) = block.rws[step.rw_indices[5+1]].storage_key_value();
        self.key.assign(region, offset, Some(key.to_le_bytes()))?;
        self.value.assign(region, offset, Some(value.to_le_bytes()))?;

        let (_, committed_value) = block.rws[step.rw_indices[5+1]].aux_pair();
        self.committed_value.assign(region, offset, Some(committed_value.to_le_bytes()))?;

        let (_, is_warm) = block.rws[step.rw_indices[5+32+1+32+1]].tx_access_list_value_pair();
        self.is_warm.assign(region, offset, Value::known(F::from(is_warm as u64)))?;

        Ok(())
    }
}

#[cfg(test)]
mod test {

    use crate::{evm_circuit::test::rand_word, test_util::CircuitTestBuilder};
    use eth_types::{bytecode, Bytecode, bytecode_internal, ToBigEndian, Word};
    use eth_types::bytecode::WasmBinaryBytecode;
    use mock::{test_ctx::helpers::tx_from_1_to_0, TestContext, MOCK_ACCOUNTS};

    fn test_ok(key: Word, value: Word) {
        // Here we use two bytecodes to test both is_persistent(STOP) or not(REVERT)
        // Besides, in bytecode we use two SLOADs,
        // the first SLOAD is used to test cold,  and the second is used to test warm
        let mut bytecode_success = Bytecode::default();
        let mut bytecode_failure = Bytecode::default();
        let key_offset = bytecode_success.fill_default_global_data(key.to_be_bytes().to_vec());
        let value_offset = bytecode_success.alloc_default_global_data(32);
        bytecode_internal! {bytecode_success,
            I32Const[key_offset]
            I32Const[value_offset]
            SLOAD
            I32Const[key_offset]
            I32Const[value_offset]
            SLOAD
        }
        let key_offset = bytecode_failure.fill_default_global_data(key.to_be_bytes().to_vec());
        let value_offset = bytecode_failure.alloc_default_global_data(32);
        bytecode_internal! {bytecode_failure,
            I32Const[key_offset]
            I32Const[value_offset]
            SLOAD
            I32Const[key_offset]
            I32Const[value_offset]
            SLOAD
            I32Const[0]
            I32Const[0]
            REVERT
        }
        for bytecode in [bytecode_success, bytecode_failure] {
            let ctx = TestContext::<2, 1>::new(
                None,
                |accs| {
                    accs[0]
                        .address(MOCK_ACCOUNTS[0])
                        .balance(Word::from(10u64.pow(19)))
                        .code(bytecode.wasm_binary())
                        .storage(vec![(key, value)].into_iter());
                    accs[1]
                        .address(MOCK_ACCOUNTS[1])
                        .balance(Word::from(10u64.pow(19)));
                },
                tx_from_1_to_0,
                |block, _txs| block,
            )
            .unwrap();

            CircuitTestBuilder::new_from_test_ctx(ctx).run();
        }
    }

    #[test]
    fn sload_gadget_simple() {
        let key = 0x030201.into();
        let value = 0x060504.into();
        test_ok(key, value);
    }

    #[test]
    fn sload_gadget_rand() {
        let key = rand_word();
        let value = rand_word();
        test_ok(key, value);
    }
}
