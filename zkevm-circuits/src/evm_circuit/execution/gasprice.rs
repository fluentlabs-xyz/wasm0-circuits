use crate::{
    evm_circuit::{
        param::N_BYTES_WORD,
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{CallContextFieldTag, TxContextFieldTag},
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToLittleEndian, ToScalar};
use halo2_proofs::{circuit::Value, plonk::Error};
use halo2_proofs::plonk::Error::Synthesis;
use crate::evm_circuit::util::{RandomLinearCombination};

#[derive(Clone, Debug)]
pub(crate) struct GasPriceGadget<F> {
    tx_id: Cell<F>,
    gas_price: RandomLinearCombination<F, N_BYTES_WORD>,
    dest_offset: Cell<F>,
    same_context: SameContextGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for GasPriceGadget<F> {
    const NAME: &'static str = "GASPRICE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::GASPRICE;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        // Query gasprice value
        let gas_price = cb.query_word_rlc();
        let dest_offset = cb.query_cell();

        // Lookup in call_ctx the TxId
        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        // Lookup the gas_price in tx table
        cb.tx_context_lookup(
            tx_id.expr(),
            TxContextFieldTag::GasPrice,
            None,
            gas_price.expr(),
        );

        // Push the value to the stack
        cb.stack_pop(dest_offset.expr());

        // State transition
        let opcode = cb.query_cell();
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(34.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
            gas_left: Delta(-OpcodeId::GASPRICE.constant_gas_cost().expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            tx_id,
            gas_price,
            same_context,
            dest_offset,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        tx: &Transaction,
        _: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        let gas_price = tx.gas_price;
        let dest_offset = block.rws[step.rw_indices[1]].stack_value();

        self.tx_id
            .assign(region, offset, Value::known(F::from(tx.id as u64)))?;

        self.gas_price.assign(
            region,
            offset,
            Some(
                gas_price.to_le_bytes()
                    .try_into()
                    .unwrap(),
            ),
        )?;
        self.dest_offset.assign(
            region,
            offset,
            Value::<F>::known(dest_offset.to_scalar().ok_or(Synthesis)?),
        )?;

        self.same_context.assign_exec_step(region, offset, step)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::CircuitTestBuilder;
    use eth_types::{bytecode, Word};
    use mock::test_ctx::{helpers::*, TestContext};

    #[test]
    fn gasprice_gadget_test() {
        let res_mem_address = 0x7f;
        let bytecode = bytecode! {
            I32Const[res_mem_address]
            GASPRICE
        };

        let two_gwei = Word::from(2_000_000_000u64);

        // Get the execution steps from the external tracer
        let ctx = TestContext::<2, 1>::new(
            None,
            account_0_code_account_1_no_code(bytecode, None),
            |mut txs, accs| {
                txs[0]
                    .from(accs[1].address)
                    .to(accs[0].address)
                    .gas_price(two_gwei);
            },
            |block, _tx| block.number(0xcafeu64),
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }
}
