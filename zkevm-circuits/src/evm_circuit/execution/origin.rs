use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_ACCOUNT_ADDRESS,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            from_bytes, CachedRegion, Cell, RandomLinearCombination,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{CallContextFieldTag, TxContextFieldTag},
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToLittleEndian, ToScalar, ToWord};
use halo2_proofs::{circuit::Value, plonk::Error};
use halo2_proofs::plonk::Error::Synthesis;

#[derive(Clone, Debug)]
pub(crate) struct OriginGadget<F> {
    tx_id: Cell<F>,
    origin: RandomLinearCombination<F, N_BYTES_ACCOUNT_ADDRESS>,
    same_context: SameContextGadget<F>,
    dest_offset: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for OriginGadget<F> {
    const NAME: &'static str = "ORIGIN";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ORIGIN;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let origin = cb.query_word_rlc::<N_BYTES_ACCOUNT_ADDRESS>();
        let dest_offset = cb.query_cell();

        // Lookup in call_ctx the TxId
        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        // Lookup rw_table -> call_context with tx origin address
        cb.tx_context_lookup(
            tx_id.expr(),
            TxContextFieldTag::CallerAddress,
            None, // None because unrelated to calldata
            from_bytes::expr(&origin.cells),
        );

        // Push the value to the stack
        cb.stack_pop(dest_offset.expr());

        for idx in 0..20 {
            cb.memory_lookup(
                true.expr(),
                dest_offset.expr() + idx.expr(),
                origin.cells[20 - idx - 1].expr(),
                None,
            );
        }

        // State transition
        let opcode = cb.query_cell();
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(22.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
            gas_left: Delta(-OpcodeId::ORIGIN.constant_gas_cost().expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            tx_id,
            origin,
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
        self.same_context.assign_exec_step(region, offset, step)?;

        self.tx_id
            .assign(region, offset.clone(), Value::known(F::from(tx.id as u64)))?;

        let origin = tx.caller_address.to_word();
        let dest_offset = block.rws[step.rw_indices[1]].stack_value();

        // Assign Origin addr RLC.
        self.origin.assign(
            region,
            offset,
            Some(
                origin.to_le_bytes()[..N_BYTES_ACCOUNT_ADDRESS]
                    .try_into()
                    .unwrap(),
            ),
        )?;
        self.dest_offset.assign(
            region,
            offset,
            Value::<F>::known(dest_offset.to_scalar().ok_or(Synthesis)?),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::CircuitTestBuilder;
    use eth_types::bytecode;
    use mock::TestContext;

    #[test]
    fn origin_gadget_test() {
        let res_mem_address = 0x7f;
        let bytecode = bytecode! {
            I32Const[res_mem_address]
            ORIGIN
        };

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run();
    }
}
