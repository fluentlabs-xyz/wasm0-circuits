use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            CachedRegion, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use eth_types::{evm_types::OpcodeId, Field, ToLittleEndian};
use halo2_proofs::{plonk::Error};

#[derive(Clone, Debug)]
pub(crate) struct PushGadget<F> {
    same_context: SameContextGadget<F>,
    value: Word<F>,
}

impl<F: Field> ExecutionGadget<F> for PushGadget<F> {
    const NAME: &'static str = "PUSH";

    const EXECUTION_STATE: ExecutionState = ExecutionState::PUSH;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let value = cb.query_word_rlc();

        // Push the value on the stack
        cb.stack_push(value.expr());

        // State transition
        // `program_counter` needs to be increased by number of bytes pushed + 1
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(1.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta((-1).expr()),
            gas_left: Delta(-OpcodeId::I32Const(0).constant_gas_cost().expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            value,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction,
        _: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let value = block.rws[step.rw_indices[0]].stack_value();
        self.value
            .assign(region, offset, Some(value.to_le_bytes()))?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{test_util::CircuitTestBuilder};
    use eth_types::{bytecode, Bytecode};
    use mock::TestContext;

    fn test_ok(bytecode: Bytecode) {
        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run();
    }

    #[test]
    fn push_gadget_simple() {
        test_ok(bytecode! {
            I32Const[12]
            Drop
        });
    }
}
