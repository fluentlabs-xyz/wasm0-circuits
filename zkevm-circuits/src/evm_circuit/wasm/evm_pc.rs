use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_PROGRAM_COUNTER,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstrainBuilderCommon, StepStateTransition, Transition::Delta},
            from_bytes, CachedRegion, RandomLinearCombination,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use eth_types::Field;
use halo2_proofs::plonk::Error;
use crate::evm_circuit::util::Cell;
use crate::evm_circuit::util::constraint_builder::EVMConstraintBuilder;
use halo2_proofs::circuit::Value;

#[derive(Clone, Debug)]
pub(crate) struct EvmPcGadget<F> {
    same_context: SameContextGadget<F>,
    value: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for EvmPcGadget<F> {
    const NAME: &'static str = "PC";

    const EXECUTION_STATE: ExecutionState = ExecutionState::PC;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let value = cb.query_cell();

        // program_counter is limited to 64 bits so we only consider 8 bytes
        cb.require_equal(
            "Constrain program_counter equal to stack value",
           value.expr(),
            cb.curr.state.program_counter.expr(),
        );

        // Push the value on the stack
        // cb.stack_push(value.expr());

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(1.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta((-1).expr()),
            gas_left: Delta(-OpcodeId::PC.constant_gas_cost().expr()),
            ..Default::default()
        };
        let opcode = cb.query_cell();
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
        _: &Block<F>,
        _: &Transaction,
        _: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        self.value
            .assign(region, offset, Value::known(F::from(step.program_counter)))?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::CircuitTestBuilder;
    use eth_types::{bytecode, Bytecode, bytecode_internal};
    use mock::TestContext;

    fn test_ok() {
        let mut code = Bytecode::default();
        let dest = code.alloc_default_global_data(32);
        bytecode_internal! {code,
            I32Const[dest]
            PC
        };

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(code).unwrap(),
        )
        .run();
    }

    #[test]
    fn pc_gadget_simple() {
        test_ok();
    }
}
