use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::Error;

use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToScalar};

use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            CachedRegion,
            Cell,
            common_gadget::SameContextGadget, constraint_builder::{StepStateTransition, Transition::Delta},
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use crate::evm_circuit::util::constraint_builder::EVMConstraintBuilder;

#[derive(Clone, Debug)]
pub(crate) struct WasmDropGadget<F> {
    same_context: SameContextGadget<F>,
    phase2_value: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for WasmDropGadget<F> {
    const NAME: &'static str = "WASM_DROP";

    const EXECUTION_STATE: ExecutionState = ExecutionState::WASM_DROP;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let phase2_value = cb.query_cell_phase2();

        // Pop the value from the stack
        cb.stack_pop(phase2_value.expr());

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(1.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
            gas_left: Delta(-OpcodeId::POP.constant_gas_cost().expr()),
            ..Default::default()
        };
        let opcode = cb.query_cell();
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            phase2_value,
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
        self.phase2_value.assign(region, offset, Value::known(value.to_scalar().unwrap()))?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use eth_types::{bytecode, Bytecode};
    use mock::TestContext;

    use crate::{test_util::CircuitTestBuilder};

    fn run_test(bytecode: Bytecode) {
        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        ).run()
    }

    #[test]
    fn test_drop() {
        let code = bytecode! {
            I32Const[1]
            I32Const[2]
            I32Const[3]
            Drop
            Drop
            Drop
        };
        run_test(code);
    }
}