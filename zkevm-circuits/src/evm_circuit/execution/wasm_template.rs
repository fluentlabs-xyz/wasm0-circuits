use std::convert::TryInto;

use halo2_proofs::plonk::Error;

use bus_mapping::evm::OpcodeId;
use eth_types::Field;

use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_ACCOUNT_ADDRESS,
        step::ExecutionState,
        util::{
            CachedRegion,
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta}, from_bytes, RandomLinearCombination,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::CallContextFieldTag,
    util::Expr,
};
use crate::evm_circuit::util::host_return_gadget::HostReturnGadget;

#[derive(Clone, Debug)]
pub(crate) struct WasmUnaryGadget<F> {
    same_context: SameContextGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for WasmUnaryGadget<F> {
    const NAME: &'static str = "WASM_UNARY";

    const EXECUTION_STATE: ExecutionState = ExecutionState::WASM_UNARY;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(22.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta((-1).expr()),
            gas_left: Delta(-OpcodeId::ADDRESS.constant_gas_cost().expr()),
            ..Default::default()
        };

        let opcode = cb.query_cell();
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;


        Ok(())
    }
}

#[cfg(test)]
mod test {
    use eth_types::{bytecode, ToWord, Word};
    use mock::test_ctx::TestContext;

    use crate::evm_circuit::test::rand_word;
    use crate::test_util::CircuitTestBuilder;
}
