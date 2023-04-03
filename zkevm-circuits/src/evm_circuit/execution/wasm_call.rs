use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::Error;

use bus_mapping::evm::OpcodeId;
use eth_types::Field;

use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            CachedRegion,
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta, Transition::To},
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use crate::evm_circuit::util::Cell;
use crate::table::CallContextFieldTag;

#[derive(Clone, Debug)]
pub(crate) struct WasmCallGadget<F> {
    same_context: SameContextGadget<F>,
    program_counter: Cell<F>,
    function_index: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for WasmCallGadget<F> {
    const NAME: &'static str = "WASM_CALL";

    const EXECUTION_STATE: ExecutionState = ExecutionState::WASM_CALL;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let function_index = cb.query_cell();
        let program_counter = cb.query_cell();

        cb.call_context_lookup(
            1.expr(),
            None,
            CallContextFieldTag::InternalFunctionId,
            function_index.expr(),
        );
        cb.call_context_lookup(
            1.expr(),
            None,
            CallContextFieldTag::ProgramCounter,
            program_counter.expr(),
        );

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(2.expr()),
            program_counter: To(program_counter.expr()),
            stack_pointer: Delta(0.expr()),
            gas_left: Delta(-OpcodeId::Call.constant_gas_cost().expr()),
            ..Default::default()
        };

        let opcode = cb.query_cell();
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            program_counter,
            function_index,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction,
        _call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let function_index = block.rws[step.rw_indices[0]].call_context_value();
        self.function_index.assign(region, offset, Value::known(F::from(function_index.low_u64())))?;
        let program_counter = block.rws[step.rw_indices[1]].call_context_value();
        self.program_counter.assign(region, offset, Value::known(F::from(program_counter.low_u64())))?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use wasm_encoder::ValType;

    use eth_types::{bytecode, Bytecode};
    use mock::test_ctx::TestContext;

    use crate::test_util::CircuitTestBuilder;

    fn run_test(bytecode: Bytecode) {
        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        ).run()
    }

    #[test]
    fn test_wasm_locals_encoding() {
        let mut code = bytecode! {
            I32Const[100]
            I32Const[20]
            Call[0]
            Drop
        };
        code.new_function(vec![ValType::I32; 2], vec![ValType::I32; 1], bytecode! {
            GetLocal[0]
            GetLocal[1]
            I32Add
            SetLocal[2]
            I32Const[0]
            TeeLocal[2]
            Return
        }, vec![(1, ValType::I32)]);
        run_test(code);
    }
}
