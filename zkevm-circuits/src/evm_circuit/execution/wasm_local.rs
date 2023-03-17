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
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use crate::evm_circuit::util::Cell;

#[derive(Clone, Debug)]
pub(crate) struct WasmLocalGadget<F> {
    same_context: SameContextGadget<F>,
    is_get_local: Cell<F>,
    is_set_local: Cell<F>,
    index: Cell<F>,
    value: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for WasmLocalGadget<F> {
    const NAME: &'static str = "WASM_LOCAL";

    const EXECUTION_STATE: ExecutionState = ExecutionState::WASM_LOCAL;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let is_get_local = cb.query_cell();
        let is_set_local = cb.query_cell();

        let index = cb.query_cell();
        let value = cb.query_cell();

        cb.require_equal(
            "op_local: selector",
            is_get_local.expr() + is_set_local.expr(),
            1.expr(),
        );

        cb.condition(is_set_local.expr(), |cb| {
            cb.stack_pop(value.expr());
            cb.stack_lookup(1.expr(), cb.stack_pointer_offset() - index.expr(), value.expr());
        });

        cb.condition(is_get_local.expr(), |cb| {
            cb.stack_lookup(0.expr(), cb.stack_pointer_offset() - index.expr(), value.expr());
            cb.stack_push(value.expr());
        });

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(2.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
            gas_left: Delta(-OpcodeId::GetLocal.constant_gas_cost().expr()),
            ..Default::default()
        };

        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            is_set_local,
            is_get_local,
            index,
            value,
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

        match step.opcode.unwrap() {
            OpcodeId::SetLocal => {
                self.is_set_local.assign(region, offset, Value::known(F::one()))?;
                let (value, index) = block.rws[step.rw_indices[1]].local_value();
                self.value.assign(region, offset, Value::<F>::known(value.to_scalar().unwrap()))?;
                self.index.assign(region, offset, Value::<F>::known(index.to_scalar().unwrap()))?;
            },
            OpcodeId::GetLocal => {
                self.is_get_local.assign(region, offset, Value::known(F::one()))?;
                let (value, index) = block.rws[step.rw_indices[0]].local_value();
                self.value.assign(region, offset, Value::<F>::known(value.to_scalar().unwrap()))?;
                self.index.assign(region, offset, Value::<F>::known(index.to_scalar().unwrap()))?;
            },
            _ => unreachable!("not supported opcode: {:?}", step.opcode),
        };

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use wasm_encoder::ValType;
    use eth_types::{bytecode, Bytecode};
    use mock::TestContext;

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
        code.new_function(vec![ValType::I32; 2], vec![ValType::I32], bytecode! {
            GetLocal[0]
            GetLocal[1]
            I32Add
            SetLocal[2]
            I32Const[0]
        }, vec![(1, ValType::I32)]);
        run_test(code);
    }
}
