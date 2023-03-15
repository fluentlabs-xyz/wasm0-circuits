use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::{Error, Expression};

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
pub(crate) struct WasmTestGadget<F> {
    same_context: SameContextGadget<F>,
    is_i64: Cell<F>,
    value_inv: Cell<F>,
    value: Cell<F>,
    res: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for WasmTestGadget<F> {
    const NAME: &'static str = "WASM_TEST";

    const EXECUTION_STATE: ExecutionState = ExecutionState::WASM_TEST;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let value = cb.alloc_u64();
        let res = cb.alloc_bit_value();
        let is_i64 = cb.alloc_bit_value();
        let value_inv = cb.alloc_unlimited_value();

        cb.stack_pop(value.expr());
        cb.stack_push(res.expr());

        cb.require_zeros("op_test: constraints", vec![
            res.expr() * value.expr(),
            value.expr() * value_inv.expr() - 1.expr() + res.expr(),
        ]);

        let opcode = cb.query_cell();

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(2.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(0.expr()),
            gas_left: Delta(-OpcodeId::I32Eqz.constant_gas_cost().expr()),
            ..StepStateTransition::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            is_i64,
            value_inv,
            value,
            res,
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

        let opcode = step.opcode.unwrap();

        let [value, res] = [step.rw_indices[0], step.rw_indices[1]]
            .map(|idx| block.rws[idx].stack_value());

        self.value.assign(region, offset, Value::known(value.to_scalar().unwrap()))?;
        self.value_inv.assign(region, offset, Value::known(F::from(value.as_u64()).invert().unwrap_or(F::zero())))?;
        self.res.assign(region, offset, Value::known(res.to_scalar().unwrap()))?;

        match opcode {
            OpcodeId::I64Eqz => {
                let zero_or_one = (value.as_u64() == 0) as u64;
                self.res.assign(region, offset, Value::known(F::from(zero_or_one)))?;
            }
            _ => unreachable!("not supported opcode: {:?}", opcode),
        };
 
        let is_i64 = matches!(opcode,
            OpcodeId::I64Eqz
        );
        self.is_i64.assign(region, offset, Value::known(F::from(is_i64 as u64)))?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use eth_types::{bytecode, Bytecode};
    use mock::TestContext;

    use crate::test_util::CircuitTestBuilder;

    fn run_test(bytecode: Bytecode) {
        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        ).run()
    }

    #[test]
    fn test_i64_eqz() {
        run_test(bytecode! {
            I64Const[0]
            I64Eqz
            Drop
            I64Const[1]
            I64Eqz
            Drop
        });
    }
}
