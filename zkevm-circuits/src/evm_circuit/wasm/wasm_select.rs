use halo2_proofs::plonk::{Error};

use bus_mapping::evm::OpcodeId;
use eth_types::{Field};

use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            CachedRegion,
            common_gadget::SameContextGadget,
            constraint_builder::{StepStateTransition, Transition::Delta},
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use crate::evm_circuit::util::Cell;
use crate::evm_circuit::util::constraint_builder::EVMConstraintBuilder;

#[derive(Clone, Debug)]
pub(crate) struct WasmSelectGadget<F> {
    same_context: SameContextGadget<F>,
    cond: Cell<F>,
    cond_inv: Cell<F>,
    val1: Cell<F>,
    val2: Cell<F>,
    res: Cell<F>,
    vtype: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for WasmSelectGadget<F> {
    const NAME: &'static str = "WASM_SELECT";

    const EXECUTION_STATE: ExecutionState = ExecutionState::WASM_SELECT;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let cond = cb.alloc_u64_on_u8();
        let cond_inv = cb.alloc_unlimited_value();
        let val1 = cb.alloc_u64();
        let val2 = cb.alloc_u64();
        let res = cb.alloc_u64();
        let vtype = cb.alloc_common_range_value();

        cb.stack_pop(cond.expr());
        cb.stack_pop(val2.expr());
        cb.stack_pop(val1.expr());
        cb.stack_push(res.expr());

        cb.require_zeros("op_select: cond is zero", vec![
            (1.expr() - cond.expr() * cond_inv.expr())
                * (res.expr() - val2.expr()),
        ]);

        cb.require_zeros("op_select: cond is not zero", vec![
            cond.expr() * (res.expr() - val1.expr())
        ]);

        let opcode = cb.query_cell();

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(4.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(0.expr()),
            gas_left: Delta(-OpcodeId::Select.constant_gas_cost().expr()),
            ..StepStateTransition::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            cond,
            cond_inv,
            val1,
            val2,
            res,
            vtype,
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
        use eth_types::ToScalar;
        use halo2_proofs::circuit::Value;

        self.same_context.assign_exec_step(region, offset, step)?;

        let opcode = step.opcode.unwrap();

        let [cond, val2, val1, res] = [step.rw_indices[0], step.rw_indices[1], step.rw_indices[2], step.rw_indices[3]]
            .map(|idx| block.rws[idx].stack_value());

        self.cond.assign(region, offset, Value::known(cond.to_scalar().unwrap()))?;
        self.cond_inv.assign(region, offset, Value::known(F::from(cond.as_u64()).invert().unwrap_or(F::zero())))?;
        self.val2.assign(region, offset, Value::known(val2.to_scalar().unwrap()))?;
        self.val1.assign(region, offset, Value::known(val1.to_scalar().unwrap()))?;
        self.res.assign(region, offset, Value::known(res.to_scalar().unwrap()))?;

/*
        self.value.assign(region, offset, Value::known(value.to_scalar().unwrap()))?;
        self.value_inv.assign(region, offset, Value::known(F::from(value.as_u64()).invert().unwrap_or(F::zero())))?;
        self.res.assign(region, offset, Value::known(res.to_scalar().unwrap()))?;

        match opcode {
            OpcodeId::I64Eqz => {
                let zero_or_one = (value.as_u64() == 0) as u64;
                self.res.assign(region, offset, Value::known(F::from(zero_or_one)))?;
            }
            OpcodeId::I32Eqz => {
                let zero_or_one = (value.as_u32() == 0) as u64;
                self.res.assign(region, offset, Value::known(F::from(zero_or_one)))?;
            }
            _ => unreachable!("not supported opcode: {:?}", opcode),
        };
 
        let is_i64 = matches!(opcode,
            OpcodeId::I64Eqz
        );
        self.is_i64.assign(region, offset, Value::known(F::from(is_i64 as u64)))?;
*/

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
    fn test_select_i32() {
        run_test(bytecode! {
            I32Const[1]
            I32Const[2]
            I32Const[0]
            Select
            Drop
        });
    }

    #[test]
    fn test_select_i64() {
        run_test(bytecode! {
            I32Const[1]
            I32Const[2]
            I64Const[0]
            Select
            Drop
        });
    }
}
