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
            constraint_builder::{ConstrainBuilderCommon, StepStateTransition, Transition::Delta},
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use crate::evm_circuit::util::Cell;
use crate::evm_circuit::util::constraint_builder::EVMConstraintBuilder;

#[derive(Clone, Debug)]
pub(crate) struct WasmTableGadget<F> {
    same_context: SameContextGadget<F>,
    is_size_op: Cell<F>,
    is_grow_op: Cell<F>,
    is_fill_op: Cell<F>,
    is_get_op: Cell<F>,
    is_set_op: Cell<F>,
    is_copy_op: Cell<F>,
    is_init_op: Cell<F>,
    table_index: Cell<F>,
    table_index_rhs: Cell<F>,
    elem_index: Cell<F>,
    arg: Cell<F>,
    value: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for WasmTableGadget<F> {
    const NAME: &'static str = "WASM_TABLE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::WASM_TABLE;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let is_size_op = cb.query_cell();
        let is_grow_op = cb.query_cell();
        let is_fill_op = cb.query_cell();
        let is_get_op = cb.query_cell();
        let is_set_op = cb.query_cell();
        let is_copy_op = cb.query_cell();
        let is_init_op = cb.query_cell();

        cb.require_equal(
            "op_table: selector",
            is_size_op.expr() + is_grow_op.expr() + is_fill_op.expr() +
            is_get_op.expr() + is_set_op.expr() +
            is_copy_op.expr() + is_init_op.expr(),
            1.expr(),
        );

        let table_index = cb.query_cell();
        let table_index_rhs = cb.query_cell();
        let elem_index = cb.query_cell();
        let arg = cb.query_cell();
        let value = cb.query_cell();

        cb.condition(is_size_op.expr(), |cb| {
            cb.table_size(table_index.expr());
            cb.stack_push(value.expr()); // Result of operation is size.
        });

        cb.condition(is_grow_op.expr(), |cb| {
            cb.stack_pop(arg.expr()); // Input argument if how much to grow.
            cb.table_grow(table_index.expr(), arg.expr(), value.expr());
            cb.stack_push(value.expr()); // Result of grow.
        });

        cb.condition(is_fill_op.expr(), |cb| {
            cb.stack_pop(elem_index.expr()); // Staring point of range.
            cb.stack_pop(arg.expr()); // Length of range.
            cb.table_fill(table_index.expr(), elem_index.expr(), arg.expr());
        });

        cb.condition(is_set_op.expr(), |cb| {
            cb.stack_pop(value.expr());
            cb.table_get(table_index.expr(), elem_index.expr());
        });

        cb.condition(is_get_op.expr(), |cb| {
            cb.table_set(table_index.expr(), elem_index.expr(), value.expr());
            cb.stack_push(value.expr());
        });

        cb.condition(is_copy_op.expr(), |cb| {
            cb.stack_pop(elem_index.expr());
            cb.stack_pop(arg.expr());
            cb.stack_pop(value.expr());
            cb.table_copy(table_index.expr(), table_index_rhs.expr(), elem_index.expr(), arg.expr(), value.expr());
        });

        cb.condition(is_init_op.expr(), |cb| {
            cb.stack_pop(elem_index.expr());
            cb.stack_pop(arg.expr());
            cb.stack_pop(value.expr());
            cb.table_init(table_index.expr(), table_index_rhs.expr(), elem_index.expr(), arg.expr(), value.expr());
        });

        let sp = is_get_op.expr() * (-1).expr() + is_set_op.expr() * (1).expr();

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(2.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(sp),
            gas_left: Delta(-OpcodeId::TableGet.constant_gas_cost().expr()),
            ..Default::default()
        };

        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            is_size_op,
            is_grow_op,
            is_fill_op,
            is_set_op,
            is_get_op,
            is_copy_op,
            is_init_op,
            table_index,
            table_index_rhs,
            elem_index,
            arg,
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
            OpcodeId::TableSize => { self.is_size_op.assign(region, offset, Value::known(F::one()))?; }
            OpcodeId::TableGrow => { self.is_grow_op.assign(region, offset, Value::known(F::one()))?; }
            OpcodeId::TableFill => { self.is_fill_op.assign(region, offset, Value::known(F::one()))?; }
            OpcodeId::TableSet => {
                self.is_set_op.assign(region, offset, Value::known(F::one()))?;
                //let (value, index) = block.rws[step.rw_indices[1]].global_value();
                //self.value.assign(region, offset, Value::<F>::known(value.to_scalar().unwrap()))?;
                //self.index.assign(region, offset, Value::<F>::known(index.to_scalar().unwrap()))?;
            },
            OpcodeId::TableGet => {
                self.is_get_op.assign(region, offset, Value::known(F::one()))?;
                //let (value, index) = block.rws[step.rw_indices[0]].global_value();
                //self.value.assign(region, offset, Value::<F>::known(value.to_scalar().unwrap()))?;
                //self.index.assign(region, offset, Value::<F>::known(index.to_scalar().unwrap()))?;
            },
            OpcodeId::TableCopy => { self.is_copy_op.assign(region, offset, Value::known(F::one()))?; }
            OpcodeId::TableInit => { self.is_init_op.assign(region, offset, Value::known(F::one()))?; }
            _ => unreachable!("not supported opcode: {:?}", step.opcode),
        };

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use eth_types::{bytecode, Bytecode};
    use eth_types::bytecode::{TableVariable, WasmBinaryBytecode};
    use eth_types::evm_types::OpcodeId::I32Const;
    use mock::TestContext;

    use crate::test_util::CircuitTestBuilder;

    fn run_test(bytecode: Bytecode) {
        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        ).run()
    }

    #[test]
    fn test_table_get() {
        let mut code = bytecode! {
            I64Const[0]
            TableGet[0]
            Drop
        };
        code.with_table_variable(TableVariable::default_i32(0, 0, 0x7f));
        run_test(code);
    }

}
