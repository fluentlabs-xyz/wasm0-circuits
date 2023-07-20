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
    is_get_table: Cell<F>,
    is_set_table: Cell<F>,
    table_index: Cell<F>,
    elem_index: Cell<F>,
    value: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for WasmTableGadget<F> {
    const NAME: &'static str = "WASM_TABLE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::WASM_TABLE;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let is_get_table = cb.query_cell();
        let is_set_table = cb.query_cell();

        cb.require_equal(
            "op_table: selector",
            is_get_table.expr() + is_set_table.expr(),
            1.expr(),
        );

        let table_index = cb.query_cell();
        let elem_index = cb.query_cell();
        let value = cb.query_cell();

        cb.condition(is_set_table.expr(), |cb| {
            cb.stack_pop(value.expr());
            cb.table_write(table_index.expr(), elem_index.expr() value.expr());
        });

        cb.condition(is_get_global.expr(), |cb| {
            cb.table_read(table_index.expr(), elem_index.expr(), value.expr());
            cb.stack_push(value.expr());
        });

        let sp = is_get_table.expr() * (-1).expr() + is_set_table.expr() * (1).expr();

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(2.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(sp),
            gas_left: Delta(-OpcodeId::GetTable.constant_gas_cost().expr()),
            ..Default::default()
        };

        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            is_set_table,
            is_get_table,
            table_index,
            elem_index,
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
            OpcodeId::SetTable => {
                self.is_set_table.assign(region, offset, Value::known(F::one()))?;
                //let (value, index) = block.rws[step.rw_indices[1]].global_value();
                //self.value.assign(region, offset, Value::<F>::known(value.to_scalar().unwrap()))?;
                //self.index.assign(region, offset, Value::<F>::known(index.to_scalar().unwrap()))?;
            },
            OpcodeId::GetTable => {
                self.is_get_table.assign(region, offset, Value::known(F::one()))?;
                //let (value, index) = block.rws[step.rw_indices[0]].global_value();
                //self.value.assign(region, offset, Value::<F>::known(value.to_scalar().unwrap()))?;
                //self.index.assign(region, offset, Value::<F>::known(index.to_scalar().unwrap()))?;
            },
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

/*
    #[test]
    fn test_global_get() {
        let mut code = bytecode! {
            GetGlobal[0]
            Drop
        };
        code.with_global_variable(TableVariable::default_i32(0, 0x7f));
        run_test(code);
    }

    #[test]
    fn test_global_set() {
        let t: i32 = -16383;
        let mut code = bytecode! {
            I32Const[t]
            SetGlobal[0]
            GetGlobal[0]
            Drop
        };
        println!("code.wasm_binary() {:x?}", code.wasm_binary());

        // code.with_global_variable(GlobalVariable::default_i32(0, 0));
        // run_test(code);
    }
*/
}
