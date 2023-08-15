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
pub(crate) struct WasmTableGrowGadget<F> {
    same_context: SameContextGadget<F>,
    table_index: Cell<F>,
    init_val: Cell<F>,
    grow_val: Cell<F>,
    res_val: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for WasmTableGrowGadget<F> {
    const NAME: &'static str = "WASM_TABLE_GROW";

    const EXECUTION_STATE: ExecutionState = ExecutionState::WASM_TABLE_GROW;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let table_index = cb.query_cell();
        let init_val = cb.query_cell();
        let grow_val = cb.query_cell();
        let res_val = cb.query_cell();

        cb.stack_pop(init_val.expr());
        cb.stack_pop(grow_val.expr());
        cb.stack_push(res_val.expr());

/*
        cb.condition(is_grow_op.expr(), |cb| {
            cb.stack_pop(init_val.expr());
            cb.stack_pop(grow_val.expr()); // Input argument if how much to grow.
            cb.table_grow(table_index.expr(), init_val.expr(), grow_val.expr(), value.expr());
            cb.stack_push(value.expr()); // Result of grow.
        });
*/

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(3.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
            gas_left: Delta(-OpcodeId::TableGrow.constant_gas_cost().expr()),
            ..Default::default()
        };

        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            table_index,
            init_val,
            grow_val,
            res_val,
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

        let [init_val, grow_val, res_val] =
            [step.rw_indices[0], step.rw_indices[1], step.rw_indices[2]]
            .map(|idx| block.rws[idx].stack_value());

        match step.opcode.unwrap() {
            OpcodeId::TableGrow => (),
            _ => unreachable!("not supported opcode: {:?}", step.opcode),
        };

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use eth_types::{bytecode, Bytecode};
    use eth_types::bytecode::{TableDecl, WasmBinaryBytecode};
    use eth_types::evm_types::OpcodeId::I32Const;
    use mock::TestContext;

    use crate::test_util::CircuitTestBuilder;

    fn run_test(bytecode: Bytecode) {
        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        ).run()
    }

    #[test]
    fn test_table_grow() {
        let mut code = bytecode! {
            RefFunc[0x0]
            I32Const[2]
            TableGrow[0]
            Drop
        };
        code.with_table_decl(TableDecl::default_i32());
        run_test(code);
    }

}
