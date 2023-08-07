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
pub(crate) struct WasmTableSizeGadget<F> {
    same_context: SameContextGadget<F>,
    table_index: Cell<F>,
    value: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for WasmTableSizeGadget<F> {
    const NAME: &'static str = "WASM_TABLE_SIZE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::WASM_TABLE_SIZE;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let table_index = cb.query_cell();
        let value = cb.query_cell();

        cb.stack_push(value.expr());

/*
        cb.condition(is_size_op.expr(), |cb| {
            cb.table_size(table_index.expr());
            cb.stack_push(value.expr()); // Result of operation is size.
        });
*/

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(1.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
            gas_left: Delta(-OpcodeId::TableSize.constant_gas_cost().expr()),
            ..Default::default()
        };

        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            table_index,
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

        let [value] = [step.rw_indices[0]].map(|idx| block.rws[idx].stack_value());
        self.value.assign(region, offset, Value::<F>::known(value.to_scalar().unwrap()))?;

        match step.opcode.unwrap() {
            OpcodeId::TableSize => (),
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
    fn test_table_size() {
        let mut code = bytecode! {
            TableSize[0]
            Drop
        };
        code.with_table_decl(TableDecl::default());
        run_test(code);
    }

}
