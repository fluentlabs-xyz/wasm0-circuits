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
pub(crate) struct WasmTableCopyGadget<F> {
    same_context: SameContextGadget<F>,
    table_index: Cell<F>,
    table_index_rhs: Cell<F>,
    src_idx: Cell<F>,
    dst_idx: Cell<F>,
    range: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for WasmTableCopyGadget<F> {
    const NAME: &'static str = "WASM_TABLE_COPY";

    const EXECUTION_STATE: ExecutionState = ExecutionState::WASM_TABLE_COPY;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let table_index = cb.query_cell();
        let table_index_rhs = cb.query_cell();
        let src_idx = cb.query_cell();
        let dst_idx = cb.query_cell();
        let range = cb.query_cell();

        cb.stack_pop(src_idx.expr());
        cb.stack_pop(dst_idx.expr());
        cb.stack_pop(range.expr());

/*
        cb.condition(is_copy_op.expr(), |cb| {
            cb.stack_pop(src_idx.expr());
            cb.stack_pop(dst_idx.expr());
            cb.stack_pop(range.expr());
            cb.table_copy(table_index.expr(), table_index_rhs.expr(), src_idx.expr(), dst_idx.expr(), range_idx.expr());
        });
*/

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(3.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
            gas_left: Delta(-OpcodeId::TableGet.constant_gas_cost().expr()),
            ..Default::default()
        };

        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            table_index,
            table_index_rhs,
            src_idx,
            dst_idx,
            range,
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

        let [src_idx, dst_idx, range] =
            [step.rw_indices[0], step.rw_indices[1], step.rw_indices[2]]
            .map(|idx| block.rws[idx].stack_value());

        match step.opcode.unwrap() {
            OpcodeId::TableCopy => (),
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

/*
    TODO: working with two op args.
    #[test]
    fn test_table_copy() {
        let mut code = bytecode! {
            I32Const[0]
            I32Const[0]
            I32Const[2]
            TableCopy[0,1]
            Drop
        };
        code.with_table_decl(TableDecl::default_i32());
        code.with_table_decl(TableDecl::default_i32());
        run_test(code);
    }
*/

}
