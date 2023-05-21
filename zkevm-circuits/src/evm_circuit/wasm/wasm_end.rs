use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            constraint_builder::{
                ConstrainBuilderCommon, StepStateTransition,
                Transition::{Delta, Same},
            },
            math_gadget::IsZeroGadget,
            CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::CallContextFieldTag,
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use eth_types::Field;
use halo2_proofs::{circuit::Value, plonk::Error};
use crate::evm_circuit::util::constraint_builder::EVMConstraintBuilder;

#[derive(Clone, Debug)]
pub(crate) struct WasmEndGadget<F> {
    code_length: Cell<F>,
    is_out_of_range: IsZeroGadget<F>,
    opcode: Cell<F>,
    // restore_context: RestoreContextGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for WasmEndGadget<F> {
    const NAME: &'static str = "WASM_END";

    const EXECUTION_STATE: ExecutionState = ExecutionState::WASM_END;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let code_length = cb.query_cell();
        cb.bytecode_length(cb.curr.state.code_hash.expr(), code_length.expr());
        let is_out_of_range = IsZeroGadget::construct(
            cb,
            code_length.expr() - cb.curr.state.program_counter.expr(),
        );
        let opcode = cb.query_cell();
        // cb.condition(1.expr() - is_out_of_range.expr(), |cb| {
        //     cb.opcode_lookup(opcode.expr(), 1.expr());
        // });

        // We do the responsible opcode check explicitly here because we're not using
        // the `SameContextGadget` for `END`.
        cb.require_equal(
            "Opcode should be END",
            opcode.expr(),
            OpcodeId::End.expr(),
        );

        // Call ends with STOP must be successful
        cb.call_context_lookup(false.expr(), None, CallContextFieldTag::IsSuccess, 1.expr());

        let is_to_end_tx = cb.next.execution_state_selector([ExecutionState::EndTx]);
        cb.require_equal(
            "Go to EndTx only when is_root",
            cb.curr.state.is_root.expr(),
            is_to_end_tx,
        );

        // When it's a root call
        cb.condition(cb.curr.state.is_root.expr(), |cb| {
            // Do step state transition
            cb.require_step_state_transition(StepStateTransition {
                call_id: Same,
                rw_counter: Delta(1.expr()),
                ..StepStateTransition::any()
            });
        });

        // // When it's an internal call
        // let restore_context = cb.condition(1.expr() - cb.curr.state.is_root.expr(), |cb| {
        //     RestoreContextGadget::construct(
        //         cb,
        //         true.expr(),
        //         0.expr(),
        //         0.expr(),
        //         0.expr(),
        //         0.expr(),
        //         0.expr(),
        //     )
        // });

        Self {
            code_length,
            is_out_of_range,
            opcode,
            // restore_context,
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
        let code = block
            .bytecodes
            .get(&call.code_hash)
            .expect("could not find current environment's bytecode");
        self.code_length.assign(
            region,
            offset,
            Value::known(F::from(code.bytes.len() as u64)),
        )?;

        self.is_out_of_range.assign(
            region,
            offset,
            F::from(code.bytes.len() as u64) - F::from(step.program_counter),
        )?;

        let opcode = step.opcode.unwrap();
        self.opcode
            .assign(region, offset, Value::known(F::from(opcode.as_u64())))?;

        // if !call.is_root {
        //     self.restore_context
        //         .assign(region, offset, block, call, step, 1)?;
        // }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::CircuitTestBuilder;
    use eth_types::{bytecode, Bytecode};

    use mock::TestContext;

    fn run_test(bytecode: Bytecode) {
        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        ).run()
    }

    #[test]
    fn test_end() {
        let code = bytecode! {
            // end is always injected by default
        };
        run_test(code);
    }
}
