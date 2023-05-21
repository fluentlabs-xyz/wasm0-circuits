use halo2_proofs::circuit::Value;
use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{StepStateTransition, Transition::Delta},
            CachedRegion,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::CallContextFieldTag,
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToLittleEndian, ToScalar};
use halo2_proofs::plonk::Error;
use halo2_proofs::plonk::Error::Synthesis;
use crate::evm_circuit::util::{Cell, RandomLinearCombination};
use crate::evm_circuit::util::constraint_builder::EVMConstraintBuilder;

#[derive(Clone, Debug)]
pub(crate) struct EvmCallValueGadget<F> {
    same_context: SameContextGadget<F>,
    // Value in rw_table->stack_op and call_context->call_value are both RLC
    // encoded, so no need to decode.
    call_value: RandomLinearCombination<F, 32>,
    dest_offset: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for EvmCallValueGadget<F> {
    const NAME: &'static str = "CALLVALUE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::CALLVALUE;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let call_value = cb.query_word_rlc();
        let dest_offset = cb.query_cell();

        // Lookup rw_table -> call_context with call value
        cb.call_context_lookup(
            false.expr(),
            None, // cb.curr.state.call_id
            CallContextFieldTag::Value,
            call_value.expr(),
        );

        // Push the value to the stack
        cb.stack_pop(dest_offset.expr());

        // State transition
        let opcode = cb.query_cell();
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(34.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
            gas_left: Delta(-OpcodeId::CALLVALUE.constant_gas_cost().expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            call_value,
            dest_offset,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction,
        _: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let call_value = block.rws[step.rw_indices[0]].call_context_value();
        let dest_offset = block.rws[step.rw_indices[1]].stack_value();

        self.call_value.assign(
            region,
            offset,
            Some(
                call_value.to_le_bytes()
                    .try_into()
                    .unwrap(),
            ),
        )?;

        self.dest_offset.assign(
            region,
            offset,
            Value::<F>::known(dest_offset.to_scalar().ok_or(Synthesis)?),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::CircuitTestBuilder;
    use eth_types::bytecode;
    use mock::TestContext;

    #[test]
    fn callvalue_gadget_test() {
        let res_mem_address = 0x7f;
        let bytecode = bytecode! {
            I32Const[res_mem_address]
            CALLVALUE
        };

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run();
    }
}
