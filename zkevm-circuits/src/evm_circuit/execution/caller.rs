use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::Error;
use halo2_proofs::plonk::Error::Synthesis;

use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToLittleEndian, ToScalar};

use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_ACCOUNT_ADDRESS,
        step::ExecutionState,
        util::{
            CachedRegion,
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta}, from_bytes, RandomLinearCombination,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::CallContextFieldTag,
    util::Expr,
};
use crate::evm_circuit::util::Cell;

#[derive(Clone, Debug)]
pub(crate) struct CallerGadget<F> {
    same_context: SameContextGadget<F>,
    // Using RLC to match against rw_table->stack_op value
    caller_address: RandomLinearCombination<F, N_BYTES_ACCOUNT_ADDRESS>,
    dest_offset: Cell<F>,
}

static mut CALLER_GADGET_CALL_COUNT: u32 = 0;

impl<F: Field> ExecutionGadget<F> for CallerGadget<F> {
    const NAME: &'static str = "CALLER";

    const EXECUTION_STATE: ExecutionState = ExecutionState::CALLER;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let caller_address = cb.query_word_rlc();
        let dest_offset = cb.query_cell();

        cb.call_context_lookup(
            false.expr(),
            None, // cb.curr.state.call_id,
            CallContextFieldTag::CallerAddress,
            from_bytes::expr(&caller_address.cells),
        );

        // Push the value to the stack
        cb.stack_pop(dest_offset.expr());
        cb.memory_rlc_lookup(1.expr(), &dest_offset, &caller_address);

        // State transition
        let opcode = cb.query_cell();
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(22.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
            gas_left: Delta(-OpcodeId::CALLER.constant_gas_cost().expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            caller_address,
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

        let caller_address = block.rws[step.rw_indices[0]].call_context_value();
        let dest_offset = block.rws[step.rw_indices[1]].stack_value();

        self.caller_address.assign(
            region,
            offset,
            Some(caller_address.to_le_bytes()[0..N_BYTES_ACCOUNT_ADDRESS].try_into().unwrap()),
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
    use eth_types::bytecode;
    use mock::TestContext;

    use crate::test_util::CircuitTestBuilder;

    #[test]
    fn caller_gadget_test() {
        let res_mem_address = 0x7f;
        let bytecode = bytecode! {
            I32Const[res_mem_address]
            CALLER
        };

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        ).run();
    }
}
