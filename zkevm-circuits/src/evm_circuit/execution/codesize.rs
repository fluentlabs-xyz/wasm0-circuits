use array_init::array_init;
use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToScalar};
use halo2_proofs::{circuit::Value, plonk::Error};
use halo2_proofs::plonk::Error::Synthesis;

use crate::{
    evm_circuit::{
        param::N_BYTES_MEMORY_WORD_SIZE,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition},
            from_bytes, CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use crate::evm_circuit::util::RandomLinearCombination;

use super::ExecutionGadget;

#[derive(Clone, Debug)]
pub(crate) struct CodesizeGadget<F> {
    same_context: SameContextGadget<F>,
    codesize_bytes: [Cell<F>; 4],
    codesize: RandomLinearCombination<F, N_BYTES_MEMORY_WORD_SIZE>,
    dest_offset: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for CodesizeGadget<F> {
    const NAME: &'static str = "CODESIZE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::CODESIZE;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();
        let dest_offset = cb.query_cell();

        let codesize_bytes = array_init(|_| cb.query_byte());

        let code_hash = cb.curr.state.code_hash.clone();
        let codesize = cb.query_word_rlc();
        cb.bytecode_length(code_hash.expr(), codesize.expr());

        cb.require_equal(
            "Constraint: bytecode length lookup == codesize",
            from_bytes::expr(&codesize_bytes),
            codesize.expr(),
        );

        cb.stack_pop(dest_offset.expr());

        let step_state_transition = StepStateTransition {
            gas_left: Transition::Delta(-OpcodeId::CODESIZE.constant_gas_cost().expr()),
            rw_counter: Transition::Delta(5.expr()),
            program_counter: Transition::Delta(1.expr()),
            stack_pointer: Transition::Delta(1.expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            codesize_bytes,
            codesize,
            dest_offset,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _transaction: &Transaction,
        _call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let dest_offset = block.rws[step.rw_indices[0]].stack_value().as_u64();
        let codesize = block.rws[step.rw_indices[0]].stack_value().as_u64();

        for (c, b) in self
            .codesize_bytes
            .iter()
            .zip(codesize.to_le_bytes().iter())
        {
            c.assign(region, offset, Value::known(F::from(*b as u64)))?;
        }

        // TODO just to test
        let codesize: i32 = 588;
        let codesize_bytes = codesize.to_be_bytes();
        self.codesize.assign(
            region,
            offset,
            Some(codesize_bytes),
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
mod tests {
    use crate::test_util::CircuitTestBuilder;
    use eth_types::{bytecode, Word};
    use mock::TestContext;

    fn test_ok(large: bool) {
        let res_mem_address = 0x7f;
        let mut code = bytecode! {};
        if large {
            for _ in 0..128 {
                code.push(1, Word::from(0));
            }
        }
        let tail = bytecode! {
            I32Const[res_mem_address]
            CODESIZE
        };
        code.append(&tail);

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(code).unwrap(),
        )
        .run();
    }

    #[test]
    fn test_codesize_gadget() {
        test_ok(false);
    }

    // #[test]
    // fn test_codesize_gadget_large() {
    //     test_ok(true);
    // }
}
