use crate::{
    evm_circuit::{
        param::N_BYTES_WORD,
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{AccountFieldTag, CallContextFieldTag},
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToLittleEndian, ToScalar, ToU256};
use halo2_proofs::{circuit::Value, plonk::Error};
use halo2_proofs::plonk::Error::Synthesis;
use crate::evm_circuit::util::{RandomLinearCombination};

#[derive(Clone, Debug)]
pub(crate) struct SelfbalanceGadget<F> {
    same_context: SameContextGadget<F>,
    callee_address: Cell<F>,
    phase2_self_balance: Cell<F>,
    dest_offset: Cell<F>,
    self_balance: RandomLinearCombination<F, N_BYTES_WORD>,
    // self_balance: RandomLinearCombination<F, N_BYTES_WORD>,
}

impl<F: Field> ExecutionGadget<F> for SelfbalanceGadget<F> {
    const NAME: &'static str = "SELFBALANCE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::SELFBALANCE;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let callee_address = cb.call_context(None, CallContextFieldTag::CalleeAddress);
        let self_balance = cb.query_word_rlc::<N_BYTES_WORD>();
        let dest_offset = cb.query_cell();

        let phase2_self_balance = cb.query_cell_phase2();
        cb.account_read(
            callee_address.expr(),
            AccountFieldTag::Balance,
            phase2_self_balance.expr(),
        );

        cb.stack_pop(dest_offset.expr());

        for idx in 0..32 {
            cb.memory_lookup(
                true.expr(),
                dest_offset.expr() + idx.expr(),
                self_balance.cells[32 - 1 - idx].expr(),
                None,
            );
        }

        let opcode = cb.query_cell();
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(34.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
            gas_left: Delta(-OpcodeId::SELFBALANCE.constant_gas_cost().expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            self_balance,
            phase2_self_balance,
            callee_address,
            dest_offset,
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
        self.same_context.assign_exec_step(region, offset, step)?;

        self.callee_address.assign(
            region,
            offset,
            Value::known(
                call.callee_address
                    .to_scalar()
                    .expect("unexpected Address -> Scalar conversion failure"),
            ),
        )?;

        let (_, self_balance) = block.rws[step.rw_indices[1]].account_value_pair();
        let dest_offset = block.rws[step.rw_indices[2]].stack_value();
        self.self_balance.assign(
            region,
            offset,
            Some(
                self_balance.to_le_bytes()
                    .try_into()
                    .unwrap(),
            ),
        )?;
        self.dest_offset.assign(
            region,
            offset,
            Value::<F>::known(dest_offset.to_scalar().ok_or(Synthesis)?),
        )?;
        self.phase2_self_balance
            .assign(region, offset, region.word_rlc(self_balance.to_u256()))?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::CircuitTestBuilder;
    use eth_types::bytecode;
    use mock::TestContext;

    #[test]
    fn selfbalance_gadget_test() {
        let res_mem_address = 0x7f;
        let bytecode = bytecode! {
            I32Const[res_mem_address]
            SELFBALANCE
            // STOP
        };

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run();
    }
}
