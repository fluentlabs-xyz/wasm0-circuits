use crate::{
    evm_circuit::{
        param::N_BYTES_WORD,
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{StepStateTransition, Transition::Delta},
            CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{AccountFieldTag, CallContextFieldTag},
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToLittleEndian, ToScalar};
use halo2_proofs::{circuit::Value, plonk::Error};
use halo2_proofs::plonk::Error::Synthesis;
use crate::evm_circuit::util::{RandomLinearCombination};
use crate::evm_circuit::util::constraint_builder::EVMConstraintBuilder;

#[derive(Clone, Debug)]
pub(crate) struct EvmSelfBalanceGadget<F> {
    same_context: SameContextGadget<F>,
    callee_address: Cell<F>,
    self_balance: RandomLinearCombination<F, N_BYTES_WORD>,
    dest_offset: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for EvmSelfBalanceGadget<F> {
    const NAME: &'static str = "SELFBALANCE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::SELFBALANCE;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let callee_address = cb.call_context(None, CallContextFieldTag::CalleeAddress);
        let self_balance = cb.query_word_rlc();
        let dest_offset = cb.query_cell();

        cb.account_read(
            callee_address.expr(),
            AccountFieldTag::Balance,
            self_balance.expr(),
        );

        cb.stack_pop(dest_offset.expr());
        cb.memory_rlc_lookup(true.expr(), &dest_offset, &self_balance);

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
            Some(self_balance.to_le_bytes()),
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
    fn selfbalance_gadget_test() {
        let res_mem_address = 0x7f;
        let bytecode = bytecode! {
            I32Const[res_mem_address]
            SELFBALANCE
        };

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run();
    }
}
