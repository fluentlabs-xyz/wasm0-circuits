use halo2_proofs::circuit::Value;
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
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToLittleEndian, ToScalar};
use halo2_proofs::plonk::Error;
use halo2_proofs::plonk::Error::Synthesis;
use crate::evm_circuit::util::{RandomLinearCombination};
use crate::table::{BlockContextFieldTag, CallContextFieldTag};

#[derive(Clone, Debug)]
pub(crate) struct ChainIdGadget<F> {
    same_context: SameContextGadget<F>,
    chain_id: RandomLinearCombination<F, N_BYTES_WORD>,
    dest_offset: Cell<F>
}

impl<F: Field> ExecutionGadget<F> for ChainIdGadget<F> {
    const NAME: &'static str = "CHAINID";

    const EXECUTION_STATE: ExecutionState = ExecutionState::CHAINID;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let chain_id = cb.query_word_rlc();
        let dest_offset = cb.query_cell();

        cb.stack_pop(dest_offset.expr());

        // Lookup rw_table -> call_context with tx origin address
        cb.block_lookup(
            BlockContextFieldTag::ChainId.expr(),
            None, // None because unrelated to calldata
            chain_id.expr(),
        );
        cb.memory_rlc_lookup(true.expr(), &dest_offset, &chain_id);

        // State transition
        let opcode = cb.query_cell();
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(33.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
            gas_left: Delta(-OpcodeId::CHAINID.constant_gas_cost().expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            chain_id,
            dest_offset,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        tx: &Transaction,
        _: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let chain_id = block.eth_block.transactions[0].chain_id.unwrap();
        let dest_offset = block.rws[step.rw_indices[0]].stack_value();

        self.chain_id.assign(
            region,
            offset,
            Some(
                chain_id.to_le_bytes()
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
    use mock::test_ctx::TestContext;

    #[test]
    fn chainid_gadget_test() {
        let res_mem_address = 0x7f;
        let bytecode = bytecode! {
            I32Const[res_mem_address]
            CHAINID
        };

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run();
    }
}
