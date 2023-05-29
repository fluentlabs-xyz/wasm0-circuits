use halo2_proofs::{circuit::Value, plonk::Error};

use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToLittleEndian, ToScalar, ToU256};
use gadgets::util::{and, not};

use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_U64,
        step::ExecutionState,
        util::{
            CachedRegion,
            Cell,
            common_gadget::{SameContextGadget},
            constraint_builder::{
                EVMConstraintBuilder, StepStateTransition,
                Transition::Delta,
            }, math_gadget::LtGadget, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::BlockContextFieldTag,
    util::Expr,
    witness::NUM_PREV_BLOCK_ALLOWED,
};
use crate::evm_circuit::util::common_gadget::WordByteCapGadget;

#[derive(Clone, Debug)]
pub(crate) struct EvmBlockHashGadget<F> {
    same_context: SameContextGadget<F>,
    block_number: WordByteCapGadget<F, N_BYTES_U64>,
    current_block_number: Cell<F>,
    block_hash: Word<F>,
    diff_lt: LtGadget<F, N_BYTES_U64>,
    dest_offset: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for EvmBlockHashGadget<F> {
    const NAME: &'static str = "BLOCKHASH";

    const EXECUTION_STATE: ExecutionState = ExecutionState::BLOCKHASH;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let current_block_number = cb.query_cell();

        let dest_offset = cb.query_cell();
        cb.stack_pop(dest_offset.expr());
        let block_number = WordByteCapGadget::construct(cb, current_block_number.expr());
        cb.stack_pop(block_number.original_word());

        // FIXME
        // cb.block_lookup(
        //    BlockContextFieldTag::Number.expr(),
        //    None,
        //    current_block_number.expr(),
        //);

        let block_hash = cb.query_word_rlc();

        let diff_lt = LtGadget::construct(
            cb,
            current_block_number.expr(),
            (NUM_PREV_BLOCK_ALLOWED + 1).expr() + block_number.valid_value(),
        );

        let is_valid = and::expr([block_number.lt_cap(), diff_lt.expr()]);

        cb.condition(is_valid.expr(), |cb| {
            cb.block_lookup(
                BlockContextFieldTag::BlockHash.expr(),
                block_number.valid_value(),
                block_hash.expr(),
            );
        });

        cb.condition(not::expr(is_valid), |cb| {
            cb.require_zero(
                "Invalid block number for block hash lookup",
                block_hash.expr(),
            );
        });

        cb.memory_rlc_lookup(1.expr(), &dest_offset, &block_hash);

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(34.expr()),
            program_counter: Delta(1.expr()),
            gas_left: Delta(-OpcodeId::BLOCKHASH.constant_gas_cost().expr()),
            ..Default::default()
        };

        let opcode = cb.query_cell();
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);
        Self {
            same_context,
            block_number,
            current_block_number,
            block_hash,
            diff_lt,
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

        let current_block_number = block.context.ctxs[&tx.block_number].number;
        let current_block_number = current_block_number
            .to_scalar()
            .expect("unexpected U256 -> Scalar conversion failure");

        let dest_offset = block.rws[step.rw_indices[0]].stack_value();
        let block_number = block.rws[step.rw_indices[1]].stack_value();
        self.block_number
            .assign(region, offset, block_number.to_u256(), current_block_number)?;
        self.dest_offset
            .assign(region, offset, Value::<F>::known(dest_offset.to_scalar().unwrap()))?;

        self.current_block_number
            .assign(region, offset, Value::known(current_block_number))?;

        let blockhash_bytes = (2..34).map(|i| block.rws[step.rw_indices[i]].memory_value()).collect::<Vec<_>>();
        let blockhash = eth_types::Word::from_big_endian(blockhash_bytes.as_slice());
        self.block_hash.assign(
            region,
            offset,
            Some(blockhash.to_le_bytes())
        )?;

        // Block number overflow should be constrained by WordByteCapGadget.
        let block_number: F = block_number
            .low_u64()
            .to_scalar()
            .expect("unexpected U256 -> Scalar conversion failure");
        self.diff_lt.assign(
            region,
            offset,
            current_block_number,
            block_number + F::from(NUM_PREV_BLOCK_ALLOWED + 1),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use eth_types::{Bytecode, bytecode_internal, U256};
    use mock::test_ctx::{helpers::*, TestContext};

    use crate::test_util::CircuitTestBuilder;

    fn test_ok(block_number: u32, current_block_number: u64) {
        let mut code = Bytecode::default();
        let dest = code.alloc_default_global_data(32);
        bytecode_internal! {code,
            I32Const[block_number]
            I32Const[dest]
            BLOCKHASH
        }

        // simple U256 values for history hashes
        let mut history_hashes = Vec::new();
        let range = if current_block_number < 256 {
            0..current_block_number
        } else {
            current_block_number - 256..current_block_number
        };
        for i in range {
            history_hashes.push(U256::from(0xbeefcafeu64 + i));
        }
        let ctx = TestContext::<2, 1>::new(
            Some(history_hashes),
            account_0_code_account_1_no_code(code),
            tx_from_1_to_0,
            |block, _tx| block.number(current_block_number),
        ).unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run()
    }

    #[test]
    fn blockhash_gadget_simple() {
        #[cfg(not(feature = "scroll"))]
        {
            test_ok(0.into(), 5);
            test_ok(1.into(), 5);
            test_ok(2.into(), 5);
            test_ok(3.into(), 5);
        }
        test_ok(4, 5);
        test_ok(5, 5);
        test_ok(6, 5);
    }

    #[test]
    fn blockhash_gadget_large() {
        test_ok(0xcafe - 257, 0xcafeu64);
        #[cfg(not(feature = "scroll"))]
        test_ok((0xcafe - 256).into(), 0xcafeu64);
        test_ok(0xcafe - 1, 0xcafeu64);
        test_ok(0xcafe, 0xcafeu64);
        test_ok(0xcafe + 1, 0xcafeu64);
    }

    #[test]
    fn blockhash_gadget_block_number_overflow() {
        test_ok(u32::MAX, 0xcafeu64);
    }
}
