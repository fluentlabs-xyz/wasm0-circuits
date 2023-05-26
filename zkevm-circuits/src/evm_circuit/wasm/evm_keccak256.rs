use bus_mapping::{circuit_input_builder::CopyDataType, evm::OpcodeId};
use eth_types::{evm_types::GasCost, Field, ToLittleEndian, ToScalar};
use gadgets::util::{not, Expr};
use halo2_proofs::{circuit::Value, plonk::Error};
use itertools::Itertools;

use crate::evm_circuit::{
    param::N_BYTES_MEMORY_WORD_SIZE,
    step::ExecutionState,
    util::{
        common_gadget::SameContextGadget,
        constraint_builder::{
            ConstrainBuilderCommon, EVMConstraintBuilder, StepStateTransition, Transition,
        },
        memory_gadget::{
            CommonMemoryAddressGadget, MemoryCopierGasGadget,
            MemoryExpansionGadget,
        },
        rlc, CachedRegion, Cell, Word,
    },
    witness::{Block, Call, ExecStep, Transaction},
};
use crate::evm_circuit::util::memory_gadget::MemoryAddress64Gadget;

use super::ExecutionGadget;

#[derive(Clone, Debug)]
pub(crate) struct EvmKeccak256Gadget<F> {
    same_context: SameContextGadget<F>,
    memory_address: MemoryAddress64Gadget<F>,
    sha3_rlc: Word<F>,
    copy_rwc_inc: Cell<F>,
    rlc_acc: Cell<F>,
    dest_offset: Cell<F>,
    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    memory_copier_gas: MemoryCopierGasGadget<F, { GasCost::COPY_SHA3 }>,
}

impl<F: Field> ExecutionGadget<F> for EvmKeccak256Gadget<F> {
    const EXECUTION_STATE: ExecutionState = ExecutionState::SHA3;

    const NAME: &'static str = "SHA3";

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let offset = cb.query_cell_phase2();
        let size = cb.query_cell();
        let sha3_rlc = cb.query_word_rlc();
        let dest_offset = cb.query_cell();

        cb.stack_pop(dest_offset.expr());
        cb.stack_pop(size.expr());
        cb.stack_pop(offset.expr());

        cb.memory_rlc_lookup(1.expr(), &dest_offset, &sha3_rlc);

        let memory_address = MemoryAddress64Gadget::construct(cb, offset, size);

        let copy_rwc_inc = cb.query_cell();
        let rlc_acc = cb.query_cell_phase2();

        cb.condition(memory_address.has_length(), |cb| {
            cb.copy_table_lookup(
                cb.curr.state.call_id.expr(),
                CopyDataType::Memory.expr(),
                cb.curr.state.call_id.expr(),
                CopyDataType::RlcAcc.expr(),
                memory_address.offset(),
                memory_address.address(),
                0.expr(), // dst_addr for CopyDataType::RlcAcc is 0.
                memory_address.length(),
                rlc_acc.expr(),
                copy_rwc_inc.expr(),
            );
        });

        cb.condition(not::expr(memory_address.has_length()), |cb| {
            cb.require_zero("copy_rwc_inc == 0 for size = 0", copy_rwc_inc.expr());
            cb.require_zero("rlc_acc == 0 for size = 0", rlc_acc.expr());
        });
        cb.keccak_table_lookup(rlc_acc.expr(), memory_address.length(), sha3_rlc.expr());

        let memory_expansion = MemoryExpansionGadget::construct(cb, [memory_address.address()]);
        let memory_copier_gas = MemoryCopierGasGadget::construct(
            cb,
            memory_address.length(),
            memory_expansion.gas_cost(),
        );

        let step_state_transition = StepStateTransition {
            rw_counter: Transition::Delta(cb.rw_counter_offset()),
            program_counter: Transition::Delta(1.expr()),
            stack_pointer: Transition::Delta(1.expr()),
            memory_word_size: Transition::To(memory_expansion.next_memory_word_size()),
            gas_left: Transition::Delta(
                -(OpcodeId::SHA3.constant_gas_cost().expr() + memory_copier_gas.gas_cost()),
            ),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            memory_address,
            sha3_rlc,
            copy_rwc_inc,
            rlc_acc,
            dest_offset,
            memory_expansion,
            memory_copier_gas,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _tx: &Transaction,
        _call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let [dest_offset, size, memory_offset] =
            [step.rw_indices[0], step.rw_indices[1], step.rw_indices[2]]
                .map(|idx| block.rws[idx].stack_value());
        let sha3_bytes = (3..35).map(|i| block.rws[step.rw_indices[i]].memory_value()).collect_vec();
        let sha3_word = eth_types::Word::from_big_endian(sha3_bytes.as_slice());
        let memory_address = self
            .memory_address
            .assign(region, offset, memory_offset, size)?;
        self.dest_offset.assign(region, offset, Value::known(F::from(dest_offset.as_u64())))?;
        self.sha3_rlc
            .assign(region, offset, Some(sha3_word.to_le_bytes()))?;

        self.copy_rwc_inc.assign(
            region,
            offset,
            Value::known(
                size.to_scalar()
                    .expect("unexpected U256 -> Scalar conversion failure"),
            ),
        )?;

        let values: Vec<u8> = (35..35 + (size.low_u64() as usize))
            .map(|i| block.rws[step.rw_indices[i]].memory_value())
            .collect();

        let rlc_acc = region
            .challenges()
            .keccak_input()
            .map(|randomness| rlc::value(values.iter().rev(), randomness));
        self.rlc_acc.assign(region, offset, rlc_acc)?;

        // Memory expansion and dynamic gas cost for reading it.
        let (_, memory_expansion_gas_cost) = self.memory_expansion.assign(
            region,
            offset,
            step.memory_word_size(),
            [memory_address],
        )?;
        self.memory_copier_gas
            .assign(region, offset, size.as_u64(), memory_expansion_gas_cost)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::test_util::CircuitTestBuilder;
    use bus_mapping::{
        circuit_input_builder::CircuitsParams,
        evm::{gen_sha3_code, MemoryKind},
    };
    use eth_types::{bytecode, Bytecode, bytecode_internal, Word};
    use mock::TestContext;

    fn test_ok(offset: usize, size: usize, mem_kind: MemoryKind) {
        let (code, _) = gen_sha3_code(offset, size, mem_kind);
        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(code).unwrap(),
        )
            .params(CircuitsParams {
                max_rws: 5500,
                max_copy_rows: 3000,
                ..Default::default()
            })
            .run();
    }

    #[test]
    fn sha3_gadget_zero_length() {
        test_ok(0x20+0x20, 0x00, MemoryKind::MoreThanSize);
    }

    #[test]
    fn sha3_gadget_simple() {
        // we store result in the first 32 bytes
        test_ok(0x00+0x20, 0x08, MemoryKind::Empty);
        test_ok(0x10+0x20, 0x10, MemoryKind::LessThanSize);
        test_ok(0x24+0x20, 0x16, MemoryKind::EqualToSize);
        test_ok(0x32+0x20, 0x78, MemoryKind::MoreThanSize);
    }

    #[test]
    fn sha3_gadget_large() {
        test_ok(0x101+0x20, 0x202, MemoryKind::Empty);
        test_ok(0x202+0x20, 0x303, MemoryKind::LessThanSize);
        test_ok(0x303+0x20, 0x404, MemoryKind::EqualToSize);
        test_ok(0x404+0x20, 0x505, MemoryKind::MoreThanSize);
    }

    #[test]
    #[ignore]
    fn sha3_gadget_overflow_offset_and_zero_size() {
        let mut bytecode = Bytecode::default();
        let dest_offset = bytecode.alloc_default_global_data(32);
        bytecode_internal! {bytecode,
            I32Const[0]
            I32Const[u32::MAX]
            I32Const[dest_offset]
            SHA3
        }
        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        ).run();
    }
}
