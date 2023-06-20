use crate::{
    evm_circuit::{
        param::{N_BYTES_ACCOUNT_ADDRESS, N_BYTES_MEMORY_WORD_SIZE, N_BYTES_U64},
        step::ExecutionState,
        util::{
            common_gadget::{SameContextGadget, Word64ByteCapGadget},
            constraint_builder::{
                ConstrainBuilderCommon, EVMConstraintBuilder, ReversionInfo, StepStateTransition,
                Transition,
            },
            from_bytes,
            memory_gadget::{
                CommonMemoryAddressGadget, MemoryAddress64Gadget, MemoryCopierGasGadget,
                MemoryExpansionGadget,
            },
            not, select, CachedRegion, Cell, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{AccountFieldTag, CallContextFieldTag},
};
use bus_mapping::circuit_input_builder::CopyDataType;
use eth_types::{Address, evm_types::GasCost, Field, ToLittleEndian, ToScalar, ToU256};
use gadgets::util::Expr;
use halo2_proofs::{circuit::Value, plonk::Error};
use itertools::Itertools;

use super::ExecutionGadget;

#[derive(Clone, Debug)]
pub(crate) struct EvmExtCodeCopyGadget<F> {
    same_context: SameContextGadget<F>,
    external_address_word_offset: Cell<F>,
    external_address_word: Word<F>,
    memory_address: MemoryAddress64Gadget<F>,
    code_offset: Word64ByteCapGadget<F, N_BYTES_U64>,
    tx_id: Cell<F>,
    reversion_info: ReversionInfo<F>,
    is_warm: Cell<F>,
    code_hash: Cell<F>,
    code_size: Cell<F>,
    copy_rwc_inc: Cell<F>,
    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    memory_copier_gas: MemoryCopierGasGadget<F, { GasCost::COPY }>,
}

impl<F: Field> ExecutionGadget<F> for EvmExtCodeCopyGadget<F> {
    const NAME: &'static str = "EXTCODECOPY";

    const EXECUTION_STATE: ExecutionState = ExecutionState::EXTCODECOPY;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let external_address_word = cb.query_word_rlc();
        let external_address =
            from_bytes::expr(&external_address_word.cells[..N_BYTES_ACCOUNT_ADDRESS]);

        let external_address_word_offset = cb.query_cell();
        let code_size = cb.query_cell();

        let memory_length = cb.query_cell();
        let memory_offset = cb.query_cell_phase2();
        let code_offset = Word64ByteCapGadget::construct(cb, code_size.expr());

        cb.stack_pop(memory_length.expr());
        cb.stack_pop(code_offset.original_word());
        cb.stack_pop(memory_offset.expr());
        cb.stack_pop(external_address_word_offset.expr());

        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let mut reversion_info = cb.reversion_info_read(None);
        let is_warm = cb.query_bool();
        cb.account_access_list_write(
            tx_id.expr(),
            external_address.expr(),
            1.expr(),
            is_warm.expr(),
            Some(&mut reversion_info),
        );

        let code_hash = cb.query_cell_phase2();
        cb.account_read(
            external_address.expr(),
            AccountFieldTag::CodeHash,
            code_hash.expr(),
        );

        cb.memory_address_lookup(0.expr(), &external_address_word_offset, &external_address_word);

        // TODO: If external_address doesn't exist, we will get code_hash = 0.  With
        // this value, the bytecode_length lookup will not work, and the copy
        // from code_hash = 0 will not work. We should use EMPTY_HASH when
        // code_hash = 0.
        cb.bytecode_length(code_hash.expr(), code_size.expr());

        let memory_address = MemoryAddress64Gadget::construct(cb, memory_offset, memory_length);
        let memory_expansion = MemoryExpansionGadget::construct(cb, [memory_address.address()]);
        let memory_copier_gas = MemoryCopierGasGadget::construct(
            cb,
            memory_address.length(),
            memory_expansion.gas_cost(),
        );
        let gas_cost = memory_copier_gas.gas_cost()
            + select::expr(
            is_warm.expr(),
            GasCost::WARM_ACCESS.expr(),
            GasCost::COLD_ACCOUNT_ACCESS.expr(),
        );

        let copy_rwc_inc = cb.query_cell();
        cb.condition(memory_address.has_length(), |cb| {
            // Set source start to the minimun value of code offset and code size.
            let src_addr = select::expr(
                code_offset.lt_cap(),
                code_offset.valid_value(),
                code_size.expr(),
            );

            cb.copy_table_lookup(
                code_hash.expr(),
                CopyDataType::Bytecode.expr(),
                cb.curr.state.call_id.expr(),
                CopyDataType::Memory.expr(),
                src_addr,
                code_size.expr(),
                memory_address.offset(),
                memory_address.length(),
                0.expr(),
                copy_rwc_inc.expr(),
            );
        });
        cb.condition(not::expr(memory_address.has_length()), |cb| {
            cb.require_zero(
                "if no bytes to copy, copy table rwc inc == 0",
                copy_rwc_inc.expr(),
            );
        });

        let step_state_transition = StepStateTransition {
            rw_counter: Transition::Delta(cb.rw_counter_offset()),
            program_counter: Transition::Delta(1.expr()),
            stack_pointer: Transition::Delta(4.expr()),
            memory_word_size: Transition::To(memory_expansion.next_memory_word_size()),
            gas_left: Transition::Delta(-gas_cost),
            reversible_write_counter: Transition::Delta(1.expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            external_address_word_offset,
            external_address_word,
            memory_address,
            code_offset,
            tx_id,
            is_warm,
            reversion_info,
            code_hash,
            code_size,
            copy_rwc_inc,
            memory_expansion,
            memory_copier_gas,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        transaction: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let [external_address_offset, memory_offset, code_offset, memory_length] =
            [3, 2, 1, 0].map(|idx| block.rws[step.rw_indices[idx]].stack_value());

        let mut external_address = block.rws[step.rw_indices[8]]
            .address()
            .ok_or(Error::Synthesis)?
            .to_u256();

        self.external_address_word_offset.assign(region, offset, Value::known(F::from(external_address_offset.as_u64())))?;
        self.external_address_word
            .assign(region, offset, Some(external_address.to_le_bytes()))?;
        let memory_address =
            self.memory_address
                .assign(region, offset, memory_offset, memory_length)?;

        self.tx_id
            .assign(region, offset, Value::known(F::from(transaction.id as u64)))?;
        self.reversion_info.assign(
            region,
            offset,
            call.rw_counter_end_of_reversion,
            call.is_persistent,
        )?;

        let (_, is_warm) = block.rws[step.rw_indices[7]].tx_access_list_value_pair();
        self.is_warm
            .assign(region, offset, Value::known(F::from(is_warm as u64)))?;

        let code_hash = block.rws[step.rw_indices[8]].account_value_pair().0;
        self.code_hash
            .assign(region, offset, region.code_hash(code_hash))?;

        let code_size = if code_hash.is_zero() {
            0
        } else {
            block
                .bytecodes
                .get(&code_hash)
                .expect("could not find external bytecode")
                .bytes
                .len() as u64
        };
        self.code_size
            .assign(region, offset, Value::known(F::from(code_size)))?;

        self.code_offset
            .assign(region, offset, code_offset, F::from(code_size))?;

        self.copy_rwc_inc.assign(
            region,
            offset,
            Value::known(
                memory_length
                    .to_scalar()
                    .expect("unexpected U256 -> Scalar conversion failure"),
            ),
        )?;

        let (_, memory_expansion_gas_cost) = self.memory_expansion.assign(
            region,
            offset,
            step.memory_word_size(),
            [memory_address],
        )?;

        self.memory_copier_gas.assign(
            region,
            offset,
            memory_length.as_u64(),
            memory_expansion_gas_cost,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{evm_circuit::test::rand_bytes_array, test_util::CircuitTestBuilder};
    use bus_mapping::circuit_input_builder::CircuitsParams;
    use eth_types::{
        address, bytecode, bytecode_internal, geth_types::Account, Address, Bytecode, Bytes, ToWord, Word,
    };
    use lazy_static::lazy_static;
    use mock::TestContext;

    lazy_static! {
        static ref EXTERNAL_ADDRESS: Address =
            address!("0xaabbccddee000000000000000000000000000000");
    }

    fn test_ok(
        external_account: Option<Account>,
        memory_offset: u32,
        code_offset: u32,
        copy_size: u32,
        is_warm: bool,
    ) {
        let external_address = external_account
            .as_ref()
            .map(|a| a.address)
            .unwrap_or(*EXTERNAL_ADDRESS);

        let mut code = Bytecode::default();

        let address_offset = code.fill_default_global_data(external_address.as_bytes().to_vec());
        let memory_offset =code.alloc_default_global_data(32);

        if is_warm {
            bytecode_internal! {code,
                I32Const[address_offset]
                I32Const[0xff]
                EXTCODEHASH
            }
        }
        bytecode_internal! {code,
            I32Const[address_offset]
            I32Const[memory_offset]
            I32Const[code_offset]
            I32Const[copy_size]
            // #[start]
            EXTCODECOPY
        }

        let ctx = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x000000000000000000000000000000000000cafe"))
                    .code(code);
                accs[1]
                    .address(address!("0x0000000000000000000000000000000000000010"))
                    .balance(Word::from(1u64 << 20));
                accs[2].address(external_address);
                if let Some(external_account) = external_account {
                    accs[2]
                        .balance(external_account.balance)
                        .nonce(external_account.nonce)
                        .code(external_account.code);
                }
            },
            |mut txs, accs| {
                txs[0]
                    .to(accs[0].address)
                    .from(accs[1].address)
                    .gas(1_000_000.into());
            },
            |block, _tx| block.number(0x1111111),
        )
            .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx)
            .params(CircuitsParams {
                max_copy_rows: 1750,
                ..Default::default()
            })
            .run();
    }

    #[test]
    fn extcodecopy_empty_account() {
        test_ok(None, 0x14, 0x00, 0x36, true); // warm account
        test_ok(None, 0x14, 0x00, 0x36, false); // cold account
    }

    #[test]
    fn extcodecopy_nonempty_account() {
        test_ok(
            Some(Account {
                address: *EXTERNAL_ADDRESS,
                code: Bytes::from([10, 40]),
                ..Default::default()
            }),
            0x14,
            0x00,
            0x36,
            true,
        ); // warm account

        test_ok(
            Some(Account {
                address: *EXTERNAL_ADDRESS,
                code: Bytes::from([10, 40]),
                ..Default::default()
            }),
            0x14,
            0x00,
            0x36,
            false,
        ); // cold account
    }

    #[test]
    fn extcodecopy_largerthan256() {
        test_ok(
            Some(Account {
                address: *EXTERNAL_ADDRESS,
                code: Bytes::from(rand_bytes_array::<256>()),
                ..Default::default()
            }),
            0x14,
            0x00,
            0x36,
            true,
        );
        test_ok(
            Some(Account {
                address: *EXTERNAL_ADDRESS,
                code: Bytes::from(rand_bytes_array::<256>()),
                ..Default::default()
            }),
            0x14,
            0x00,
            0x36,
            false,
        );
    }

    #[test]
    fn extcodecopy_outofbound() {
        test_ok(
            Some(Account {
                address: *EXTERNAL_ADDRESS,
                code: Bytes::from(rand_bytes_array::<64>()),
                ..Default::default()
            }),
            0x20,
            0x00,
            0x104,
            true,
        );
        test_ok(
            Some(Account {
                address: *EXTERNAL_ADDRESS,
                code: Bytes::from(rand_bytes_array::<64>()),
                ..Default::default()
            }),
            0x20,
            0x00,
            0x104,
            false,
        );
    }

    #[test]
    fn extcodecopy_code_offset_overflow() {
        test_ok(
            Some(Account {
                address: *EXTERNAL_ADDRESS,
                code: Bytes::from(rand_bytes_array::<256>()),
                ..Default::default()
            }),
            u32::MAX,
            0x00,
            0x36,
            true,
        );
        test_ok(
            Some(Account {
                address: *EXTERNAL_ADDRESS,
                code: Bytes::from(rand_bytes_array::<256>()),
                ..Default::default()
            }),
            u32::MAX,
            0x00,
            0x36,
            false,
        );
    }

    #[test]
    fn extcodecopy_overflow_memory_offset_and_zero_length() {
        test_ok(
            Some(Account {
                address: *EXTERNAL_ADDRESS,
                code: Bytes::from(rand_bytes_array::<256>()),
                ..Default::default()
            }),
            0x20,
            u32::MAX,
            0,
            true,
        );
        test_ok(
            Some(Account {
                address: *EXTERNAL_ADDRESS,
                code: Bytes::from(rand_bytes_array::<256>()),
                ..Default::default()
            }),
            0x20,
            u32::MAX,
            0,
            true,
        );
    }
}
