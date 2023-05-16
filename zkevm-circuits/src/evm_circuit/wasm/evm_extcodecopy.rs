use halo2_proofs::{circuit::Value, plonk::Error};

use bus_mapping::circuit_input_builder::CopyDataType;
use eth_types::{evm_types::GasCost, Field, ToLittleEndian, ToScalar};
use gadgets::util::Expr;

use crate::{
    evm_circuit::{
        param::N_BYTES_ACCOUNT_ADDRESS,
        param::N_BYTES_MEMORY_ADDRESS,
        step::ExecutionState,
        util::{
            CachedRegion,
            Cell,
            common_gadget::SameContextGadget,
            constraint_builder::{
                ConstraintBuilder, ReversionInfo, StepStateTransition, Transition,
            },
            from_bytes, memory_gadget::{MemoryAddressGadget, MemoryCopierGasGadget}, MemoryAddress, not, select,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{AccountFieldTag, CallContextFieldTag},
};
use crate::evm_circuit::util::RandomLinearCombination;
use crate::table::RwTableTag;

use super::ExecutionGadget;

#[derive(Clone, Debug)]
pub(crate) struct EvmExtCodeCopyGadget<F> {
    same_context: SameContextGadget<F>,
    // external_address_word: Word<F>,
    external_address_word: RandomLinearCombination<F, N_BYTES_ACCOUNT_ADDRESS>,
    external_address_offset: Cell<F>,
    dst_memory_addr: MemoryAddressGadget<F>,
    code_offset: MemoryAddress<F>,
    tx_id: Cell<F>,
    reversion_info: ReversionInfo<F>,
    is_warm: Cell<F>,
    code_hash: Cell<F>,
    code_size: Cell<F>,
    copy_rwc_inc: Cell<F>,
    // memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
    memory_copier_gas: MemoryCopierGasGadget<F, { GasCost::COPY }>,
}

impl<F: Field> ExecutionGadget<F> for EvmExtCodeCopyGadget<F> {
    const NAME: &'static str = "EXTCODECOPY";

    const EXECUTION_STATE: ExecutionState = ExecutionState::EXTCODECOPY;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let external_address_word = cb.query_word_rlc();
        let external_address =
            from_bytes::expr(&external_address_word.cells[..N_BYTES_ACCOUNT_ADDRESS]);

        let copy_size = cb.query_word_rlc();
        let code_offset = cb.query_word_rlc();
        let dst_memory_offset = cb.query_cell_phase2();
        let external_address_offset = cb.query_cell();

        cb.stack_pop(copy_size.expr());
        cb.stack_pop(code_offset.expr());
        cb.stack_pop(dst_memory_offset.expr());
        cb.stack_pop(external_address_offset.expr());
        // cb.memory_rlc_lookup(false.expr(), &external_address_offset, &external_address_word);

        let memory_address_gadget = MemoryAddressGadget::construct(cb, dst_memory_offset, copy_size);

        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let mut reversion_info = cb.reversion_info_read(None);
        let is_warm = cb.query_bool();
        cb.account_access_list_write(
            tx_id.expr(),
            external_address.clone(),
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
        let code_size = cb.query_cell();
        // TODO: If external_address doesn't exist, we will get code_hash = 0.  With
        // this value, the bytecode_length lookup will not work, and the copy
        // from code_hash = 0 will not work. We should use EMPTY_HASH when
        // code_hash = 0.
        cb.bytecode_length(code_hash.expr(), code_size.expr());

        // let memory_expansion = MemoryExpansionGadget::construct(cb, [memory_address.address()]);
        let memory_copier_gas = MemoryCopierGasGadget::construct(
            cb,
            memory_address_gadget.length(),
            0.expr()/*memory_expansion.gas_cost()*/,
        );
        let gas_cost = memory_copier_gas.gas_cost()
            + select::expr(
            is_warm.expr(),
            GasCost::WARM_ACCESS.expr(),
            GasCost::COLD_ACCOUNT_ACCESS.expr(),
        );

        let copy_rwc_inc = cb.query_cell();
        cb.condition(memory_address_gadget.has_length(), |cb| {
            // TODO problem here
            cb.copy_table_lookup(
                code_hash.expr(),
                CopyDataType::Bytecode.expr(),
                cb.curr.state.call_id.expr(),
                CopyDataType::Memory.expr(),
                from_bytes::expr(&code_offset.cells),
                code_size.expr(),
                memory_address_gadget.offset(),
                memory_address_gadget.length(),
                0.expr(),
                copy_rwc_inc.expr(),
            );
        });
        cb.condition(not::expr(memory_address_gadget.has_length()), |cb| {
            cb.require_zero(
                "if no bytes to copy, copy table rwc inc == 0",
                copy_rwc_inc.expr(),
            );
        });
        // cb.memory_rlc_lookup(false.expr(), &external_address_offset, &external_address_word);

        let step_state_transition = StepStateTransition {
            rw_counter: Transition::Delta(cb.rw_counter_offset()),
            program_counter: Transition::Delta(1.expr()),
            stack_pointer: Transition::Delta(4.expr()),
            // memory_word_size: Transition::To(memory_expansion.next_memory_word_size()),
            gas_left: Transition::Delta(-gas_cost),
            reversible_write_counter: Transition::Delta(1.expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            external_address_word,
            external_address_offset,
            dst_memory_addr: memory_address_gadget,
            code_offset,
            tx_id,
            is_warm,
            reversion_info,
            code_hash,
            code_size,
            copy_rwc_inc,
            // memory_expansion,
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

        // let [external_address, memory_offset, data_offset, memory_length] =
        let [
        copy_size,
        code_offset,
        dest_offset,
        external_address_offset,
        ] = [0, 1, 2, 3].map(|idx| block.rws[step.rw_indices[idx]].stack_value());
        let address_rw_index = 9;
        let external_address = {
            let address_rw_tup_vec: Vec<(RwTableTag, usize)> = step.rw_indices[address_rw_index..(address_rw_index + N_BYTES_ACCOUNT_ADDRESS)].to_vec();
            let address_bytes_vec: Vec<u8> = address_rw_tup_vec
                .iter()
                .map(|&b| block.rws[b].memory_value())
                .collect();
            eth_types::Word::from_big_endian(address_bytes_vec.as_slice())
        };
        let external_address_le_bytes: [u8; N_BYTES_ACCOUNT_ADDRESS] = external_address.to_le_bytes()
            .as_slice()[..N_BYTES_ACCOUNT_ADDRESS].try_into().unwrap();
        self.external_address_word
            .assign(region, offset, Some(external_address_le_bytes))?;
        self.external_address_offset
            .assign(region, offset, Value::<F>::known(external_address_offset.to_scalar().unwrap()))?;
        let _memory_address = self.dst_memory_addr.assign(region, offset, dest_offset, copy_size)?;
        self.code_offset.assign(
            region,
            offset,
            Some(
                code_offset.to_le_bytes()[..N_BYTES_MEMORY_ADDRESS]
                    .try_into()
                    .unwrap(),
            ),
        )?;

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
            .assign(region, offset, region.word_rlc(code_hash))?;

        let bytecode_len = if code_hash.is_zero() {
            0
        } else {
            block
                .bytecodes
                .get(&code_hash)
                .expect("could not find external bytecode")
                .bytes
                .len()
        };
        self.code_size
            .assign(region, offset, Value::known(F::from(bytecode_len as u64)))?;

        // let (_, memory_expansion_gas_cost) = self.memory_expansion.assign(
        //     region,
        //     offset,
        //     step.memory_word_size(),
        //     [memory_address],
        // )?;

        self.memory_copier_gas.assign(
            region,
            offset,
            copy_size.as_u64(),
            0/*memory_expansion_gas_cost as u64*/,
        )?;

        self.copy_rwc_inc.assign(
            region,
            offset,
            Value::known(
                copy_size
                    .to_scalar()
                    .expect("unexpected U256 -> Scalar conversion failure"),
            ),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use lazy_static::lazy_static;

    use eth_types::{
        address, Address, bytecode, Bytecode, Bytes, geth_types::Account, Word,
    };
    use eth_types::bytecode::WasmBinaryBytecode;
    use mock::TestContext;

    use crate::{evm_circuit::test::rand_bytes_array, test_util::CircuitTestBuilder};

    lazy_static! {
        static ref EXTERNAL_ADDRESS: Address =
            address!("0xaabbccddee000000000000000000000000000000");
    }

    fn test_ok(
        external_account: Option<Account>,
        memory_offset: usize,
        code_offset: usize,
        copy_size: usize,
        is_warm: bool,
    ) {
        let external_address = external_account
            .as_ref()
            .map(|a| a.address)
            .unwrap_or(*EXTERNAL_ADDRESS);

        let mut code = Bytecode::default();

        let address_offset = code.fill_default_global_data(external_address.as_bytes().to_vec());

        if is_warm {
            code.append(&bytecode! {
                I32Const[address_offset]
                I32Const[0xff]
                EXTCODEHASH
            });
        }
        code.append(&bytecode! {
            I32Const[address_offset]
            I32Const[memory_offset]
            I32Const[code_offset]
            I32Const[copy_size]
            // #[start]
            EXTCODECOPY
        });

        let ctx = TestContext::<3, 1>::new(
            None,
            |accs| {
                accs[0]
                    .address(address!("0x000000000000000000000000000000000000cafe"))
                    .code(code.wasm_binary());
                accs[1]
                    .address(address!("0x0000000000000000000000000000000000000010"))
                    .balance(Word::from(1u64 << 20));
                accs[2].address(external_address);
                if let Some(external_account) = external_account {
                    let external_account_code_vec = external_account.code.to_vec();
                    accs[2]
                        .balance(external_account.balance)
                        .nonce(external_account.nonce)
                        .code(external_account_code_vec);
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

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }

    #[test]
    fn extcodecopy_empty_account_cold() {
        test_ok(None, 0x00, 0x00, 0x36, false);
    }

    // #[test]
    // fn extcodecopy_empty_account_warm() {
    //     test_ok(None, 0x00, 0x00, 0x36, true);
    // }

    // #[test]
    // fn extcodecopy_nonempty_account_warm() {
    //     test_ok(
    //         Some(Account {
    //             address: *EXTERNAL_ADDRESS,
    //             code: Bytes::from([10, 40]),
    //             ..Default::default()
    //         }),
    //         0x00,
    //         0x00,
    //         0x36,
    //         true,
    //     );
    // }

    #[test]
    fn extcodecopy_nonempty_account_cold() {
        test_ok(
            Some(Account {
                address: *EXTERNAL_ADDRESS,
                code: Bytes::from([10, 40]),
                ..Default::default()
            }),
            20,
            0,
            2,
            false,
        );
    }

    // #[test]
    // fn extcodecopy_nonempty_account_warm() {
    //     test_ok(
    //         Some(Account {
    //             address: *EXTERNAL_ADDRESS,
    //             code: Bytes::from([10, 40]),
    //             ..Default::default()
    //         }),
    //         0x00,
    //         0x00,
    //         0x36,
    //         true,
    //     );
    // }

    #[test]
    fn extcodecopy_largerthan256_cold() {
        test_ok(
            Some(Account {
                address: *EXTERNAL_ADDRESS,
                code: Bytes::from(rand_bytes_array::<256>()),
                ..Default::default()
            }),
            0x00,
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
            0x00,
            0x20,
            0x104,
            true,
        );
        test_ok(
            Some(Account {
                address: *EXTERNAL_ADDRESS,
                code: Bytes::from(rand_bytes_array::<64>()),
                ..Default::default()
            }),
            0x00,
            0x20,
            0x104,
            false,
        );
    }
}
