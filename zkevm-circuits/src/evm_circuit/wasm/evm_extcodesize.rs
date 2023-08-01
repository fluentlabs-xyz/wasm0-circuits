use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_ACCOUNT_ADDRESS, N_BYTES_MEMORY_WORD_SIZE},
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{
                ReversionInfo, StepStateTransition, Transition::Delta,
            },
            from_bytes,
            math_gadget::IsZeroGadget,
            not, select, CachedRegion, Cell, RandomLinearCombination,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{AccountFieldTag, CallContextFieldTag},
    util::Expr,
};
use eth_types::{evm_types::GasCost, Field, ToLittleEndian, ToScalar};
use halo2_proofs::{circuit::Value, plonk::Error};
use crate::evm_circuit::util::constraint_builder::EVMConstraintBuilder;

#[derive(Clone, Debug)]
pub(crate) struct EvmExtCodeSizeGadget<F> {
    same_context: SameContextGadget<F>,
    address_word: RandomLinearCombination<F, N_BYTES_ACCOUNT_ADDRESS>,
    address_offset: Cell<F>,
    codesize_offset: Cell<F>,
    reversion_info: ReversionInfo<F>,
    tx_id: Cell<F>,
    is_warm: Cell<F>,
    code_hash: Cell<F>,
    not_exists: IsZeroGadget<F>,
    codesize: RandomLinearCombination<F, N_BYTES_MEMORY_WORD_SIZE>,
}

impl<F: Field> ExecutionGadget<F> for EvmExtCodeSizeGadget<F> {
    const NAME: &'static str = "EXTCODESIZE";

    const EXECUTION_STATE: ExecutionState = ExecutionState::EXTCODESIZE;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let address_word = cb.query_word_rlc();
        let address = from_bytes::expr(&address_word.cells[..N_BYTES_ACCOUNT_ADDRESS]);
        let codesize_offset = cb.query_cell();
        let address_offset = cb.query_cell();

        cb.stack_pop(codesize_offset.expr());
        cb.stack_pop(address_offset.expr());

        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        let mut reversion_info = cb.reversion_info_read(None);
        let is_warm = cb.query_bool();
        cb.account_access_list_write(
            tx_id.expr(),
            address.expr(),
            1.expr(),
            is_warm.expr(),
            Some(&mut reversion_info),
        );

        let code_hash = cb.query_cell_phase2();
        // For non-existing accounts the code_hash must be 0 in the rw_table.
        cb.account_read(address.expr(), AccountFieldTag::CodeHash, code_hash.expr());
        let not_exists = IsZeroGadget::construct(cb, code_hash.expr());
        let exists = not::expr(not_exists.expr());

        let codesize = cb.query_word_rlc();
        cb.condition(exists.expr(), |cb| {
            cb.bytecode_length(code_hash.expr(), from_bytes::expr(&codesize.cells));
        });
        cb.condition(not_exists.expr(), |cb| {
            cb.require_zero("codesize is zero when non_exists", codesize.expr());
        });

        cb.memory_rlc_lookup(0.expr(), &address_offset, &address_word);
        cb.memory_rlc_lookup(1.expr(), &codesize_offset, &codesize);

        let gas_cost = select::expr(
            is_warm.expr(),
            GasCost::WARM_ACCESS.expr(),
            GasCost::COLD_ACCOUNT_ACCESS.expr(),
        );
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(31.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(2.expr()),
            gas_left: Delta(-gas_cost),
            reversible_write_counter: Delta(1.expr()),
            ..Default::default()
        };

        let opcode = cb.query_cell();
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            address_word,
            codesize_offset,
            address_offset,
            tx_id,
            reversion_info,
            is_warm,
            code_hash,
            not_exists,
            codesize,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        tx: &Transaction,
        call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let codesize_offset = block.rws[step.rw_indices[0]].stack_value();
        self.codesize_offset
            .assign(region, offset, Value::known(codesize_offset.to_scalar().unwrap()))?;
        let address_offset = block.rws[step.rw_indices[1]].stack_value();
        self.address_offset
            .assign(region, offset, Value::known(address_offset.to_scalar().unwrap()))?;

        self.tx_id
            .assign(region, offset, Value::known(F::from(tx.id as u64)))?;

        self.reversion_info.assign(
            region,
            offset,
            call.rw_counter_end_of_reversion,
            call.is_persistent,
        )?;

        let (_, is_warm) = block.rws[step.rw_indices[5]].tx_access_list_value_pair();
        self.is_warm
            .assign(region, offset, Value::known(F::from(is_warm as u64)))?;

        let code_hash = block.rws[step.rw_indices[6]].account_value_pair().0;
        self.code_hash
            .assign(region, offset, region.word_rlc(code_hash))?;
        self.not_exists
            .assign_value(region, offset, region.word_rlc(code_hash))?;

        let address_rw_index = 7;
        let codesize_rw_index = address_rw_index + N_BYTES_ACCOUNT_ADDRESS;
        let address = {
            let vec = step.rw_indices[address_rw_index..(address_rw_index + N_BYTES_ACCOUNT_ADDRESS)]
                .iter()
                .map(|&b| block.rws[b].memory_value())
                .collect::<Vec<u8>>();
            eth_types::Word::from_big_endian(vec.as_slice())
        };
        self.address_word
            .assign(region, offset, Some(address.to_le_bytes()[0..N_BYTES_ACCOUNT_ADDRESS].try_into().unwrap()))?;
        let codesize = {
            let vec = step.rw_indices[codesize_rw_index..(codesize_rw_index + N_BYTES_MEMORY_WORD_SIZE)]
                .iter()
                .map(|&b| block.rws[b].memory_value())
                .collect::<Vec<u8>>();
            eth_types::StackWord::from_big_endian(vec.as_slice())
        };
        self.codesize
            .assign(region, offset, Some(codesize.to_le_bytes()[0..N_BYTES_MEMORY_WORD_SIZE].try_into().unwrap()))?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{test_util::CircuitTestBuilder};
    use eth_types::{bytecode, bytecode_internal, geth_types::Account, Bytecode};
    use eth_types::bytecode::WasmBinaryBytecode;
    use mock::{TestContext, MOCK_1_ETH, MOCK_ACCOUNTS, MOCK_CODES};
    use crate::evm_circuit::param::N_BYTES_ACCOUNT_ADDRESS;

    #[test]
    fn test_extcodesize_gadget_simple_empty_acc() {
        test_ok(&Account::default(), true);
    }

    #[test]
    fn test_extcodesize_gadget_simple_cold_acc() {
        let account = Account {
            address: MOCK_ACCOUNTS[4],
            code: MOCK_CODES[4].clone(),
            ..Default::default()
        };

        // Test for cold account.
        test_ok(&account, true);
        // Test for warm account.
        // test_ok(&account, true);
    }

    #[test]
    fn test_extcodesize_gadget_with_long_code() {
        let account = Account {
            address: MOCK_ACCOUNTS[4],
            code: MOCK_CODES[5].clone(), // ADDRESS * 256
            ..Default::default()
        };

        // Test for cold account.
        test_ok(&account, false);
        // Test for warm account.
        test_ok(&account, true);
    }

    fn test_ok(account: &Account, is_warm: bool) {
        let account_exists = !account.is_empty();
        let account_mem_address = 0x0;
        let res_mem_address1 = 0x7f;
        let res_mem_address2 = res_mem_address1 + N_BYTES_ACCOUNT_ADDRESS;

        let (addr_a, addr_b) = (mock::MOCK_ACCOUNTS[0], mock::MOCK_ACCOUNTS[1]);

        // code B gets called by code A, so the call is an internal call.
        let mut bytecode_b = Bytecode::default();
        if is_warm {
            bytecode_internal! {bytecode_b,
                // PUSH20(account.address.to_word())
                // EXTCODESIZE
                // POP
                I32Const[account_mem_address]
                I32Const[res_mem_address1]
                EXTCODESIZE
            }
        }
        bytecode_internal! {bytecode_b,
            // PUSH20(account.address.to_word())
            // EXTCODESIZE
            // POP
            I32Const[account_mem_address]
            I32Const[res_mem_address1]
            EXTCODESIZE
        }
        bytecode_b.with_global_data(0, account_mem_address, account.address.0.to_vec());

        let mut bytecode_a = bytecode! {
            // PUSH20(account.address.to_word())
            // EXTCODESIZE
            // POP
            I32Const[account_mem_address]
            I32Const[res_mem_address2]
            EXTCODESIZE
        };
        bytecode_a.with_global_data(0, account_mem_address, account.address.0.to_vec());

        // code A calls code B.
        // let pushdata = rand_bytes(8);
        // let bytecode_a = bytecode! {
        //     // populate memory in A's context.
        //     PUSH8(Word::from_big_endian(&pushdata))
        //     PUSH1(0x00) // offset
        //     MSTORE
        //     // call ADDR_B.
        //     PUSH1(0x00) // retLength
        //     PUSH1(0x00) // retOffset
        //     PUSH32(0xff) // argsLength
        //     PUSH32(0x1010) // argsOffset
        //     PUSH1(0x00) // value
        //     PUSH32(addr_b.to_word()) // addr
        //     PUSH32(0x1_0000) // gas
        //     CALL
        //     STOP
        // };

        let ctx = TestContext::<4, 1>::new(
            None,
            |accs| {
                accs[0].address(addr_b).code(bytecode_b.wasm_binary());
                accs[1].address(addr_a).code(bytecode_a.wasm_binary());
                // Set code if account exists.
                if account_exists {
                    accs[2].address(account.address).code(account.code.clone());
                } else {
                    accs[2].address(mock::MOCK_ACCOUNTS[2]).balance(*MOCK_1_ETH);
                }
                accs[3].address(mock::MOCK_ACCOUNTS[3]).balance(*MOCK_1_ETH);
            },
            |mut txs, accs| {
                txs[0].to(accs[1].address).from(accs[3].address);
            },
            |block, _tx| block,
        )
        .unwrap();

        CircuitTestBuilder::new_from_test_ctx(ctx).run();
    }
}
