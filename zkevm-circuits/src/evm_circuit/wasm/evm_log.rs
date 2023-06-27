use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::{N_BYTES_MEMORY_WORD_SIZE, N_BYTES_U64},
        step::ExecutionState,
        util::{
            common_gadget::{SameContextGadget, WordByteRangeGadget},
            constraint_builder::{
                ConstrainBuilderCommon, EVMConstraintBuilder, StepStateTransition,
                Transition::{Delta, To},
            },
            memory_gadget::{
                CommonMemoryAddressGadget, MemoryAddressGadget, MemoryExpansionGadget,
            },
            not, sum, CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::{CallContextFieldTag, RwTableTag, TxLogFieldTag},
    util::{build_tx_log_expression, Expr},
};
use array_init::array_init;
use bus_mapping::circuit_input_builder::CopyDataType;
use eth_types::{evm_types::{GasCost, OpcodeId}, Field, StackWord, ToBigEndian, ToLittleEndian, ToScalar, ToU256, U256};
use halo2_proofs::{circuit::Value, plonk::Error};
use crate::evm_circuit::util::memory_gadget::MemoryAddress64Gadget;
use crate::evm_circuit::util::Word;

#[derive(Clone, Debug)]
pub(crate) struct EvmLogGadget<F> {
    same_context: SameContextGadget<F>,
    memory_address: MemoryAddress64Gadget<F>,
    topics_offsets: [Cell<F>; 4],
    topic_selectors: [Cell<F>; 4],
    topics_rlc: [Word<F>; 4],

    contract_address: Cell<F>,
    is_static_call: Cell<F>,
    is_persistent: Cell<F>,
    tx_id: Cell<F>,
    copy_rwc_inc: Cell<F>,
    memory_expansion: MemoryExpansionGadget<F, 1, N_BYTES_MEMORY_WORD_SIZE>,
}

impl<F: Field> ExecutionGadget<F> for EvmLogGadget<F> {
    const NAME: &'static str = "LOG";

    const EXECUTION_STATE: ExecutionState = ExecutionState::LOG;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let mstart = cb.query_cell_phase2();
        let msize = cb.query_cell();

        // read tx id
        let tx_id = cb.call_context(None, CallContextFieldTag::TxId);
        // constrain not in static call
        let is_static_call = cb.call_context(None, CallContextFieldTag::IsStatic);
        cb.require_zero("is_static_call is false", is_static_call.expr());

        // check contract_address in CallContext & TxLog
        // use call context's  callee address as contract address
        let contract_address = cb.call_context(None, CallContextFieldTag::CalleeAddress);
        let is_persistent = cb.call_context(None, CallContextFieldTag::IsPersistent);
        cb.require_boolean("is_persistent is bool", is_persistent.expr());

        cb.condition(is_persistent.expr(), |cb| {
            cb.tx_log_lookup(
                tx_id.expr(),
                cb.curr.state.log_id.expr() + 1.expr(),
                TxLogFieldTag::Address,
                0.expr(),
                contract_address.expr(),
            );
        });

        // constrain topics in logs
        let topic_selectors: [Cell<F>; 4] = array_init(|_| cb.query_cell());
        let topics_offsets: [Cell<F>; 4] = array_init(|_| cb.query_cell());
        let topics_rlc: [Word<F>; 4] = array_init(|_| cb.query_word_rlc());
        for (idx, (topics_offsets,  topic_rlc)) in topics_offsets.iter().zip(topics_rlc.iter()).enumerate() {
            cb.condition(topic_selectors[idx].expr(), |cb| {
                cb.stack_pop(topics_offsets.expr());
                cb.memory_rlc_lookup(1.expr(), &topics_offsets, &topic_rlc);
            });
            cb.condition(topic_selectors[idx].expr() * is_persistent.expr(), |cb| {
                cb.tx_log_lookup(
                    tx_id.expr(),
                    cb.curr.state.log_id.expr() + 1.expr(),
                    TxLogFieldTag::Topic,
                    idx.expr(),
                    topic_rlc.expr(),
                );
            });
        }

        // Pop mstart_address, msize from stack
        cb.stack_pop(msize.expr());
        cb.stack_pop(mstart.expr());

        let opcode = cb.query_cell();
        let topic_count = opcode.expr() - OpcodeId::LOG0.as_u8().expr();

        // TOPIC_COUNT == Non zero topic selector count
        cb.require_equal(
            " sum of topic selectors = topic_count ",
            topic_count.clone(),
            sum::expr(topic_selectors.clone()),
        );

        // `topic_selectors` order must be from 1 --> 0
        for idx in 0..4 {
            cb.require_boolean("topic selector is bool ", topic_selectors[idx].expr());
            if idx > 0 {
                let selector_prev = topic_selectors[idx - 1].expr();
                // selector can transit from 1 to 0 only once as [1, 1 ..., 0]
                cb.require_boolean(
                    "Constrain topic selectors can only transit from 1 to 0",
                    selector_prev - topic_selectors[idx].expr(),
                );
            }
        }

        // check memory copy
        let memory_address = MemoryAddress64Gadget::construct(cb, mstart, msize);

        // Calculate the next memory size and the gas cost for this memory
        // access
        let memory_expansion = MemoryExpansionGadget::construct(cb, [memory_address.address()]);

        let copy_rwc_inc = cb.query_cell();
        let dst_addr = build_tx_log_expression(
            0.expr(),
            TxLogFieldTag::Data.expr(),
            cb.curr.state.log_id.expr() + 1.expr(),
        );
        let cond = memory_address.has_length() * is_persistent.expr();
        cb.condition(cond.clone(), |cb| {
            cb.copy_table_lookup(
                cb.curr.state.call_id.expr(),
                CopyDataType::Memory.expr(),
                tx_id.expr(),
                CopyDataType::TxLog.expr(),
                memory_address.offset(),
                memory_address.address(),
                dst_addr,
                memory_address.length(),
                0.expr(), // for LOGN, rlc_acc is 0
                copy_rwc_inc.expr(),
            );
        });
        cb.condition(not::expr(cond), |cb| {
            cb.require_zero(
                "if length is 0 or tx is not persistent, copy table rwc inc == 0",
                copy_rwc_inc.expr(),
            );
        });

        let gas_cost = GasCost::LOG.as_u64().expr()
            + GasCost::LOG.as_u64().expr() * topic_count.clone()
            + 8.expr() * memory_address.length()
            + memory_expansion.gas_cost();
        // State transition

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(cb.rw_counter_offset()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(2.expr() + topic_count),
            memory_word_size: To(memory_expansion.next_memory_word_size()),
            log_id: Delta(is_persistent.expr()),
            gas_left: Delta(-gas_cost),
            ..Default::default()
        };

        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            memory_address,
            topic_selectors,
            topics_offsets,
            contract_address,
            is_static_call,
            is_persistent,
            tx_id,
            copy_rwc_inc,
            memory_expansion,
            topics_rlc,
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

        let opcode = step.opcode.unwrap();
        let topic_count = opcode.postfix().expect("opcode with postfix") as usize;
        assert!(topic_count <= 4);

        let is_persistent = call.is_persistent as u64;
        let mut topic_stack_entry = if topic_count > 0 {
            step.rw_indices[4 + call.is_persistent as usize]
        } else {
            // if topic_count == 0, this value will be no used anymore
            (RwTableTag::Stack, 0usize)
        };

        for i in 0..4 {
            let mut topic = U256::zero();
            let mut topic_offset = StackWord::zero();
            if i < topic_count {
                let topic_vec = step.rw_indices[5 + call.is_persistent as usize + 34 * i..6 + 34 * i + 32].iter().map(|&b|
                    block.rws[b].memory_value()
                ).collect::<Vec<u8>>();
                topic = U256::from_big_endian(topic_vec.as_slice());
                topic_offset = block.rws[topic_stack_entry].stack_value();

                self.topic_selectors[i].assign(region, offset, Value::known(F::one()))?;
                topic_stack_entry.1 += 1;
            } else {
                self.topic_selectors[i].assign(region, offset, Value::known(F::zero()))?;
            }
            self.topics_rlc[i].assign(region, offset, Some(topic.to_le_bytes()))?;
            self.topics_offsets[i].assign(region, offset, Value::<F>::known(topic_offset.to_scalar().unwrap()))?;
        }

        let stack_offset = 4 + call.is_persistent as usize + topic_count * (1 + 32 + is_persistent as usize);
        let [msize, memory_start] =
            [step.rw_indices[stack_offset], step.rw_indices[stack_offset + 1]].map(|idx| {
                block.rws[idx].stack_value()
            });

        let memory_address = self
            .memory_address
            .assign(region, offset, memory_start, msize)?;

        // Memory expansion
        self.memory_expansion
            .assign(region, offset, step.memory_word_size(), [memory_address])?;

        self.contract_address.assign(
            region,
            offset,
            Value::known(
                call.callee_address
                    .to_scalar()
                    .expect("unexpected Address -> Scalar conversion failure"),
            ),
        )?;

        self.is_static_call
            .assign(region, offset, Value::known(F::from(call.is_static as u64)))?;
        self.is_persistent
            .assign(region, offset, Value::known(F::from(is_persistent)))?;
        self.tx_id
            .assign(region, offset, Value::known(F::from(tx.id as u64)))?;
        // rw_counter increase from copy table lookup is `msize` memory reads + `msize`
        // log writes when `is_persistent` is true.
        self.copy_rwc_inc.assign(
            region,
            offset,
            Value::known(
                ((msize + msize) * StackWord::from(is_persistent))
                    .to_scalar()
                    .expect("unexpected U256 -> Scalar conversion failure"),
            ),
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::CircuitTestBuilder;
    use eth_types::{evm_types::OpcodeId, Bytecode, Word, ToBigEndian, bytecode_internal};
    use mock::TestContext;
    use rand::Rng;

    #[test]
    fn test_log0() {
        test_log_ok(&[], true, None);
    }

    #[test]
    fn log_gadget_simple() {
        // 1. tests for is_persistent = true cases
        // zero topic: log0
        test_log_ok(&[], true, None);
        // one topic: log1
        test_log_ok(&[Word::from(0xA0)], true, None);
        // two topics: log2
        test_log_ok(&[Word::from(0xA0), Word::from(0xef)], true, None);
        // three topics: log3
        test_log_ok(
            &[Word::from(0xA0), Word::from(0xef), Word::from(0xb0)],
            true,
            None,
        );
        // four topics: log4
        test_log_ok(
            &[
                Word::from(0xA0),
                Word::from(0xef),
                Word::from(0xb0),
                Word::from(0x37),
            ],
            true,
            None,
        );
        //
        // // 2. tests for is_persistent = false cases
        // // log0
        // test_log_ok(&[], false, None);
        // // log1
        // test_log_ok(&[Word::from(0xA0)], false, None);
        // // log4
        // test_log_ok(
        //     &[
        //         Word::from(0xA0),
        //         Word::from(0xef),
        //         Word::from(0xb0),
        //         Word::from(0x37),
        //     ],
        //     false,
        //     None,
        // );
    }

    #[test]
    fn log_gadget_multi_logs() {
        // zero topic: log0
        test_multi_log_ok(&[]);
        // one topic: log1
        test_multi_log_ok(&[Word::from(0xA0)]);
        // two topics: log2
        test_multi_log_ok(&[Word::from(0xA0), Word::from(0xef)]);
        // three topics: log3
        test_multi_log_ok(&[Word::from(0xA0), Word::from(0xef), Word::from(0xb0)]);
        // four topics: log4
        test_multi_log_ok(&[
            Word::from(0xA0),
            Word::from(0xef),
            Word::from(0xb0),
            Word::from(0x37),
        ]);
    }

    #[test]
    fn log_gadget_with_overflow_mstart_and_zero_msize() {
        let stack = Some(Stack {
            mstart: Word::MAX,
            msize: Word::zero(),
        });

        test_log_ok(&[], false, stack);
        test_log_ok(&[Word::from(0xA0)], true, stack);
        test_log_ok(&[Word::from(0xA0), Word::from(0xef)], false, stack);
        test_log_ok(
            &[Word::from(0xA0), Word::from(0xef), Word::from(0xb0)],
            true,
            stack,
        );
        test_log_ok(
            &[
                Word::from(0xA0),
                Word::from(0xef),
                Word::from(0xb0),
                Word::from(0x37),
            ],
            true,
            stack,
        );
    }

    #[derive(Clone, Copy)]
    struct Stack {
        mstart: Word,
        msize: Word,
    }

    // test single log code and single copy log step
    fn test_log_ok(topics: &[Word], is_persistent: bool, stack: Option<Stack>) {
        let mut pushdata = [0u8; 320];
        rand::thread_rng().try_fill(&mut pushdata[..]).unwrap();

        let log_codes = [
            OpcodeId::LOG0,
            OpcodeId::LOG1,
            OpcodeId::LOG2,
            OpcodeId::LOG3,
            OpcodeId::LOG4,
        ];

        let topic_count = topics.len();
        let cur_op_code = log_codes[topic_count];

        // use more than 256 for testing offset rlc
        let mstart = 0x102usize;
        let msize = 0x20usize;
        let mut code = Bytecode::default();
        code.alloc_default_global_data(1);
        code.fill_default_global_data(pushdata.to_vec());

        code.write_postfix(OpcodeId::I32Const, mstart as i128);
        code.write_postfix(OpcodeId::I32Const, msize as i128);
        // make dynamic topics push operations
        for topic in topics {
            let offset = code.fill_default_global_data(topic.to_be_bytes().to_vec());
            code.write_postfix(OpcodeId::I32Const, offset as i128);
        }
        code.write_op(cur_op_code);
        if is_persistent {
        } else {
            // make current call failed with false persistent
            code.write_op(OpcodeId::INVALID(0xfe));
        }

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(code).unwrap(),
        ).run();
    }

    // test multi log op codes and multi copy log steps
    fn test_multi_log_ok(topics: &[Word]) {
        // prepare memory data
        let mut pushdata = [0u8; 320];
        rand::thread_rng().try_fill(&mut pushdata[..]).unwrap();
        let mut code_prepare = prepare_code(&pushdata, 0);

        let log_codes = [
            OpcodeId::LOG0,
            OpcodeId::LOG1,
            OpcodeId::LOG2,
            OpcodeId::LOG3,
            OpcodeId::LOG4,
        ];

        let topic_count = topics.len();
        let cur_op_code = log_codes[topic_count];

        let mut mstart = 0x00usize;
        let mut msize = 0x10usize;
        // first log op code
        let mut code = Bytecode::default();
        // make dynamic topics push operations
        code.alloc_default_global_data(1);
        code.fill_default_global_data(pushdata.to_vec());

        code.write_postfix(OpcodeId::I32Const, mstart as i128);
        code.write_postfix(OpcodeId::I32Const, msize as i128);
        for topic in topics {
            let offset = code.fill_default_global_data(topic.to_be_bytes().to_vec());
            code.write_postfix(OpcodeId::I32Const, offset as i128);
        }
        code.write_op(cur_op_code);

        // second log op code
        // prepare additinal bytes for memory reading
        code.append(&prepare_code(&pushdata, 0x20));
        mstart = 0x00usize;
        // when mszie > 0x20 (32) needs multi copy steps
        msize = 0x30usize;
        code.write_postfix(OpcodeId::I32Const, mstart as i128);
        code.write_postfix(OpcodeId::I32Const, msize as i128);
        for topic in topics {
            let offset = code.fill_default_global_data(topic.to_be_bytes().to_vec());
            code.write_postfix(OpcodeId::I32Const, offset as i128);
        }
        code.write_op(cur_op_code);

        code.op_stop();
        code_prepare.append(&code);

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(code).unwrap(),
        )
        .run();
    }

    /// prepare memory reading data
    fn prepare_code(data: &[u8], offset: usize) -> Bytecode {
        assert_eq!(data.len() % 32, 0);
        // prepare memory data
        let mut code = Bytecode::default();
        for (i, d) in data.chunks(32).enumerate() {
            code.op_mstore(offset + i * 32, Word::from_big_endian(d));
        }
        code
    }
}
