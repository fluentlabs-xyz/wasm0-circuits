use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_PROGRAM_COUNTER,
        step::ExecutionState,
        util::{
            common_gadget::RestoreContextGadget,
            constraint_builder::{
                ConstrainBuilderCommon, StepStateTransition,
                Transition::{Delta, Same},
            },
            math_gadget::IsZeroGadget,
            CachedRegion, Cell,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::CallContextFieldTag,
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use eth_types::Field;
use halo2_proofs::{circuit::Value, plonk::Error};
use crate::evm_circuit::util::constraint_builder::EVMConstraintBuilder;
use crate::evm_circuit::util::math_gadget::LtGadget;

#[derive(Clone, Debug)]
pub(crate) struct EvmStopGadget<F> {
    code_length: Cell<F>,
    is_within_range: LtGadget<F, N_BYTES_PROGRAM_COUNTER>,
    call_opcode: Cell<F>,
    call_index: Cell<F>,
    restore_context: RestoreContextGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for EvmStopGadget<F> {
    const NAME: &'static str = "STOP";

    const EXECUTION_STATE: ExecutionState = ExecutionState::STOP;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let code_length = cb.query_cell();
        cb.bytecode_length(cb.curr.state.code_hash.expr(), code_length.expr());
        let is_within_range =
            LtGadget::construct(cb, cb.curr.state.program_counter.expr(), code_length.expr());
        let call_opcode = cb.query_cell();
        let call_index = cb.query_cell();

        cb.condition(is_within_range.expr(), |cb| {
            //TODO: Set correct is_code
            cb.opcode_lookup(call_opcode.expr(), 0.expr());
            cb.opcode_lookup(call_index.expr(), 1.expr());
        });

        // We do the responsible opcode check explicitly here because we're not using
        // the `SameContextGadget` for `STOP`.
        cb.require_equal(
            "Opcode should be Call",
            call_opcode.expr(),
            OpcodeId::Call.expr(),
        );

        // Call ends with STOP must be successful
        cb.call_context_lookup(false.expr(), None, CallContextFieldTag::IsSuccess, 1.expr());

        let is_to_end_tx = cb.next.execution_state_selector([ExecutionState::EndTx]);
        cb.require_equal(
            "Go to EndTx only when is_root",
            cb.curr.state.is_root.expr(),
            is_to_end_tx,
        );

        // When it's a root call
        cb.condition(cb.curr.state.is_root.expr(), |cb| {
            // Do step state transition
            cb.require_step_state_transition(StepStateTransition {
                call_id: Same,
                rw_counter: Delta(1.expr()),
                ..StepStateTransition::any()
            });
        });

        // When it's an internal call
        let restore_context = cb.condition(1.expr() - cb.curr.state.is_root.expr(), |cb| {
            RestoreContextGadget::construct(
                cb,
                true.expr(),
                0.expr(),
                0.expr(),
                0.expr(),
                0.expr(),
                0.expr(),
            )
        });

        Self {
            code_length,
            is_within_range,
            call_opcode,
            restore_context,
            call_index,
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
        let code = block
            .bytecodes
            .get(&call.code_hash)
            .expect("could not find current environment's bytecode");
        self.code_length.assign(
            region,
            offset,
            Value::known(F::from(code.bytes.len() as u64)),
        )?;

        self.is_within_range.assign(
            region,
            offset,
            F::from(step.program_counter),
            F::from(code.bytes.len() as u64),
        )?;

        self.call_opcode
            .assign(region, offset, Value::known(F::from(OpcodeId::Call.as_u64())))?;
        //TODO: Set correct call function index
        self.call_index
            .assign(region, offset, Value::known(F::from(1)))?;

        if !call.is_root {
            self.restore_context
                .assign(region, offset, block, call, step, 1)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::test_util::CircuitTestBuilder;
    use eth_types::{address, bytecode, Bytecode, Word};

    use itertools::Itertools;
    use mock::TestContext;

    fn test_ok(bytecode: Bytecode, is_root: bool) {
        if is_root {
            let ctx = TestContext::<2, 1>::new(
                None,
                |accs| {
                    accs[0]
                        .address(address!("0x0000000000000000000000000000000000000123"))
                        .balance(Word::from(1u64 << 30));
                    accs[1]
                        .address(address!("0x0000000000000000000000000000000000000010"))
                        .balance(Word::from(1u64 << 20))
                        .code(bytecode);
                },
                |mut txs, accs| {
                    txs[0]
                        .from(accs[0].address)
                        .to(accs[1].address)
                        .gas(Word::from(30000));
                },
                |block, _tx| block.number(0xcafeu64),
            )
            .unwrap();

            CircuitTestBuilder::new_from_test_ctx(ctx).run();
        } else {
            let ctx = TestContext::<3, 1>::new(
                None,
                |accs| {
                    accs[0]
                        .address(address!("0x0000000000000000000000000000000000000123"))
                        .balance(Word::from(1u64 << 30));
                    accs[1]
                        .address(address!("0x0000000000000000000000000000000000000010"))
                        .balance(Word::from(1u64 << 20))
                        .code(bytecode! {
                            I32Const[20]
                            GAS
                            STOP
                        });
                    accs[2]
                        .address(address!("0x0000000000000000000000000000000000000020"))
                        .balance(Word::from(1u64 << 20))
                        .code(bytecode);
                },
                |mut txs, accs| {
                    txs[0]
                        .from(accs[0].address)
                        .to(accs[1].address)
                        .gas(Word::from(30000));
                },
                |block, _tx| block.number(0xcafeu64),
            )
            .unwrap();

            CircuitTestBuilder::new_from_test_ctx(ctx).run();
        };
    }

    #[test]
    fn stop_gadget_simple() {
        let bytecodes = vec![
            bytecode! {
                I32Const[0]
                Drop
                STOP
            },
            bytecode! {
                I32Const[0]
                Drop
            },
        ];
        let is_roots = vec![true, false];
        // for (bytecode, is_root) in bytecodes.into_iter().cartesian_product(is_roots) {
        //     test_ok(bytecode, is_root);
        // }
        test_ok(bytecodes[1].clone(), false);
    }
}
