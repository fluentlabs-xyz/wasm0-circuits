use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        param::N_BYTES_ACCOUNT_ADDRESS,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstrainBuilderCommon, StepStateTransition, Transition::Delta},
            from_bytes, CachedRegion, RandomLinearCombination,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    table::CallContextFieldTag,
    util::Expr,
};
use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToLittleEndian, ToScalar};
use halo2_proofs::plonk::Error;
use std::convert::TryInto;
use halo2_proofs::circuit::Value;
use crate::evm_circuit::util::Cell;
use crate::evm_circuit::util::constraint_builder::EVMConstraintBuilder;

#[derive(Clone, Debug)]
pub(crate) struct EvmAddressGadget<F> {
    same_context: SameContextGadget<F>,
    address_offset: Cell<F>,
    callee_address: RandomLinearCombination<F, N_BYTES_ACCOUNT_ADDRESS>,
}

impl<F: Field> ExecutionGadget<F> for EvmAddressGadget<F> {
    const NAME: &'static str = "ADDRESS";

    const EXECUTION_STATE: ExecutionState = ExecutionState::ADDRESS;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let address_offset = cb.query_cell();
        let callee_address = cb.query_word_rlc();

        // Lookup callee address in call context.
        cb.call_context_lookup(
            false.expr(),
            None,
            CallContextFieldTag::CalleeAddress,
            from_bytes::expr(&callee_address.cells),
        );
        cb.stack_pop(address_offset.expr());
        cb.memory_rlc_lookup(true.expr(), &address_offset, &callee_address);

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(22.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
            gas_left: Delta(-OpcodeId::ADDRESS.constant_gas_cost().expr()),
            ..Default::default()
        };

        let opcode = cb.query_cell();
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            address_offset,
            callee_address,
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

        let callee_address = block.rws[step.rw_indices[0]].call_context_value();
        let callee_address_le_bytes = &callee_address.to_le_bytes()[0..N_BYTES_ACCOUNT_ADDRESS];
        self.callee_address
            .assign(region, offset, Some(callee_address_le_bytes.try_into().unwrap()))?;

        let address_offset = block.rws[step.rw_indices[1]].stack_value();
        self.address_offset.assign(region, offset, Value::<F>::known(address_offset.to_scalar().unwrap()))?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use eth_types::bytecode;
    use mock::test_ctx::TestContext;
    use crate::test_util::CircuitTestBuilder;

    fn test_root_ok() {
        let res_mem_address = 0x7f;
        let bytecode = bytecode! {
            I32Const[res_mem_address]
            ADDRESS
        };
        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
        .run();
    }

    // fn test_internal_ok(call_data_offset: usize, call_data_length: usize) {
    //     let (addr_a, addr_b) = (mock::MOCK_ACCOUNTS[0], mock::MOCK_ACCOUNTS[1]);
    //
    //     // code B gets called by code A, so the call is an internal call.
    //     let res_mem_address = 0x7f;
    //     let code_b = bytecode! {
    //         I32Const[res_mem_address]
    //         ADDRESS
    //     };
    //
    //     // code A calls code B.
    //     let pushdata = rand_word();
    //     let code_a = bytecode! {
    //         // populate memory in A's context.
    //         PUSH8(pushdata)
    //         PUSH1(0x00) // offset
    //         MSTORE
    //         // call ADDR_B.
    //         PUSH1(0x00) // retLength
    //         PUSH1(0x00) // retOffset
    //         PUSH32(call_data_length) // argsLength
    //         PUSH32(call_data_offset) // argsOffset
    //         PUSH1(0x00) // value
    //         PUSH32(addr_b.to_word()) // addr
    //         PUSH32(0x1_0000) // gas
    //         CALL
    //         STOP
    //     };
    //
    //     let ctx = TestContext::<3, 1>::new(
    //         None,
    //         |accs| {
    //             accs[0].address(addr_b).code(code_b);
    //             accs[1].address(addr_a).code(code_a);
    //             accs[2]
    //                 .address(mock::MOCK_ACCOUNTS[2])
    //                 .balance(Word::from(1u64 << 30));
    //         },
    //         |mut txs, accs| {
    //             txs[0].to(accs[1].address).from(accs[2].address);
    //         },
    //         |block, _tx| block,
    //     )
    //     .unwrap();
    //
    //     CircuitTestBuilder::new_from_test_ctx(ctx).run();
    // }

    #[test]
    fn address_gadget_root() {
        test_root_ok();
    }

    // #[test]
    // fn address_gadget_internal() {
    //     test_internal_ok(0x20, 0x00);
    //     test_internal_ok(0x20, 0x10);
    //     test_internal_ok(0x40, 0x20);
    //     test_internal_ok(0x1010, 0xff);
    // }
}
