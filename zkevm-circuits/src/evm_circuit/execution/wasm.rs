use std::marker::PhantomData;
use halo2_proofs::plonk::{Circuit, ConstraintSystem, Error};

use bus_mapping::evm::OpcodeId;
use eth_types::Field;

use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            CachedRegion,
            Cell,
            common_gadget::SameContextGadget, constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};

#[derive(Clone, Debug)]
pub(crate) struct WasmGadget<F> {
    _phantom: PhantomData<F>,
}

impl<F: Field> ExecutionGadget<F> for WasmGadget<F> {
    const NAME: &'static str = "WASM";

    const EXECUTION_STATE: ExecutionState = ExecutionState::WASM;

    fn configure(_cb: &mut ConstraintBuilder<F>) -> Self {
        panic!("not implemented");
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction,
        _: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use eth_types::{bytecode, Word};
    use mock::TestContext;

    use crate::{evm_circuit::test::rand_word, test_util::CircuitTestBuilder};

    fn test_ok(value: Word) {
        let bytecode = bytecode! {
            PUSH32(value)
            POP
            STOP
        };

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
            .run();
    }

    #[test]
    fn pop_gadget_simple() {
        test_ok(Word::from(0x030201));
    }

    #[test]
    fn pop_gadget_rand() {
        test_ok(rand_word());
    }

    fn test_stack_underflow(value: Word) {
        let bytecode = bytecode! {
            PUSH32(value)
            POP
            POP
            STOP
        };

        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        )
            .run();
    }

    #[test]
    fn pop_gadget_underflow() {
        test_stack_underflow(Word::from(0x030201));
        test_stack_underflow(Word::from(0xab));
    }
}
