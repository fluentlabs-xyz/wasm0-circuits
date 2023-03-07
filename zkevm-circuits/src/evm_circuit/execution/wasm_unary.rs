use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::{Error, Expression};

use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToScalar};

use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            CachedRegion,
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use crate::evm_circuit::util::Cell;

#[derive(Clone, Debug)]
pub(crate) struct WasmUnaryGadget<F> {
    same_context: SameContextGadget<F>,
    operand: Cell<F>,
    result: Cell<F>,
    operand_inv: Cell<F>,
    operand_is_zero: Cell<F>,
    is_ctz: Cell<F>,
    is_clz: Cell<F>,
    is_popcnt: Cell<F>,
    is_64bits: Cell<F>,
    boundary: Cell<F>,
    aux1: Cell<F>,
    aux2: Cell<F>,
    lookup_pow: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for WasmUnaryGadget<F> {
    const NAME: &'static str = "WASM_UNARY";

    const EXECUTION_STATE: ExecutionState = ExecutionState::WASM_UNARY;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let operand = cb.alloc_u64();
        let result = cb.alloc_u64();
        let operand_is_zero = cb.alloc_bit_value();
        let operand_inv = cb.alloc_unlimited_value();

        let boundary = cb.alloc_unlimited_value();
        let aux1 = cb.alloc_u64_on_u8();
        let aux2 = cb.alloc_u64_on_u8();

        let is_ctz = cb.alloc_bit_value();
        let is_clz = cb.alloc_bit_value();
        let is_popcnt = cb.alloc_bit_value();
        let is_64bits = cb.alloc_bit_value();

        let lookup_pow = cb.alloc_u64();

        cb.stack_pop(operand.expr());
        cb.stack_push(result.expr());

        cb.require_zero(
            "op_unary: selector",
            is_ctz.expr() + is_clz.expr() + is_popcnt.expr() - 1.expr(),
        );

        cb.require_zeros(
            "op_unary: zero_cond",
            vec![
                operand_is_zero.expr() * operand.expr(),
                operand.expr() * operand_inv.expr() - 1.expr() + operand_is_zero.expr(),
            ],
        );

        pub fn pow_table_encode<F: Field>(
            modulus: Expression<F>,
            power: Expression<F>,
        ) -> Expression<F> {
            modulus * (1u64 << 16).expr() + power
        }

        let bits = 32.expr() + 32.expr() * is_64bits.expr();
        let operand_is_not_zero = 1.expr() - operand_is_zero.expr();

        cb.require_zeros(
            "op_unary: clz",
            vec![
                operand_is_zero.expr() * (result.expr() - (32.expr() + is_64bits.expr() * 32.expr())),
                operand_is_not_zero.clone() * (boundary.expr() + aux1.expr() - operand.expr()),
                operand_is_not_zero.clone() * (aux1.expr() + aux2.expr() + 1.expr() - boundary.expr()),
                operand_is_not_zero.clone() * (lookup_pow.expr() - pow_table_encode(boundary.expr(), bits - result.expr() - 1.expr())),
            ].into_iter().map(|constraint| constraint * is_clz.expr()).collect(),
        );

        cb.require_zeros(
            "op_unary: ctz",
            vec![
                operand_is_zero.expr()
                    * (result.expr()
                    - (32.expr() + is_64bits.expr() * 32.expr())),
                operand_is_not_zero
                    * (aux1.expr() * boundary.expr() * 2.expr()
                    + boundary.expr()
                    - operand.expr()),
                lookup_pow.expr()
                    - pow_table_encode(boundary.expr(), result.expr()),
            ].into_iter().map(|constraint| constraint * is_ctz.expr()).collect(),
        );

        let step_state_transition = StepStateTransition {
            rw_counter: Delta(2.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(0.expr()),
            gas_left: Delta(-OpcodeId::I32Ctz.constant_gas_cost().expr()),
            ..Default::default()
        };

        let opcode = cb.query_cell();
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            operand,
            result,
            operand_inv,
            operand_is_zero,
            is_ctz,
            is_clz,
            is_popcnt,
            is_64bits,
            boundary,
            aux1,
            aux2,
            lookup_pow,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction,
        _call: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let opcode = step.opcode.unwrap();

        let [operand, result] = [step.rw_indices[0], step.rw_indices[1]]
            .map(|idx| block.rws[idx].stack_value());

        self.operand.assign(region, offset, Value::<F>::known(operand.to_scalar().unwrap()))?;
        self.result.assign(region, offset, Value::<F>::known(result.to_scalar().unwrap()))?;
        self.operand_inv.assign(region, offset, Value::<F>::known(F::from(operand.as_u64()).invert().unwrap_or(F::zero())))?;
        self.operand_is_zero.assign(region, offset, Value::<F>::known(F::from(operand.is_zero() as u64)))?;

        let (selector, bits, max) = match opcode {
            OpcodeId::I32Ctz => (&self.is_ctz, 32, 1u128 << 32),
            OpcodeId::I64Ctz => (&self.is_ctz, 64, 1u128 << 64),
            OpcodeId::I32Clz => (&self.is_clz, 32, 1u128 << 32),
            OpcodeId::I64Clz => (&self.is_clz, 64, 1u128 << 64),
            OpcodeId::I32Popcnt => (&self.is_popcnt, 32, 1u128 << 32),
            OpcodeId::I64Popcnt => (&self.is_popcnt, 64, 1u128 << 64),
            _ => unreachable!("not supported opcode for unary operation: {:?}", step.opcode)
        };
        selector.assign(region, offset, Value::known(F::one()))?;

        match opcode {
            OpcodeId::I32Ctz | OpcodeId::I64Ctz => {
                /*
                 * 0000 0100 0000 1000
                 * |____________| |__|
                 *  hd            boundary
                 *
                 */
                let least_one_pos = result.as_u64();
                let hd = operand
                    .as_u64()
                    .checked_shr(least_one_pos as u32 + 1)
                    .unwrap_or(0);

                self.aux1.assign(region, offset, Value::<F>::known(F::from(hd)))?;
                self.boundary.assign(region, offset, Value::<F>::known(F::from(1u64 << least_one_pos)))?;
                self.lookup_pow.assign(region, offset, Value::<F>::known(F::from(least_one_pos)))?;
            }
            OpcodeId::I32Clz | OpcodeId::I64Clz => {
                /*
                 * operand:
                 *   0000 0100 0000 1000
                 * aux1: tail of operand
                 *    i.e.  00 0000 1000
                 * boundary: operand minus tail
                 *    i.e. 100 0000 0000
                 */
                let boundary = max.checked_shr(1 + result.as_u32()).unwrap_or(0) as u64;
                let tail = operand.as_u64() ^ boundary;

                self.boundary.assign(region, offset, Value::<F>::known(F::from(boundary as u64)))?;
                self.aux1.assign(region, offset, Value::<F>::known(F::from(tail)))?;
                self.aux2.assign(region, offset, Value::<F>::known(F::from(boundary - tail - 1)))?;
                if boundary != 0 {
                    self.lookup_pow.assign(region, offset, Value::<F>::known(F::from(bits - result.as_u64() - 1)))?;
                }
            }
            _ => unreachable!("not supported opcode for unary operation: {:?}", step.opcode)
        };

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use eth_types::{bytecode, Bytecode};
    use mock::test_ctx::TestContext;

    use crate::test_util::CircuitTestBuilder;

    fn run_test(bytecode: Bytecode) {
        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        ).run()
    }

    #[test]
    fn test_ctz() {
        run_test(bytecode! {
            // I32Const[0x00100000]
            // I32Ctz
            // Drop
            I32Const[0x00000001]
            I32Ctz
            Drop
            // I32Const[0x80000000]
            // I32Ctz
            // Drop
            // I32Const[0x00000000]
            // I32Ctz
            // Drop
            // I64Const[0x0010000000000000]
            // I64Ctz
            // Drop
            // I64Const[0x0000000000000001]
            // I64Ctz
            // Drop
            // I64Const[0x8000000000000000]
            // I64Ctz
            // Drop
            // I64Const[0x0000000000000000]
            // I64Ctz
            // Drop
        });
    }

    #[test]
    fn test_clz() {
        run_test(bytecode! {
            I32Const[0x00000001]
            I32Clz
            Drop
            I32Const[0x80000000]
            I32Clz
            Drop
            I32Const[0x00000000]
            I32Clz
            Drop
            I32Const[0xffffffff]
            I32Clz
            Drop
            I64Const[0x0000000000000001]
            I64Clz
            Drop
            I64Const[0x8000000000000000]
            I64Clz
            Drop
            I64Const[0x0000000000000000]
            I64Clz
            Drop
            I64Clz[0xffffffffffffffff]
            I64Clz
            Drop
        });
    }

    // #[test]
    // fn test_popcnt() {
    //     run_test(bytecode! {
    //         I32Const[0x00000000]
    //         I32Popcnt
    //         Drop
    //         I32Const[0xffffffff]
    //         I32Popcnt
    //         Drop
    //         I64Const[0x0000000000000000]
    //         I64Popcnt
    //         Drop
    //         I64Const[0xffffffffffffffff]
    //         I64Popcnt
    //         Drop
    //     });
    // }
}
