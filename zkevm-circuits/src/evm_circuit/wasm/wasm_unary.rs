use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::{Error, Expression};

use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToScalar};

use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        table::{FixedTableTag, Lookup},
        step::ExecutionState,
        util::{
            CachedRegion,
            common_gadget::SameContextGadget,
            constraint_builder::{StepStateTransition, Transition::Delta},
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use crate::evm_circuit::util::Cell;
use crate::evm_circuit::util::constraint_builder::EVMConstraintBuilder;

#[derive(Clone, Debug)]
pub(crate) struct WasmUnaryGadget<F> {
    same_context: SameContextGadget<F>,
    operand: Cell<F>,
    result: Cell<F>,
    is_ctz: Cell<F>,
    is_clz: Cell<F>,
    is_popcnt: Cell<F>,
    is_64bits: Cell<F>,
    arg_limbs: [Cell<F>; 8],
    terms: [Cell<F>; 4],
}

impl<F: Field> ExecutionGadget<F> for WasmUnaryGadget<F> {
    const NAME: &'static str = "WASM_UNARY";

    const EXECUTION_STATE: ExecutionState = ExecutionState::WASM_UNARY;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let operand = cb.alloc_u64();
        let result = cb.alloc_u64();

        let is_ctz = cb.alloc_bit_value();
        let is_clz = cb.alloc_bit_value();
        let is_popcnt = cb.alloc_bit_value();
        let is_64bits = cb.alloc_bit_value();
        let is_32bits = || 1.expr() - is_64bits.expr();

        let arg_limbs = [cb.alloc_u64(), cb.alloc_u64(), cb.alloc_u64(), cb.alloc_u64(),
                         cb.alloc_u64(), cb.alloc_u64(), cb.alloc_u64(), cb.alloc_u64()];
        let terms = [cb.alloc_u64(), cb.alloc_u64(), cb.alloc_u64(), cb.alloc_u64()];

        cb.stack_pop(operand.expr());
        cb.stack_push(result.expr());

        for i in 0..4 {
            let even = || arg_limbs[i*2].expr();
            let odd = || arg_limbs[i*2+1].expr();
            cb.add_lookup("Using Ctz fixed table", Lookup::Fixed {
                tag: FixedTableTag::Ctz.expr(),
                values: [even() * is_ctz.expr(), odd() * is_ctz.expr(),
                         terms[i].expr() * is_ctz.expr() + 16.expr() * (1.expr() - is_ctz.expr())],
            });
            cb.add_lookup("Using Clz fixed table", Lookup::Fixed {
                tag: FixedTableTag::Clz.expr(),
                values: [even() * is_clz.expr(), odd() * is_clz.expr(),
                         terms[i].expr() * is_clz.expr() + 16.expr() * (1.expr() - is_clz.expr())],
            });
            cb.add_lookup("Using Popcnt fixed table", Lookup::Fixed {
                tag: FixedTableTag::Popcnt.expr(),
                values: [even() * is_popcnt.expr(), odd() * is_popcnt.expr(),
                         terms[i].expr() * is_popcnt.expr()],
            });
        }

        cb.add_lookup("Using CzOut fixed table for Ctz", Lookup::Fixed {
            tag: FixedTableTag::CzOut.expr(),
            values: [(terms[0].expr() + terms[1].expr() * 17.expr()) * is_ctz.expr(),
                     (terms[2].expr() + terms[3].expr() * 17.expr()) * is_64bits.expr() * is_ctz.expr(),
                     result.expr() * is_ctz.expr()],
        });

        cb.add_lookup("Using CzOut fixed table for Clz", Lookup::Fixed {
            tag: FixedTableTag::CzOut.expr(),
            values: [(
                         (terms[3].expr() + terms[2].expr() * 17.expr()) * is_64bits.expr() +
                         (terms[1].expr() + terms[0].expr() * 17.expr()) * is_32bits()
                     ) * is_clz.expr(),
                     (terms[1].expr() + terms[0].expr() * 17.expr()) * is_64bits.expr() * is_clz.expr(),
                     result.expr() * is_clz.expr()],
        });

        cb.require_zero(
            "op_unary: selector",
            is_ctz.expr() + is_clz.expr() + is_popcnt.expr() - 1.expr(),
        );

        cb.require_zeros(
            "op_unary: argument from limbs",
            vec![{
                let mut out = arg_limbs[0].expr();
                for i in 1..8 {
                  out = out + arg_limbs[i].expr() * (1_u64 << i*8).expr();
                }
                out - operand.expr()
            }],
        );

        cb.require_zeros(
            "op_unary: popcnt",
            vec![
                ( terms[0].expr() + terms[1].expr() + terms[2].expr() + terms[3].expr()
                - result.expr() ) * is_popcnt.expr()
            ],
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
            is_ctz,
            is_clz,
            is_popcnt,
            is_64bits,
            arg_limbs,
            terms,
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
        self.is_64bits.assign(region, offset, Value::<F>::known(F::from(bits == 64)))?;

        for idx in 0..4 {
            let pair = (operand.0[0] >> (idx * 16)) & 0xffff;
            let even = pair & 0xff;
            let odd = pair >> 8;
            self.arg_limbs[idx*2].assign(region, offset, Value::<F>::known(F::from(even)))?;
            self.arg_limbs[idx*2+1].assign(region, offset, Value::<F>::known(F::from(odd)))?;
            match opcode {
                OpcodeId::I32Ctz | OpcodeId::I64Ctz => {
                    self.terms[idx].assign(region, offset, Value::<F>::known(F::from(bitintr::Tzcnt::tzcnt(pair as u16) as u64)))?;
                }
                OpcodeId::I32Clz | OpcodeId::I64Clz => {
                    self.terms[idx].assign(region, offset, Value::<F>::known(F::from(bitintr::Lzcnt::lzcnt(pair as u16) as u64)))?;
                }
                OpcodeId::I32Popcnt | OpcodeId::I64Popcnt => {
                    self.terms[idx].assign(region, offset, Value::<F>::known(F::from(bitintr::Popcnt::popcnt(pair))))?;
                }
                _ => unreachable!("not supported opcode for unary operation: {:?}", step.opcode)
            }
        }

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
            I32Const[0x00100000]
            I32Ctz
            Drop
            I32Const[0x00000001]
            I32Ctz
            Drop
            I32Const[0x80000000]
            I32Ctz
            Drop
            I32Const[0x00000000]
            I32Ctz
            Drop
            I64Const[0x0010000000000000]
            I64Ctz
            Drop
            I64Const[0x0000000000000001]
            I64Ctz
            Drop
            I64Const[0x8000000000000000]
            I64Ctz
            Drop
            I64Const[0x0000000000000000]
            I64Ctz
            Drop
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
            I64Const[0xffffffffffffffff]
            I64Clz
            Drop
        });
    }

    #[test]
    fn test_popcnt32() {
        run_test(bytecode! {
            I32Const[0x00000000]
            I32Popcnt
            Drop
            I32Const[0xffffffff]
            I32Popcnt
            Drop
        });
    }

    #[test]
    fn test_popcnt64() {
        run_test(bytecode! {
            I64Const[0x0000000000000000]
            I64Popcnt
            Drop
            I64Const[0xffffffffffffffff]
            I64Popcnt
            Drop
        });
    }
}
