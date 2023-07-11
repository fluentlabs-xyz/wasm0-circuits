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
            constraint_builder::{ConstrainBuilderCommon, StepStateTransition, Transition::Delta},
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use crate::evm_circuit::util::Cell;
use crate::evm_circuit::util::constraint_builder::EVMConstraintBuilder;

const REM_SHIFT: usize = 3usize;
const REM_MASK: u64 = (1u64 << REM_SHIFT) - 1u64;
const I64_REM_SHIFT: usize = 60usize;
const I32_REM_SHIFT: usize = 28usize;

#[derive(Clone, Debug)]
pub(crate) struct WasmRelGadget<F> {
    same_context: SameContextGadget<F>,

    lhs: Cell<F>,
    rhs: Cell<F>,

    // This limbs comes from absolute value.
    lhs_limbs: [Cell<F>; 8],
    rhs_limbs: [Cell<F>; 8],
    neq_terms: [Cell<F>; 8],
    out_terms: [Cell<F>; 8],
    res: Cell<F>,

    op_is_eq: Cell<F>,
    op_is_ne: Cell<F>,
    op_is_lt: Cell<F>,
    op_is_gt: Cell<F>,
    op_is_le: Cell<F>,
    op_is_ge: Cell<F>,
    op_is_sign: Cell<F>,

}


// Idea it to make comparsion for each limb, but only one result is correct.
// To filter this correct result, `ClzFilter` is used.
// Logic is skip equal limbs until we found difference.
impl<F: Field> ExecutionGadget<F> for WasmRelGadget<F> {
    const NAME: &'static str = "WASM_REL";

    const EXECUTION_STATE: ExecutionState = ExecutionState::WASM_REL;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {

        let lhs = cb.alloc_u64();
        let rhs = cb.alloc_u64();
        let res = cb.alloc_u64();

        let op_is_eq = cb.alloc_bit_value();
        let op_is_ne = cb.alloc_bit_value();
        let op_is_lt = cb.alloc_bit_value();
        let op_is_gt = cb.alloc_bit_value();
        let op_is_le = cb.alloc_bit_value();
        let op_is_ge = cb.alloc_bit_value();
        let op_is_sign = cb.alloc_bit_value();

        let rhs_limbs = [cb.alloc_u64(), cb.alloc_u64(), cb.alloc_u64(), cb.alloc_u64(),
                         cb.alloc_u64(), cb.alloc_u64(), cb.alloc_u64(), cb.alloc_u64()];

        let lhs_limbs = [cb.alloc_u64(), cb.alloc_u64(), cb.alloc_u64(), cb.alloc_u64(),
                         cb.alloc_u64(), cb.alloc_u64(), cb.alloc_u64(), cb.alloc_u64()];

        let neq_terms = [cb.alloc_u64(), cb.alloc_u64(), cb.alloc_u64(), cb.alloc_u64(),
                         cb.alloc_u64(), cb.alloc_u64(), cb.alloc_u64(), cb.alloc_u64()];

        let out_terms = [cb.alloc_u64(), cb.alloc_u64(), cb.alloc_u64(), cb.alloc_u64(),
                         cb.alloc_u64(), cb.alloc_u64(), cb.alloc_u64(), cb.alloc_u64()];

        let enable = || op_is_gt.expr() + op_is_ge.expr() + op_is_lt.expr() + op_is_le.expr();
        let code = || 1.expr() * op_is_gt.expr() + 2.expr() * op_is_ge.expr() +
                      3.expr() * op_is_lt.expr() + 4.expr() * op_is_le.expr();

        for idx in 0..8 {
            cb.add_lookup("Using OpRel fixed table", Lookup::Fixed {
                tag: FixedTableTag::OpRel.expr(),
                values: [lhs_limbs[idx].expr() * enable(),
                         (rhs_limbs[idx].expr() + 256.expr() * code()) * enable(),
                         out_terms[idx].expr() * enable()],
            });
            cb.add_lookup("Using OpRel fixed table for neq terms", Lookup::Fixed {
                tag: FixedTableTag::OpRel.expr(),
                values: [lhs_limbs[idx].expr() * enable(),
                         rhs_limbs[idx].expr() * enable(),
                         neq_terms[idx].expr() * enable()],
            });
        }

        let mut neq_bits = neq_terms[0].expr();
        for neq_i in 1..8 {
            neq_bits = neq_bits + (1 << neq_i).expr() * neq_terms[neq_i].expr();
        }
        let mut out_bits = out_terms[0].expr();
        for out_i in 1..8 {
            out_bits = out_bits + (1 << out_i).expr() * out_terms[out_i].expr();
        }
        cb.add_lookup("Using ClzFilter fixed table", Lookup::Fixed {
            tag: FixedTableTag::ClzFilter.expr(),
            values: [neq_bits * enable(),
                     out_bits.expr() * enable(),
                     res.expr() * enable()],
        });

        cb.stack_pop(rhs.expr());
        cb.stack_pop(lhs.expr());
        cb.stack_push(res.expr());

        let opcode = cb.query_cell();

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(2.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(0.expr()),
            // TODO: Change opcode.
            gas_left: Delta(-OpcodeId::I32Eqz.constant_gas_cost().expr()),
            ..StepStateTransition::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            lhs,
            rhs,
            lhs_limbs,
            rhs_limbs,
            neq_terms,
            out_terms,
            res,

            op_is_eq,
            op_is_ne,
            op_is_lt,
            op_is_gt,
            op_is_le,
            op_is_ge,
            op_is_sign,
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

        let [rhs, lhs, res] = [step.rw_indices[0], step.rw_indices[1], step.rw_indices[2]]
            .map(|idx| block.rws[idx].stack_value());

        self.rhs.assign(region, offset, Value::known(rhs.to_scalar().unwrap()))?;
        self.lhs.assign(region, offset, Value::known(lhs.to_scalar().unwrap()))?;
        self.res.assign(region, offset, Value::known(res.to_scalar().unwrap()))?;

        let mut is_32 = true;

        match opcode {
          OpcodeId::I32GtU | OpcodeId::I32GeU | OpcodeId::I32LtU | OpcodeId::I32LeU |
          OpcodeId::I64GtU | OpcodeId::I64GeU | OpcodeId::I64LtU | OpcodeId::I64LeU => {
            for idx in 0..8 {
              let lhs_limb = (lhs.0[0] >> (8 * idx)) & 0xff;
              let rhs_limb = (rhs.0[0] >> (8 * idx)) & 0xff;
              let neq_out = lhs_limb != rhs_limb;
              let (out, _code) = match opcode {
                OpcodeId::I32GtU | OpcodeId::I64GtU => (lhs_limb >  rhs_limb, 1),
                OpcodeId::I32GeU | OpcodeId::I64GeU => (lhs_limb >= rhs_limb, 2),
                OpcodeId::I32LtU | OpcodeId::I64LtU => (lhs_limb <  rhs_limb, 3),
                OpcodeId::I32LeU | OpcodeId::I64LeU => (lhs_limb <= rhs_limb, 4),
                _ => unreachable!(),
              };
              self.lhs_limbs[idx].assign(region, offset, Value::<F>::known(F::from(lhs_limb)))?;
              self.rhs_limbs[idx].assign(region, offset, Value::<F>::known(F::from(rhs_limb)))?;
              self.neq_terms[idx].assign(region, offset, Value::<F>::known(F::from(neq_out)))?;
              self.out_terms[idx].assign(region, offset, Value::<F>::known(F::from(out)))?;
            }
          }
          OpcodeId::I32GtS | OpcodeId::I32GeS | OpcodeId::I32LtS | OpcodeId::I32LeS |
          OpcodeId::I64GtS | OpcodeId::I64GeS | OpcodeId::I64LtS | OpcodeId::I64LeS => {
          }
          _ => ()
        }

        match opcode {
            OpcodeId::I32GtU => {
              self.op_is_gt.assign(region, offset, Value::known(1.into()))?;
            }
            OpcodeId::I32GeU => {
              self.op_is_ge.assign(region, offset, Value::known(1.into()))?;
            }
            OpcodeId::I32LtU => {
              self.op_is_lt.assign(region, offset, Value::known(1.into()))?;
            }
            OpcodeId::I32LeU => {
              self.op_is_le.assign(region, offset, Value::known(1.into()))?;
            }
            OpcodeId::I32Eq => {
              self.op_is_eq.assign(region, offset, Value::known(1.into()))?;
            }
            OpcodeId::I32Ne => {
              self.op_is_ne.assign(region, offset, Value::known(1.into()))?;
            }
            OpcodeId::I32GtS => {
              self.op_is_sign.assign(region, offset, Value::known(1.into()))?;
              self.op_is_gt.assign(region, offset, Value::known(1.into()))?;
            }
            OpcodeId::I32GeS => {
              self.op_is_sign.assign(region, offset, Value::known(1.into()))?;
              self.op_is_ge.assign(region, offset, Value::known(1.into()))?;
            }
            OpcodeId::I32LtS => {
              self.op_is_sign.assign(region, offset, Value::known(1.into()))?;
              self.op_is_lt.assign(region, offset, Value::known(1.into()))?;
            }
            OpcodeId::I32LeS => {
              self.op_is_sign.assign(region, offset, Value::known(1.into()))?;
              self.op_is_le.assign(region, offset, Value::known(1.into()))?;
            }
            _ => unreachable!()
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use eth_types::{bytecode, Bytecode};
    use mock::TestContext;

    use crate::test_util::CircuitTestBuilder;

    fn run_test(bytecode: Bytecode) {
        CircuitTestBuilder::new_from_test_ctx(
            TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
        ).run()
    }

    macro_rules! tests_from_data_lhs_rhs_matrix {
        ([$Const:ident] [$op:ident]) => {
            let lhs = make_args();
            let rhs = make_args();
            //for rhs in args() {
                run_test(bytecode! {
                   $Const[lhs[0]]
                   $Const[rhs[0]]
                   $op
                   Drop
                   $Const[lhs[1]]
                   $Const[rhs[1]]
                   $op
                   Drop
                   $Const[lhs[0]]
                   $Const[rhs[1]]
                   $op
                   Drop
                   $Const[lhs[1]]
                   $Const[rhs[0]]
                   $op
                   Drop
                });
            //}
        }
    }

    macro_rules! tests_from_data {
        ([$( [$Const:ident [$($op:ident),*] [$($t:tt)*]] )*]) => {
            #[allow(non_snake_case)]
            mod generated_tests {
                use super::*;
                $(mod $Const {
                    use super::*;
                    fn make_args() -> Vec<i64> {
                      vec![$($t)*]
                    }
                    $(#[test]
                      fn $op() {
                        tests_from_data_lhs_rhs_matrix! { [$Const] [$op] }
                    })*
                })*
            }
        }
    }

    // Example command to run test: cargo test generated_tests::I32Const::I32GtU
    tests_from_data! {
      [
        [I32Const
          //[I32GtU, I32GeU, I32LtU, I32LeU, I32Eq, I32Ne, I32GtS, I32GeS, I32LtS, I32LeS]
          [I32GtU, I32GeU, I32LtU, I32LeU]
          [0, 1, 2, -1, -2, 0x80000000]
        ]
        [I64Const
          //[I64GtU, I64GeU, I64LtU, I64LeU, I64Eq, I64Ne, I64GtS, I64GeS, I64LtS, I64LeS]
          [I64GtU, I64GeU, I64LtU, I64LeU]
          [0, 1, 2, -1, -2, -0x100000001, -0x100000002, 0x100000001, 0x100000002]
        ]
      ]
    }

}
