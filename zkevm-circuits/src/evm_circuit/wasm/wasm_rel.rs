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

    // Neg version of aruments is used to reconstruct it from limbs than `is_neg` makes sense.
    lhs: Cell<F>,
    is_neg_lhs: Cell<F>,
    neg_lhs: Cell<F>,
    rhs: Cell<F>,
    is_neg_rhs: Cell<F>,
    neg_rhs: Cell<F>,

    // This limbs comes from absolute value.
    // So logic is to compare `is_neg` bits, and if it same than limbs can be used.
    lhs_limbs: [Cell<F>; 8],
    rhs_limbs: [Cell<F>; 8],
    neq_terms: [Cell<F>; 8],
    out_terms: [Cell<F>; 8],
    res: Cell<F>,

    op_is_32bit: Cell<F>,
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
        let is_neg_lhs = cb.alloc_bit_value();
        let neg_lhs = cb.alloc_u64();
        let rhs = cb.alloc_u64();
        let is_neg_rhs = cb.alloc_bit_value();
        let neg_rhs = cb.alloc_u64();
        let res = cb.alloc_u64();

        let op_is_32bit = cb.alloc_bit_value();
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

        // Is must be three ones (without any zero), to be on same negative side.
        let sign_and_one_side = || op_is_sign.expr() * is_neg_lhs.expr() * is_neg_rhs.expr();
        // This logic is exclusive to previous one.
        let positive = || 1.expr() - op_is_sign.expr();
        let enable_case = || sign_and_one_side() + positive();
        let enable = || ( op_is_gt.expr() + op_is_ge.expr() + op_is_lt.expr() + op_is_le.expr() ) * enable_case();
        let code = || 1.expr() * op_is_gt.expr() + 2.expr() * op_is_ge.expr() +
                      3.expr() * op_is_lt.expr() + 4.expr() * op_is_le.expr();
        // Means that fixed lookup table is disabled, and we can just use bits of negativity to make result.
        let disabled = || 1.expr() - enable();

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

        cb.require_zeros(
            "op_rel: arguments from limbs", {
            let abs_lhs = || {
                let mut lhs_expr = lhs_limbs[0].expr();
                for i in 1..8 {
                    lhs_expr = lhs_expr + lhs_limbs[i].expr() * (1_u64 << i*8).expr();
                }
                lhs_expr
            };
            let abs_rhs = || {
                let mut rhs_expr = rhs_limbs[0].expr();
                for i in 1..8 {
                    rhs_expr = rhs_expr + rhs_limbs[i].expr() * (1_u64 << i*8).expr();
                }
                rhs_expr
            };
            vec![
                ( abs_lhs() - lhs.expr() ) * (1.expr() - is_neg_lhs.expr()),
                ( abs_lhs() - neg_lhs.expr() ) * is_neg_lhs.expr(),
                ( abs_rhs() - rhs.expr() ) * (1.expr() - is_neg_rhs.expr()),
                ( abs_rhs() - neg_rhs.expr() ) * is_neg_rhs.expr(),
            ]},
        );

        let modular_zero32 = || 1.expr() + 0xffffffff_u64.expr();
        let modular_zero64 = || 1.expr() + 0xffffffff_ffffffff_u64.expr();

        cb.require_zeros("op_rel: neg version is correct", vec![
            ( neg_lhs.expr() + lhs.expr() - modular_zero32() ) * is_neg_lhs.expr() * op_is_32bit.expr(),
            ( neg_rhs.expr() + rhs.expr() - modular_zero32() ) * is_neg_rhs.expr() * op_is_32bit.expr(),
            ( neg_lhs.expr() + lhs.expr() - modular_zero64() ) * is_neg_lhs.expr() * (1.expr() - op_is_32bit.expr()),
            ( neg_rhs.expr() + rhs.expr() - modular_zero64() ) * is_neg_rhs.expr() * (1.expr() - op_is_32bit.expr()),
        ]);

        cb.require_zeros("op_rel: if 32bit then limbs must be zero", vec![
            {
              let mut check = 0.expr();
              for i in 4..8 {
                check = check + rhs_limbs[i].expr() + lhs_limbs[i].expr();
              }
              check * op_is_32bit.expr()
            }
        ]);

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
            is_neg_lhs,
            neg_lhs,
            rhs,
            is_neg_rhs,
            neg_rhs,
            lhs_limbs,
            rhs_limbs,
            neq_terms,
            out_terms,
            res,

            op_is_32bit,
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

        let (is_neg_lhs, is_neg_rhs, abs_lhs, abs_rhs) = match opcode {
          OpcodeId::I32GtS | OpcodeId::I32GeS | OpcodeId::I32LtS | OpcodeId::I32LeS => {
              let is_neg_lhs = (lhs.as_u32() <= i32::MAX as u32) as u64;
              let is_neg_rhs = (rhs.as_u32() <= i32::MAX as u32) as u64;
              let abs_lhs = (lhs.as_u32() as i32).abs() as u64;
              let abs_rhs = (lhs.as_u32() as i32).abs() as u64;
              (is_neg_lhs, is_neg_rhs, abs_lhs, abs_rhs)
          }
          OpcodeId::I64GtS | OpcodeId::I64GeS | OpcodeId::I64LtS | OpcodeId::I64LeS => {
              let is_neg_lhs = (lhs.as_u64() <= i64::MAX as u64) as u64;
              let is_neg_rhs = (rhs.as_u64() <= i64::MAX as u64) as u64;
              let abs_lhs = (lhs.as_u64() as i64).abs() as u64;
              let abs_rhs = (lhs.as_u64() as i64).abs() as u64;
              (is_neg_lhs, is_neg_rhs, abs_lhs, abs_rhs)
          }
          _ => (0, 0, lhs.as_u64(), rhs.as_u64())
        };

        self.is_neg_rhs.assign(region, offset, Value::<F>::known(F::from(is_neg_rhs)))?;
        self.is_neg_lhs.assign(region, offset, Value::<F>::known(F::from(is_neg_lhs)))?;
        if is_neg_rhs > 0 { self.neg_rhs.assign(region, offset, Value::<F>::known(F::from(abs_rhs)))?; }
        if is_neg_lhs > 0 { self.neg_lhs.assign(region, offset, Value::<F>::known(F::from(abs_lhs)))?; }

        println!("DEBUG rhs {rhs} lhs {lhs} res {res} abs_rhs {abs_rhs} abs_lhs {abs_lhs}");
        for idx in 0..8 {
          let lhs_limb = (abs_lhs >> (8 * idx)) & 0xff;
          let rhs_limb = (abs_rhs >> (8 * idx)) & 0xff;
          let neq_out = lhs_limb != rhs_limb;
          let (out, _code) = match opcode {
            OpcodeId::I32GtU | OpcodeId::I64GtU | OpcodeId::I32GtS | OpcodeId::I64GtS => (lhs_limb >  rhs_limb, 1),
            OpcodeId::I32GeU | OpcodeId::I64GeU | OpcodeId::I32GeS | OpcodeId::I64GeS => (lhs_limb >= rhs_limb, 2),
            OpcodeId::I32LtU | OpcodeId::I64LtU | OpcodeId::I32LtS | OpcodeId::I64LtS => (lhs_limb <  rhs_limb, 3),
            OpcodeId::I32LeU | OpcodeId::I64LeU | OpcodeId::I32LeS | OpcodeId::I64LeS => (lhs_limb <= rhs_limb, 4),
            _ => (false, 0_u64),
          };
          self.lhs_limbs[idx].assign(region, offset, Value::<F>::known(F::from(lhs_limb)))?;
          self.rhs_limbs[idx].assign(region, offset, Value::<F>::known(F::from(rhs_limb)))?;
          self.neq_terms[idx].assign(region, offset, Value::<F>::known(F::from(neq_out)))?;
          self.out_terms[idx].assign(region, offset, Value::<F>::known(F::from(out)))?;
          println!("DEBUG {idx} {lhs_limb} {rhs_limb} {neq_out} {out}");
        }

        let is_32 = match opcode {
            OpcodeId::I32GtU | OpcodeId::I32GeU | OpcodeId::I32LtU | OpcodeId::I32LeU | OpcodeId::I32Eq | OpcodeId::I32Ne |
            OpcodeId::I32GtS | OpcodeId::I32GeS | OpcodeId::I32LtS | OpcodeId::I32LeS => true,
            _ => false
        };
        self.op_is_32bit.assign(region, offset, Value::known(is_32.into()))?;

        match opcode {
            OpcodeId::I32GtU | OpcodeId::I64GtU => {
              self.op_is_gt.assign(region, offset, Value::known(1.into()))?;
            }
            OpcodeId::I32GeU | OpcodeId::I64GeU => {
              self.op_is_ge.assign(region, offset, Value::known(1.into()))?;
            }
            OpcodeId::I32LtU | OpcodeId::I64LtU => {
              self.op_is_lt.assign(region, offset, Value::known(1.into()))?;
            }
            OpcodeId::I32LeU | OpcodeId::I64LeU => {
              self.op_is_le.assign(region, offset, Value::known(1.into()))?;
            }
            OpcodeId::I32Eq | OpcodeId::I64Eq => {
              self.op_is_eq.assign(region, offset, Value::known(1.into()))?;
            }
            OpcodeId::I32Ne | OpcodeId::I64Ne => {
              self.op_is_ne.assign(region, offset, Value::known(1.into()))?;
            }
            OpcodeId::I32GtS | OpcodeId::I64GtS => {
              self.op_is_sign.assign(region, offset, Value::known(1.into()))?;
              self.op_is_gt.assign(region, offset, Value::known(1.into()))?;
            }
            OpcodeId::I32GeS | OpcodeId::I64GeS => {
              self.op_is_sign.assign(region, offset, Value::known(1.into()))?;
              self.op_is_ge.assign(region, offset, Value::known(1.into()))?;
            }
            OpcodeId::I32LtS | OpcodeId::I64LtS => {
              self.op_is_sign.assign(region, offset, Value::known(1.into()))?;
              self.op_is_lt.assign(region, offset, Value::known(1.into()))?;
            }
            OpcodeId::I32LeS | OpcodeId::I64LeS => {
              self.op_is_sign.assign(region, offset, Value::known(1.into()))?;
              self.op_is_le.assign(region, offset, Value::known(1.into()))?;
            }
            _ => (),
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

    // Idea here is to run only lower triangle of pair matrix, and do four operations at once (four tests inside).
    // If any argument is not exist than test is skipped, also it is skippend out of triangle.
    macro_rules! try_test_by_number {
        ([$Const:ident] [$op:ident] [$n:expr, $m:expr]) => {
            let run = || {
                let i = $n % $m;
                let j = $n / $m;
                if i >= j { return Ok(()) }
                let a = try_get_arg($n % $m)?;
                let b = try_get_arg($n / $m)?;
                run_test(bytecode! {
                    $Const[a] $Const[a] $op Drop
                    $Const[b] $Const[b] $op Drop
                    $Const[a] $Const[b] $op Drop
                    $Const[b] $Const[a] $op Drop
                });
                Ok(())
            };
            let _: Result<(),()> = run();
        }
    }

    macro_rules! tests_from_data {
        ([$( [$Const:ident [$($op:ident),*] [$($t:tt)*]] )*]) => {
            #[allow(non_snake_case)]
            mod generated_tests {
                use super::*;
                $(mod $Const {
                    use super::*;
                    fn try_get_arg(idx: usize) -> Result<i64, ()> {
                      vec![$($t)*].get(idx).ok_or(()).map(|x| *x)
                    }
                    $(mod $op {
                      use super::*;
                      use seq_macro::seq;
                      seq!(N in 0..100 {
                        #[test] fn test_~N() { try_test_by_number! { [$Const] [$op] [N, 10] } }
                      });
                    })*
                })*
            }
        }
    }

    // Example command to run test: cargo test generated_tests::I32Const::I32GtU::test_10
    // Encoding of test number is decimal pair by ten, ones and tens, a + b * 10
    // For example test_10 means lhs_index is 1 and rhs_index is 0
    tests_from_data! {
      [
        [I32Const
          [I32GtU, I32GeU, I32LtU, I32LeU, I32Eq, I32Ne, I32GtS, I32GeS, I32LtS, I32LeS]
          [0, 1, 2, -1, -2, 0x80000000]
        ]
        [I64Const
          [I64GtU, I64GeU, I64LtU, I64LeU, I64Eq, I64Ne, I64GtS, I64GeS, I64LtS, I64LeS]
          [0, 1, 2, -1, -2, -0x100000001, -0x100000002, 0x100000001, 0x100000002]
        ]
      ]
    }

}
