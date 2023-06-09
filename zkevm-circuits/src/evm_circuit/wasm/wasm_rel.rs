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

    is_eight_bytes: Cell<F>,

    lhs: Cell<F>,
    rhs: Cell<F>,
    diff: Cell<F>,

    diff_inv: Cell<F>,
    res_is_eq: Cell<F>,
    res_is_lt: Cell<F>,
    res_is_gt: Cell<F>,
    res: Cell<F>,

    lhs_leading_bit: Cell<F>,
    rhs_leading_bit: Cell<F>,
    lhs_rem_value: Cell<F>,
    lhs_rem_diff: Cell<F>,
    rhs_rem_value: Cell<F>,
    rhs_rem_diff: Cell<F>,

    op_is_eq: Cell<F>,
    op_is_ne: Cell<F>,
    op_is_lt: Cell<F>,
    op_is_gt: Cell<F>,
    op_is_le: Cell<F>,
    op_is_ge: Cell<F>,
    op_is_sign: Cell<F>,

}

impl<F: Field> ExecutionGadget<F> for WasmRelGadget<F> {
    const NAME: &'static str = "WASM_REL";

    const EXECUTION_STATE: ExecutionState = ExecutionState::WASM_REL;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {

        let diff_inv = cb.alloc_unlimited_value();
        let res_is_eq = cb.alloc_bit_value();
        let res_is_lt = cb.alloc_bit_value();
        let res_is_gt = cb.alloc_bit_value();
        let res = cb.alloc_unlimited_value();

        let lhs = cb.alloc_u64();
        let rhs = cb.alloc_u64();
        let diff = cb.alloc_u64();

        let lhs_leading_bit = cb.alloc_bit_value();
        let rhs_leading_bit = cb.alloc_bit_value();
        let lhs_rem_value = cb.alloc_common_range_value();
        let lhs_rem_diff = cb.alloc_common_range_value();
        let rhs_rem_value = cb.alloc_common_range_value();
        let rhs_rem_diff = cb.alloc_common_range_value();

        let op_is_eq = cb.alloc_bit_value();
        let op_is_ne = cb.alloc_bit_value();
        let op_is_lt = cb.alloc_bit_value();
        let op_is_gt = cb.alloc_bit_value();
        let op_is_le = cb.alloc_bit_value();
        let op_is_ge = cb.alloc_bit_value();
        let op_is_sign = cb.alloc_bit_value();

        let is_eight_bytes = cb.alloc_bit_value();

        cb.stack_pop(rhs.expr());
        cb.stack_pop(lhs.expr());
        cb.stack_push(res.expr());

        cb.require_zeros("op_rel: compare diff", vec![
            (lhs.expr() + res_is_lt.expr() * diff.expr()
                        - res_is_gt.expr() * diff.expr()
                        - rhs.expr()),
            (res_is_gt.expr() + res_is_lt.expr() + res_is_eq.expr() - 1.expr()),
            (diff.expr() * res_is_eq.expr()),
            (diff.expr() * diff_inv.expr() + res_is_eq.expr() - 1.expr()),
        ]);

        cb.require_zeros("op_rel: compare op", vec![
            (op_is_eq.expr()
                + op_is_ne.expr()
                + op_is_lt.expr()
                + op_is_gt.expr()
                + op_is_le.expr()
                + op_is_ge.expr()
                - 1.expr()),
        ]);

        /* constraint_builder.push(
            "compare leading bit",
            Box::new(move |meta| {
                let is_four_bytes = constant_from!(1) - is_eight_bytes.expr(meta);
                vec![
                    lhs_leading_bit.expr(meta) * constant_from!(8) + lhs_rem_value.expr(meta)
                        - (is_four_bytes.clone() * lhs.u4_expr(meta, 7)
                            + is_eight_bytes.expr(meta) * lhs.u4_expr(meta, 15))
                            * op_is_sign.expr(meta),
                    rhs_leading_bit.expr(meta) * constant_from!(8) + rhs_rem_value.expr(meta)
                        - (is_four_bytes * rhs.u4_expr(meta, 7)
                            + is_eight_bytes.expr(meta) * rhs.u4_expr(meta, 15))
                            * op_is_sign.expr(meta),
                    (rhs_rem_diff.expr(meta) + rhs_rem_value.expr(meta) - constant_from!(7))
                        * op_is_sign.expr(meta),
                    (lhs_rem_diff.expr(meta) + lhs_rem_value.expr(meta) - constant_from!(7))
                        * op_is_sign.expr(meta),
                ]
            }),
        ); */

        cb.require_zeros("op_rel: compare op res", {
            let l_pos_r_pos = (1.expr() - lhs_leading_bit.expr())
                            * (1.expr() - rhs_leading_bit.expr());
            let l_pos_r_neg = (1.expr() - lhs_leading_bit.expr()) * rhs_leading_bit.expr();
            let l_neg_r_pos =
                              lhs_leading_bit.expr() * (1.expr() - rhs_leading_bit.expr());
            let l_neg_r_neg = lhs_leading_bit.expr() * rhs_leading_bit.expr();
            vec![
                op_is_eq.expr() * (res.expr() - res_is_eq.expr()),
                op_is_ne.expr()
                    * (res.expr() - 1.expr() + res_is_eq.expr()),
                op_is_lt.expr()
                    * (res.expr()
                        - l_neg_r_pos.clone()
                        - l_pos_r_pos.clone() * res_is_lt.expr()
                        - l_neg_r_neg.clone() * res_is_lt.expr()),
                op_is_le.expr()
                    * (res.expr()
                        - l_neg_r_pos.clone()
                        - l_pos_r_pos.clone() * res_is_lt.expr()
                        - l_neg_r_neg.clone() * res_is_lt.expr()
                        - res_is_eq.expr()),
                op_is_gt.expr()
                    * (res.expr()
                        - l_pos_r_neg.clone()
                        - l_pos_r_pos.clone() * res_is_gt.expr()
                        - l_neg_r_neg.clone() * res_is_gt.expr()),
                op_is_ge.expr()
                    * (res.expr()
                        - l_pos_r_neg.clone()
                        - l_pos_r_pos.clone() * res_is_gt.expr()
                        - l_neg_r_neg.clone() * res_is_gt.expr()
                        - res_is_eq.expr()),
            ]
        });

        cb.require_zeros("compare op res", {

                let l_pos_r_pos = (1.expr() - lhs_leading_bit.expr())
                    * (1.expr() - rhs_leading_bit.expr());
                let l_pos_r_neg =
                    (1.expr() - lhs_leading_bit.expr()) * rhs_leading_bit.expr();
                let l_neg_r_pos =
                    lhs_leading_bit.expr() * (1.expr() - rhs_leading_bit.expr());
                let l_neg_r_neg = lhs_leading_bit.expr() * rhs_leading_bit.expr();

                vec![
                    op_is_eq.expr() * (res.expr() - res_is_eq.expr()),
                    op_is_ne.expr()
                        * (res.expr() - 1.expr() + res_is_eq.expr()),
                    op_is_lt.expr()
                        * (res.expr()
                            - l_neg_r_pos.clone()
                            - l_pos_r_pos.clone() * res_is_lt.expr()
                            - l_neg_r_neg.clone() * res_is_lt.expr()),
                    op_is_le.expr()
                        * (res.expr()
                            - l_neg_r_pos.clone()
                            - l_pos_r_pos.clone() * res_is_lt.expr()
                            - l_neg_r_neg.clone() * res_is_lt.expr()
                            - res_is_eq.expr()),
                    op_is_gt.expr()
                        * (res.expr()
                            - l_pos_r_neg.clone()
                            - l_pos_r_pos.clone() * res_is_gt.expr()
                            - l_neg_r_neg.clone() * res_is_gt.expr()),
                    op_is_ge.expr()
                        * (res.expr()
                            - l_pos_r_neg.clone()
                            - l_pos_r_pos.clone() * res_is_gt.expr()
                            - l_neg_r_neg.clone() * res_is_gt.expr()
                            - res_is_eq.expr()),

                ]
            },
        );
 
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
            diff_inv,
            res_is_eq,
            res_is_lt,
            res_is_gt,
            lhs,
            rhs,
            diff,
            //lookup_stack_read_lhs,
            //lookup_stack_read_rhs,
            //lookup_stack_write_res,
            res,
            op_is_eq,
            op_is_ne,
            op_is_lt,
            op_is_gt,
            op_is_le,
            op_is_ge,
            op_is_sign,
            is_eight_bytes,
            lhs_leading_bit,
            rhs_leading_bit,
            lhs_rem_value,
            lhs_rem_diff,
            rhs_rem_value,
            rhs_rem_diff,
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

        let diff = if lhs < rhs { rhs - lhs } else { lhs - rhs };
        self.diff.assign(region, offset, Value::known(diff.to_scalar().unwrap()))?;
        self.diff_inv.assign(region, offset, Value::known(F::from(diff.as_u64()).invert().unwrap_or(F::zero())))?;

        self.res_is_eq.assign(region, offset, Value::known((lhs == rhs).into()))?;
        self.res_is_gt.assign(region, offset, Value::known((lhs > rhs).into()))?;
        self.res_is_lt.assign(region, offset, Value::known((lhs < rhs).into()))?;

        let mut is_32 = true;

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

        let shift: usize = if is_32 {
            I64_REM_SHIFT
        } else {
            I32_REM_SHIFT
        };

        let left_leading_u4: u64 = lhs.0[0] >> (shift as u64);
        let right_leading_u4: u64 = rhs.0[0] >> (shift as u64);

        self.lhs_leading_bit.assign(region, offset, Value::known((left_leading_u4 >> REM_SHIFT != 0).to_scalar().unwrap()))?;
        self.rhs_leading_bit.assign(region, offset, Value::known((right_leading_u4 >> REM_SHIFT != 0).to_scalar().unwrap()))?;
        self.lhs_rem_value.assign(region, offset, Value::known((left_leading_u4 & REM_MASK).to_scalar().unwrap()))?;
        self.lhs_rem_diff.assign(region, offset, Value::known(((left_leading_u4 & REM_MASK) ^ REM_MASK).to_scalar().unwrap()))?;
        self.rhs_rem_value.assign(region, offset, Value::known((right_leading_u4 & REM_MASK).to_scalar().unwrap()))?;
        self.rhs_rem_diff.assign(region, offset, Value::known(((right_leading_u4 & REM_MASK) ^ REM_MASK).to_scalar().unwrap()))?;

/*
        self.value.assign(region, offset, Value::known(value.to_scalar().unwrap()))?;
        self.value_inv.assign(region, offset, Value::known(F::from(value.as_u64()).invert().unwrap_or(F::zero())))?;
        self.res.assign(region, offset, Value::known(res.to_scalar().unwrap()))?;

        match opcode {
            OpcodeId::I64Eqz => {
                let zero_or_one = (value.as_u64() == 0) as u64;
                self.res.assign(region, offset, Value::known(F::from(zero_or_one)))?;
            }
            OpcodeId::I32Eqz => {
                let zero_or_one = (value.as_u32() == 0) as u64;
                self.res.assign(region, offset, Value::known(F::from(zero_or_one)))?;
            }
            _ => unreachable!("not supported opcode: {:?}", opcode),
        };
 
        let is_i64 = matches!(opcode,
            OpcodeId::I64Eqz
        );
        self.is_i64.assign(region, offset, Value::known(F::from(is_i64 as u64)))?;
*/

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
            for lhs in args() {
               for rhs in args() {
                    run_test(bytecode! {
                      $Const[lhs]
                      $Const[rhs]
                      $op
                      Drop
                    });
                }
            }
        }
    }

    macro_rules! tests_from_data {
        ([$( [$Const:ident [$($op:ident),*] [$($t:tt)*]] )*]) => {
            #[allow(non_snake_case)]
            mod generated_tests {
                use super::*;
                $(mod $Const {
                    use super::*;
                    fn args() -> Vec<i64> {
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
