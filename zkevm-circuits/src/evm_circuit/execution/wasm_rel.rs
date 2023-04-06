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

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {

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
        cb.stack_push(value.expr());

        cb.require_zeros("op_rel: compare diff", vec![
            (lhs.expr() + res_is_lt.expr() * diff.expr()
                        - res_is_gt.expr() * diff.expr()
                        - rhs.expr()),
            (res_is_gt.expr() + res_is_lt.expr() + res_is_eq.expr()
                              - constant_from!(1)),
            (diff.expr() * res_is_eq.expr()),
            (diff.expr() * diff_inv.expr() + res_is_eq.expr()
                                           - constant_from!(1)),
        ]);

        cb.require_zeros("op_rel: compare op", vec![
            (op_is_eq.expr()
                + op_is_ne.expr()
                + op_is_lt.expr()
                + op_is_gt.expr()
                + op_is_le.expr()
                + op_is_ge.expr()
                - constant_from!(1)),
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
            let l_pos_r_pos = (constant_from!(1) - lhs_leading_bit.expr())
                            * (constant_from!(1) - rhs_leading_bit.expr());
            let l_pos_r_neg = (constant_from!(1) - lhs_leading_bit.expr()) * rhs_leading_bit.expr();
            let l_neg_r_pos =
                              lhs_leading_bit.expr() * (constant_from!(1) - rhs_leading_bit.expr());
            let l_neg_r_neg = lhs_leading_bit.expr() * rhs_leading_bit.expr();
            vec![
                op_is_eq.expr() * (res.expr() - res_is_eq.expr()),
                op_is_ne.expr()
                    * (res.expr() - constant_from!(1) + res_is_eq.expr()),
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

        constraint_builder.push(
            "compare op res",
            Box::new(move |meta| {

                let l_pos_r_pos = (constant_from!(1) - lhs_leading_bit.expr(meta))
                    * (constant_from!(1) - rhs_leading_bit.expr(meta));
                let l_pos_r_neg =
                    (constant_from!(1) - lhs_leading_bit.expr(meta)) * rhs_leading_bit.expr(meta);
                let l_neg_r_pos =
                    lhs_leading_bit.expr(meta) * (constant_from!(1) - rhs_leading_bit.expr(meta));
                let l_neg_r_neg = lhs_leading_bit.expr(meta) * rhs_leading_bit.expr(meta);

                vec![

                    op_is_eq.expr(meta) * (res.expr(meta) - res_is_eq.expr(meta)),
                    op_is_ne.expr(meta)
                        * (res.expr(meta) - constant_from!(1) + res_is_eq.expr(meta)),
                    op_is_lt.expr(meta)
                        * (res.expr(meta)
                            - l_neg_r_pos.clone()
                            - l_pos_r_pos.clone() * res_is_lt.expr(meta)
                            - l_neg_r_neg.clone() * res_is_lt.expr(meta)),
                    op_is_le.expr(meta)
                        * (res.expr(meta)
                            - l_neg_r_pos.clone()
                            - l_pos_r_pos.clone() * res_is_lt.expr(meta)
                            - l_neg_r_neg.clone() * res_is_lt.expr(meta)
                            - res_is_eq.expr(meta)),
                    op_is_gt.expr(meta)
                        * (res.expr(meta)
                            - l_pos_r_neg.clone()
                            - l_pos_r_pos.clone() * res_is_gt.expr(meta)
                            - l_neg_r_neg.clone() * res_is_gt.expr(meta)),
                    op_is_ge.expr(meta)
                        * (res.expr(meta)
                            - l_pos_r_neg.clone()
                            - l_pos_r_pos.clone() * res_is_gt.expr(meta)
                            - l_neg_r_neg.clone() * res_is_gt.expr(meta)
                            - res_is_eq.expr(meta)),

                ]
            }),
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
            lookup_stack_read_lhs,
            lookup_stack_read_rhs,
            lookup_stack_write_res,
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

        let [rhs, lhs, value] = [step.rw_indices[0], step.rw_indices[1], step.rw_indices[2]]
            .map(|idx| block.rws[idx].stack_value());

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

    macro_rules! tests_from_data { ($($t:tt)*) => {} }

    tests_from_data! {
      [
        [I32Const [0, 1, 2, -1, -2, 0x80000000]
          [I32GtU, I32GeU, I32LtU, I32LeU, I32Eq, I32Ne, I32GtS, I32GeS, I32LtS, I32LeS]
        ]
        [I64Const [0, 1, 2, -1, -2, -0x100000001, -0x100000002, 0x100000001, 0x100000002]
          [I64GtU, I64GeU, I64LtU, I64LeU, I64Eq, I64Ne, I64GtS, I64GeS, I64LtS, I64LeS]
        ]
      ]
    }

    #[test]
    fn test_i32_gt_u() {
        run_test(bytecode! {
            I32Const 0
            I32Const 0
            I32GtU
            Drop
        });
    }

/*

    #[test]
    fn test_i32_eqz() {
        run_test(bytecode! {
            I32Const[0]
            I32Eqz
            Drop
            I32Const[1]
            I32Eqz
            Drop
        });
    }

    #[test]
    fn test_i64_eqz() {
        run_test(bytecode! {
            I64Const[0]
            I64Eqz
            Drop
            I64Const[1]
            I64Eqz
            Drop
        });
    }
*/
}
