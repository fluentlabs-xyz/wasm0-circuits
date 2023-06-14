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

#[derive(Clone, Debug)]
pub(crate) struct WasmBinGadget<F> {
    same_context: SameContextGadget<F>,
    lhs: Cell<F>,
    rhs: Cell<F>,
    res: Cell<F>,
    is_add: Cell<F>,
    is_sub: Cell<F>,
    is_mul: Cell<F>,
    is_div_u: Cell<F>,
    is_rem_u: Cell<F>,
    is_div_s: Cell<F>,
    is_rem_s: Cell<F>,
    div_rem_s_is_lhs_pos: Cell<F>,
    div_rem_s_is_rhs_pos: Cell<F>,
    aux1: Cell<F>,
    aux2: Cell<F>,
    aux3: Cell<F>,
    is_64bits: Cell<F>,
}

impl<F: Field> ExecutionGadget<F> for WasmBinGadget<F> {
    const NAME: &'static str = "WASM_BIN";

    const EXECUTION_STATE: ExecutionState = ExecutionState::WASM_BIN;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let lhs = cb.query_cell();
        let rhs = cb.query_cell();
        let res = cb.query_cell();

        let is_add = cb.alloc_bit_value();
        let is_sub = cb.alloc_bit_value();
        let is_mul = cb.alloc_bit_value();
        let is_div_u = cb.alloc_bit_value();
        let is_rem_u = cb.alloc_bit_value();
        let is_div_s = cb.alloc_bit_value();
        let is_rem_s = cb.alloc_bit_value();

        let div_rem_s_is_lhs_pos = cb.alloc_bit_value();
        let div_rem_s_is_rhs_pos = cb.alloc_bit_value();

        let aux1 = cb.alloc_u64_on_u8();
        let aux2 = cb.alloc_u64_on_u8();
        let aux3 = cb.alloc_u64_on_u8();

        // let lhs_flag = cb.alloc_bit_value();
        // let rhs_flag = cb.alloc_bit_value();

        // let lhs_flag_helper = cb.alloc_common_range_value();
        // let lhs_flag_helper_diff = cb.alloc_common_range_value();
        // let rhs_flag_helper = cb.alloc_common_range_value();
        // let rhs_flag_helper_diff = cb.alloc_common_range_value();
        // let d_flag_helper_diff = cb.alloc_common_range_value();

        let is_64bits = cb.alloc_bit_value();

        cb.stack_pop(rhs.expr());
        cb.stack_pop(lhs.expr());
        cb.stack_push(res.expr());

        // TODO: Analyze the security of such an addition. In theory, if all the `is` variables have
        // already been proven as the only possible one or zero, then there is no problem.
        // If `alloc_bit_value` does the job. If not, then fraud is possible.
        cb.require_equal(
            "binop: selector",
            is_add.expr() + is_sub.expr() + is_mul.expr() + is_div_u.expr() + is_rem_u.expr() + is_div_s.expr() + is_rem_s.expr(),
            1.expr(),
        );

        let modulus = Expression::Constant(F::from(1u64 << 32usize)) +
            Expression::Constant(F::from((u32::MAX as u64) << 32usize)) * is_64bits.expr();

        cb.require_zero(
            "binop: add constraint",
            (lhs.expr() + rhs.expr() - res.expr() - aux1.expr() * modulus.clone()) * is_add.expr(),
        );

        cb.require_zero(
            "binop: sub constraint",
            (rhs.expr() + res.expr() - lhs.expr() - aux1.expr() * modulus.clone()) * is_sub.expr(),
        );

        cb.require_zero(
            "binop: mul constraint",
            (lhs.expr() * rhs.expr() - aux1.expr() * modulus.clone() - res.expr()) * is_mul.expr(),
        );

        cb.require_zeros("div_u/rem_u constraints", vec![
            (lhs.expr() - rhs.expr() * aux1.expr() - aux2.expr()) * (is_rem_u.expr() + is_div_u.expr()),
            (aux2.expr() + aux3.expr() + 1.expr() - rhs.expr()) * (is_rem_u.expr() + is_div_u.expr()),
            (res.expr() - aux1.expr()) * is_div_u.expr(),
            (res.expr() - aux2.expr()) * is_rem_u.expr(),
        ]);

        let pp_case = || div_rem_s_is_lhs_pos.expr() * div_rem_s_is_rhs_pos.expr();
        cb.require_zeros("div_s/rem_s constraints pp case", vec![
            (lhs.expr() - rhs.expr() * aux1.expr() - aux2.expr()) * (is_rem_s.expr() + is_div_s.expr()) * pp_case(),
            (aux2.expr() + aux3.expr() + 1.expr() - rhs.expr()) * (is_rem_s.expr() + is_div_s.expr()) * pp_case(),
            (res.expr() - aux1.expr()) * is_div_s.expr() * pp_case(),
            (res.expr() - aux2.expr()) * is_rem_s.expr() * pp_case(),
        ]);

        let pn_case = || div_rem_s_is_lhs_pos.expr() * (1.expr() - div_rem_s_is_rhs_pos.expr());
        cb.require_zeros("div_s/rem_s constraints pn case", vec![
            //(lhs.expr() - rhs.expr() * aux1.expr() - aux2.expr()) * (is_rem_s.expr() + is_div_s.expr()) * pn_case(),
            //(aux2.expr() + aux3.expr() + 1.expr() - rhs.expr()) * (is_rem_s.expr() + is_div_s.expr()) * pn_case(),
            (res.expr() - aux1.expr()) * is_div_s.expr() * pn_case(),
            (res.expr() - aux2.expr()) * is_rem_s.expr() * pn_case(),
        ]);

        let np_case = || (1.expr() - div_rem_s_is_lhs_pos.expr()) * div_rem_s_is_rhs_pos.expr();
        cb.require_zeros("div_s/rem_s constraints pn case", vec![
            //(lhs.expr() - rhs.expr() * aux1.expr() - aux2.expr()) * (is_rem_s.expr() + is_div_s.expr()) * np_case(),
            //(aux2.expr() + aux3.expr() + 1.expr() - rhs.expr()) * (is_rem_s.expr() + is_div_s.expr()) * np_case(),
            (res.expr() - aux1.expr()) * is_div_s.expr() * np_case(),
            (res.expr() - aux2.expr()) * is_rem_s.expr() * np_case(),
        ]);

        let nn_case = || (1.expr() - div_rem_s_is_lhs_pos.expr()) * (1.expr() - div_rem_s_is_rhs_pos.expr());
        cb.require_zeros("div_s/rem_s constraints pn case", vec![
            //(lhs.expr() - rhs.expr() * aux1.expr() - aux2.expr()) * (is_rem_s.expr() + is_div_s.expr()) * nn_case(),
            //(aux2.expr() + aux3.expr() + 1.expr() - rhs.expr()) * (is_rem_s.expr() + is_div_s.expr()) * nn_case(),
            (res.expr() - aux1.expr()) * is_div_s.expr() * nn_case(),
            (res.expr() - aux2.expr()) * is_rem_s.expr() * nn_case(),
        ]);

        // constraint_builder.push(
        //     "binop: div_s/rem_s constraints common",
        //     Box::new(move |meta| {
        //         let enable = is_div_s.expr(meta) + is_rem_s.expr(meta);
        //
        //         let modulus = constant!(bn_to_field(&(BigUint::from(1u64) << 32usize)))
        //             + constant!(bn_to_field(&(BigUint::from((u32::MAX as u64) << 32usize))))
        //             * is_64bits.expr(meta);
        //
        //         let lhs_leading_u4 = lhs.u4_expr(meta, 7)
        //             + (lhs.u4_expr(meta, 15) - lhs.u4_expr(meta, 7)) * is_64bits.expr(meta);
        //         let rhs_leading_u4 = rhs.u4_expr(meta, 7)
        //             + (rhs.u4_expr(meta, 15) - rhs.u4_expr(meta, 7)) * is_64bits.expr(meta);
        //         let d_leading_u4 = d.u4_expr(meta, 7)
        //             + (d.u4_expr(meta, 15) - d.u4_expr(meta, 7)) * is_64bits.expr(meta);
        //
        //         let normalized_lhs = lhs.expr(meta) * (constant_from!(1) - lhs_flag.expr(meta))
        //             + (modulus.clone() - lhs.expr(meta)) * lhs_flag.expr(meta);
        //         let normalized_rhs = rhs.expr(meta) * (constant_from!(1) - rhs_flag.expr(meta))
        //             + (modulus.clone() - rhs.expr(meta)) * rhs_flag.expr(meta);
        //
        //         let res_flag = lhs_flag.expr(meta) + rhs_flag.expr(meta)
        //             - constant_from!(2) * lhs_flag.expr(meta) * rhs_flag.expr(meta);
        //
        //         vec![
        //             lhs_leading_u4
        //                 - lhs_flag.expr(meta) * constant_from!(8)
        //                 - lhs_flag_helper.expr(meta),
        //             lhs_flag_helper.expr(meta) + lhs_flag_helper_diff.expr(meta)
        //                 - constant_from!(7),
        //             rhs_leading_u4
        //                 - rhs_flag.expr(meta) * constant_from!(8)
        //                 - rhs_flag_helper.expr(meta),
        //             rhs_flag_helper.expr(meta) + rhs_flag_helper_diff.expr(meta)
        //                 - constant_from!(7),
        //             // d_flag must be zero if res_flag is zero
        //             (d_leading_u4 + d_flag_helper_diff.expr(meta) - constant_from!(7))
        //                 * (constant_from!(1) - res_flag.clone()),
        //             normalized_lhs - normalized_rhs.clone() * d.expr(meta) - aux1.expr(meta),
        //             aux1.expr(meta) + aux2.expr(meta) + constant_from!(1) - normalized_rhs,
        //         ]
        //             .into_iter()
        //             .map(|x| x * enable.clone())
        //             .collect()
        //     }),
        // );
        //
        // constraint_builder.push(
        //     "binop: div_s constraints res",
        //     Box::new(move |meta| {
        //         let modulus = constant!(bn_to_field(&(BigUint::from(1u64) << 32usize)))
        //             + constant!(bn_to_field(&(BigUint::from((u32::MAX as u64) << 32usize))))
        //             * is_64bits.expr(meta);
        //
        //         let res_flag = lhs_flag.expr(meta) + rhs_flag.expr(meta)
        //             - constant_from!(2) * lhs_flag.expr(meta) * rhs_flag.expr(meta);
        //
        //         vec![
        //             (res.expr(meta) - d.expr(meta))
        //                 * (constant_from!(1) - res_flag.clone())
        //                 * is_div_s.expr(meta),
        //             (res.expr(meta) + d.expr(meta) - modulus.clone())
        //                 * (d.expr(meta) + res.expr(meta))
        //                 * res_flag.clone()
        //                 * is_div_s.expr(meta),
        //         ]
        //     }),
        // );
        //
        // constraint_builder.push(
        //     "binop: rem_s constraints res",
        //     Box::new(move |meta| {
        //         let modulus = constant!(bn_to_field(&(BigUint::from(1u64) << 32usize)))
        //             + constant!(bn_to_field(&(BigUint::from((u32::MAX as u64) << 32usize))))
        //             * is_64bits.expr(meta);
        //
        //         vec![
        //             (res.expr(meta) - aux1.expr(meta))
        //                 * (constant_from!(1) - lhs_flag.expr(meta))
        //                 * is_rem_s.expr(meta),
        //             (res.expr(meta) + aux1.expr(meta) - modulus.clone())
        //                 * (aux1.expr(meta) + res.expr(meta))
        //                 * lhs_flag.expr(meta)
        //                 * is_rem_s.expr(meta),
        //         ]
        //     }),
        // );

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(3.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
            gas_left: Delta(-OpcodeId::I32Add.constant_gas_cost().expr()),
            ..StepStateTransition::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            lhs,
            rhs,
            res,
            is_add,
            is_sub,
            is_mul,
            is_div_u,
            is_rem_u,
            is_div_s,
            is_rem_s,
            div_rem_s_is_lhs_pos,
            div_rem_s_is_rhs_pos,
            aux1,
            aux2,
            aux3,
            is_64bits,
        }
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
        self.same_context.assign_exec_step(region, offset, step)?;

        let opcode = step.opcode.unwrap();

        let [rhs, lhs, res] = [step.rw_indices[0], step.rw_indices[1], step.rw_indices[2]]
            .map(|idx| block.rws[idx].stack_value());

        self.lhs.assign(region, offset, Value::known(lhs.to_scalar().unwrap()))?;
        self.rhs.assign(region, offset, Value::known(rhs.to_scalar().unwrap()))?;
        self.res.assign(region, offset, Value::known(res.to_scalar().unwrap()))?;

        let selector = match opcode {
            OpcodeId::I32Add | OpcodeId::I64Add => &self.is_add,
            OpcodeId::I32Sub | OpcodeId::I64Sub => &self.is_sub,
            OpcodeId::I32Mul | OpcodeId::I64Mul => &self.is_mul,
            OpcodeId::I32DivS | OpcodeId::I64DivS => &self.is_div_s,
            OpcodeId::I32DivU | OpcodeId::I64DivU => &self.is_div_u,
            OpcodeId::I32RemU | OpcodeId::I64RemU => &self.is_rem_u,
            OpcodeId::I32RemS | OpcodeId::I64RemS => &self.is_rem_s,
            _ => unreachable!("not supported opcode: {:?}", opcode),
        };
        selector.assign(region, offset, Value::known(F::one()))?;

        let aux1;
        let mut aux2 = 0u64;
        let mut aux3 = 0u64;

        let mut div_rem_s_is_lhs_pos = 0u64;
        let mut div_rem_s_is_rhs_pos = 0u64;

        match opcode {
            OpcodeId::I32Add => {
                let (_, overflow) = (lhs.as_u32()).overflowing_add(rhs.as_u32());
                aux1 = overflow as u64
            }
            OpcodeId::I64Add => {
                let (_, overflow) = lhs.overflowing_add(rhs);
                aux1 = overflow as u64
            }
            OpcodeId::I32Sub => {
                let (_, overflow) = (lhs.as_u32()).overflowing_sub(rhs.as_u32());
                aux1 = overflow as u64
            }
            OpcodeId::I64Sub => {
                let (_, overflow) = lhs.overflowing_sub(rhs);
                aux1 = overflow as u64
            }
            OpcodeId::I32Mul => {
                let (res2, overflow) = (lhs.as_u64()).overflowing_mul(rhs.as_u64());
                debug_assert!(!overflow, "overflow here is not possible");
                aux1 = res2 >> 32;
            }
            OpcodeId::I64Mul => {
                let (res2, overflow) = (lhs.as_u64() as u128).overflowing_mul(rhs.as_u64() as u128);
                debug_assert!(!overflow, "overflow here is not possible");
                aux1 = (res2 >> 64) as u64;
            }
            OpcodeId::I32DivU | OpcodeId::I32RemU => {
                aux1 = (lhs.as_u32() / rhs.as_u32()) as u64;
                aux2 = (lhs.as_u32() % rhs.as_u32()) as u64;
                aux3 = (rhs.as_u32() - lhs.as_u32() % rhs.as_u32() - 1) as u64;
            }
            OpcodeId::I64DivU | OpcodeId::I64RemU => {
                aux1 = (lhs.as_u64() / rhs.as_u64()) as u64;
                aux2 = (lhs.as_u64() % rhs.as_u64()) as u64;
                aux3 = (rhs.as_u64() - lhs.as_u64() % rhs.as_u64() - 1) as u64;
            }
            OpcodeId::I32DivS | OpcodeId::I32RemS => {
                // TODO: check and correct to fix possible problems with conversion.
                aux1 = (lhs.as_u32() as i32 / rhs.as_u32() as i32) as u64;
                aux2 = (lhs.as_u32() as i32 % rhs.as_u32() as i32) as u64;
                aux3 = (rhs.as_u32() as i32 - lhs.as_u32() as i32 % rhs.as_u32() as i32 - 1) as u64;
                div_rem_s_is_lhs_pos = (lhs.as_u32() <= i32::MAX as u32) as u64;
                div_rem_s_is_rhs_pos = (rhs.as_u32() <= i32::MAX as u32) as u64;
            }
            OpcodeId::I64DivS | OpcodeId::I64RemS => {
                // TODO: check and correct to fix possible problems with conversion.
                aux1 = (lhs.as_u64() as i64 / rhs.as_u64() as i64) as u64;
                aux2 = (lhs.as_u64() as i64 % rhs.as_u64() as i64) as u64;
                aux3 = (rhs.as_u64() as i64 - lhs.as_u64() as i64 % rhs.as_u64() as i64 - 1) as u64;
                div_rem_s_is_lhs_pos = (lhs.as_u64() <= i64::MAX as u64) as u64;
                div_rem_s_is_rhs_pos = (rhs.as_u64() <= i64::MAX as u64) as u64;
            }
            _ => unreachable!("not supported opcode: {:?}", opcode),
        };
        self.aux1.assign(region, offset, Value::known(F::from(aux1)))?;
        self.aux2.assign(region, offset, Value::known(F::from(aux2)))?;
        self.aux3.assign(region, offset, Value::known(F::from(aux3)))?;
        self.div_rem_s_is_lhs_pos.assign(region, offset, Value::known(F::from(div_rem_s_is_lhs_pos)))?;
        self.div_rem_s_is_rhs_pos.assign(region, offset, Value::known(F::from(div_rem_s_is_rhs_pos)))?;

        let is_64bit = matches!(opcode,
            OpcodeId::I64Add |
            OpcodeId::I64Sub |
            OpcodeId::I64Mul |
            OpcodeId::I64DivS |
            OpcodeId::I64DivU |
            OpcodeId::I64RemS |
            OpcodeId::I64RemU
        );
        self.is_64bits.assign(region, offset, Value::known(F::from(is_64bit as u64)))?;

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

    #[test]
    fn test_i32_add() {
        run_test(bytecode! {
            I32Const[1]
            I32Const[1]
            I32Add
            Drop
        });
    }

    #[test]
    fn test_i32_add_overflow() {
        run_test(bytecode! {
            I32Const[1]
            I32Const[4294967295]
            I32Add
            Drop
        });
    }

    #[test]
    fn test_i64_add() {
        run_test(bytecode! {
            I64Const[1]
            I64Const[1]
            I64Add
            Drop
        });
    }

    #[test]
    fn test_i64_add_overflow() {
        run_test(bytecode! {
            I64Const[1]
            I64Const[18446744073709551615]
            I64Add
            Drop
        });
    }

    #[test]
    fn test_i32_mul() {
        run_test(bytecode! {
            I32Const[3]
            I32Const[4]
            I32Mul
            Drop
        });
    }

    #[test]
    fn test_i32_mul_overflow() {
        run_test(bytecode! {
            I32Const[4294967295]
            I32Const[4294967295]
            I32Mul
            Drop
        });
    }

    #[test]
    fn test_i32_div_u() {
        run_test(bytecode! {
            I32Const[4]
            I32Const[3]
            I32DivU
            Drop
        });
        run_test(bytecode! {
            I32Const[0x80000000]
            I32Const[1]
            I32DivU
            Drop
        });
    }

    #[test]
    fn test_i64_mul() {
        run_test(bytecode! {
            I64Const[3]
            I64Const[4]
            I64Mul
            Drop
        });
    }

    #[test]
    fn test_i64_mul_overflow() {
        run_test(bytecode! {
            I64Const[18446744073709551615]
            I64Const[18446744073709551615]
            I64Mul
            Drop
        });
    }

    #[test]
    fn test_i32_64_rem() {
        run_test(bytecode! {
            I64Const[4]
            I64Const[3]
            I64RemU
            Drop
            I64Const[4]
            I64Const[4]
            I64RemU
            Drop
        });
    }

    #[test]
    fn test_i32_64_rem_s() {
        run_test(bytecode! {
            I64Const[-4]
            I64Const[-3]
            I64RemS
            Drop
            I64Const[-4]
            I64Const[3]
            I64RemS
            Drop
            I64Const[4]
            I64Const[-3]
            I64RemS
            Drop
            I64Const[4]
            I64Const[-4]
            I64RemS
            Drop
            I64Const[-3]
            I64Const[-3]
            I64RemS
            Drop
        });
    }

    // `s_pp` means signed where lhs is positive and rhs is positive.
    #[test]
    fn test_i32_64_rem_s_pp() {
        run_test(bytecode! {
            I64Const[4]
            I64Const[3]
            I64RemS
            Drop
            I64Const[4]
            I64Const[4]
            I64RemS
            Drop
        });
    }

    // `s_pp` means signed where lhs is positive and rhs is positive.
    #[test]
    fn test_i32_64_div_s_pp() {
        run_test(bytecode! {
            I64Const[4]
            I64Const[3]
            I64DivS
            Drop
            I64Const[4]
            I64Const[4]
            I64DivS
            Drop
        });
    }

    // `s_pp` means signed where lhs is positive and rhs is positive.
    #[test]
    fn test_i32_32_rem_s_pp() {
        run_test(bytecode! {
            I32Const[4]
            I32Const[3]
            I32RemS
            Drop
            I32Const[4]
            I32Const[4]
            I32RemS
            Drop
        });
    }

    // `s_pp` means signed where lhs is positive and rhs is positive.
    #[test]
    fn test_i32_32_div_s_pp() {
        run_test(bytecode! {
            I32Const[4]
            I32Const[3]
            I32DivS
            Drop
            I32Const[4]
            I32Const[4]
            I32DivS
            Drop
        });
    }

    #[test]
    fn test_different_cases() {
        run_test(bytecode! {
            I32Const[100]
            I32Const[20]
            I32Add
            I32Const[3]
            I32Add
            I32Const[123]
            I32Sub
            Drop
        });
    }
}
