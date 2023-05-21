use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::{Error};

use bus_mapping::evm::OpcodeId;
use eth_types::{Field, ToScalar};

use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
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
pub(crate) struct WasmConversionGadget<F> {
    same_context: SameContextGadget<F>,

    value: Cell<F>,
    value_type: Cell<F>,
    res: Cell<F>,
    res_type: Cell<F>,

    flag_bit: Cell<F>,
    flag_u8_rem: Cell<F>,
    flag_u8_rem_diff: Cell<F>,

    is_i32_wrap_i64: Cell<F>,
    is_i64_extend_i32_u: Cell<F>,
    is_i64_extend_i32_s: Cell<F>,
}

pub(crate) mod types {
    pub(crate) const I32: u64 = 10;
    pub(crate) const I64: u64 = 11;
}

impl<F: Field> ExecutionGadget<F> for WasmConversionGadget<F> {
    const NAME: &'static str = "WASM_CONVERSION";

    const EXECUTION_STATE: ExecutionState = ExecutionState::WASM_CONVERSION;

    fn configure(cb: &mut EVMConstraintBuilder<F>) -> Self {
        let value = cb.alloc_u64_on_u8();
        let value_type = cb.alloc_common_range_value();
        let res = cb.alloc_u64();
        let res_type = cb.alloc_common_range_value();

        let flag_bit = cb.alloc_bit_value();
        let flag_u8_rem = cb.alloc_common_range_value();
        let flag_u8_rem_diff = cb.alloc_common_range_value();

        let is_i32_wrap_i64 = cb.alloc_bit_value();
        let is_i64_extend_i32_u = cb.alloc_bit_value();
        let is_i64_extend_i32_s = cb.alloc_bit_value();

        cb.stack_pop(value.expr());
        cb.stack_push(res.expr());

        cb.require_zeros("op_conversion: pick one", vec![
              is_i32_wrap_i64.expr()
            + is_i64_extend_i32_u.expr()
            + is_i64_extend_i32_s.expr()
            - 1.expr()
        ]);

        cb.require_zeros("op_conversion: type matches op", vec![
            is_i32_wrap_i64.expr() * (value_type.expr() - types::I64.expr()),
            is_i32_wrap_i64.expr() * (res_type.expr() - types::I32.expr()),
            (is_i64_extend_i32_s.expr() + is_i64_extend_i32_u.expr())
                * (value_type.expr() - types::I32.expr()),
            (is_i64_extend_i32_s.expr() + is_i64_extend_i32_u.expr())
                * (res_type.expr() - types::I64.expr()),
        ]);

        // TODO: enable this constraint, maybe some range proofs and byte limbs is useful for this.
        // constraint_builder.push("i32_wrap_i64", Box::new(move |meta| {
        //         let mut acc = constant_from!(0);
        //        for i in 0..4 { acc = acc + value.u8_expr(meta, i) * constant_from!(1 << (i * 8)); }
        //        vec![is_i32_wrap_i64.expr(meta) * (acc - res.expr(meta))]
        // }),);

        // TODO: enable this constraint, maybe some range proofs and byte limbs is useful for this.
        // constraint_builder.push("extend op flag bit", Box::new(move |meta| {
        //        let flag_u8 = value.u8_expr(meta, 3);
        //        vec![(is_i64_extend_i32_s.expr(meta) + is_i64_extend_i32_u.expr(meta))
        //                * (flag_bit.expr(meta) * constant_from!(128) + flag_u8_rem.expr(meta) - flag_u8),
        //             (is_i64_extend_i32_s.expr(meta) + is_i64_extend_i32_u.expr(meta))
        //                * (flag_u8_rem.expr(meta) + flag_u8_rem_diff.expr(meta) - constant_from!(127)),
        // ]}),);

        cb.require_zeros("op_conversion: i64_extend_i32_u", vec![
            is_i64_extend_i32_u.expr() * (res.expr() - value.expr())
        ]);

        cb.require_zeros("op_conversion: i64_extend_i32_s", {
            let pad = flag_bit.expr() * ((u32::MAX as u64) << 32).expr();
            vec![is_i64_extend_i32_s.expr() * (pad + value.expr() - res.expr())]
        });

        let opcode = cb.query_cell();

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(2.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(0.expr()),
            gas_left: Delta(-OpcodeId::I32WrapI64.constant_gas_cost().expr()),
            ..StepStateTransition::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            value,
            value_type,
            res,
            res_type,
            flag_bit,
            flag_u8_rem,
            flag_u8_rem_diff,
            is_i32_wrap_i64,
            is_i64_extend_i32_u,
            is_i64_extend_i32_s,
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

        let [value, res] = [step.rw_indices[0], step.rw_indices[1]]
            .map(|idx| block.rws[idx].stack_value());

        match opcode {
            OpcodeId::I32WrapI64 => {
                self.value.assign(region, offset, Value::known(value.to_scalar().unwrap()))?;
                self.value_type.assign(region, offset, Value::known(types::I64.to_scalar().unwrap()))?;
                self.res.assign(region, offset, Value::known(res.to_scalar().unwrap()))?;
                self.res_type.assign(region, offset, Value::known(types::I32.to_scalar().unwrap()))?;

                self.is_i32_wrap_i64.assign(region, offset, Value::known(true.to_scalar().unwrap()))?;
            }
            OpcodeId::I64ExtendI32 => {
                let is_psign = true;
                if is_psign {
                    self.is_i64_extend_i32_u.assign(region, offset, Value::known(true.to_scalar().unwrap()))?;
                } else {
                    self.is_i64_extend_i32_s.assign(region, offset, Value::known(true.to_scalar().unwrap()))?;
                }

                let flag_u8 = value.0[0] as u32 >> (32 - 8);
                let flag_bit = flag_u8 >> 7;
                let flag_u8_rem = flag_u8 & 0x7f;
                let flag_u8_rem_diff = 0x7f - flag_u8_rem;

                self.flag_bit.assign(region, offset, Value::known((flag_bit == 1).to_scalar().unwrap()))?;
                self.flag_u8_rem.assign(region, offset, Value::known((flag_u8_rem as u64).to_scalar().unwrap()))?;
                self.flag_u8_rem_diff.assign(region, offset, Value::known((flag_u8_rem_diff as u64).to_scalar().unwrap()))?;

                self.value.assign(region, offset, Value::known(value.to_scalar().unwrap()))?;
                self.value_type.assign(region, offset, Value::known(types::I32.to_scalar().unwrap()))?;
                self.res.assign(region, offset, Value::known(res.to_scalar().unwrap()))?;
                self.res_type.assign(region, offset, Value::known(types::I64.to_scalar().unwrap()))?;
            }
            _ => unreachable!("not supported opcode: {:?}", opcode),
        };
 
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
    fn test_i32_wrap_i64() {
        run_test(bytecode! {
            I64Const[0]
            I32WrapI64
            Drop
            I64Const[0xffffffff00000000]
            I32WrapI64
            Drop
            I64Const[0xfffffffff0f0f0f0]
            I32WrapI64
            Drop
        });
    }
}
