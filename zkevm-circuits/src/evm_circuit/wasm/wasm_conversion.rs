use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::{Error};

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
pub(crate) struct WasmConversionGadget<F> {
    same_context: SameContextGadget<F>,

    value: Cell<F>,
    value_limbs: [Cell<F>; 8],
    res: Cell<F>,
    is_value_pos: Cell<F>,
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
        let value_limbs = [cb.alloc_u64(), cb.alloc_u64(), cb.alloc_u64(), cb.alloc_u64(),
                           cb.alloc_u64(), cb.alloc_u64(), cb.alloc_u64(), cb.alloc_u64()];

        let res = cb.alloc_u64();

        let is_value_pos = cb.alloc_bit_value();
        let is_i32_wrap_i64 = cb.alloc_bit_value();
        let is_i64_extend_i32_u = cb.alloc_bit_value();
        let is_i64_extend_i32_s = cb.alloc_bit_value();

        cb.stack_pop(value.expr());
        cb.stack_push(res.expr());

        for i in 0..4 {
            cb.add_lookup("op_conversion: Using Range256x2 fixed table", Lookup::Fixed {
                tag: FixedTableTag::Range256x2.expr(),
                values: [value_limbs[i*2].expr(), value_limbs[i*2+1].expr(), 0.expr()],
            });
        }

        cb.require_zeros("op_conversion: pick one", vec![
              is_i32_wrap_i64.expr()
            + is_i64_extend_i32_u.expr()
            + is_i64_extend_i32_s.expr()
            - 1.expr()
        ]);

        cb.require_zeros(
            "op_conversion: argument from limbs",
            vec![{
                let mut out = value_limbs[0].expr();
                for i in 1..8 {
                  out = out + value_limbs[i].expr() * (1_u64 << i*8).expr();
                }
                out - value.expr()
            }],
        );

        cb.require_zeros(
            "op_conversion: result from limbs in case of i32_wrap_i64",
            vec![{
                let mut out = value_limbs[0].expr();
                for i in 1..4 {
                  out = out + value_limbs[i].expr() * (1_u64 << i*8).expr();
                }
                ( out - res.expr() ) * is_i32_wrap_i64.expr()
            }],
        );

        cb.require_zeros(
            "op_conversion: result case of i64_extend_i32",
            {
                // Now we are working with i32 that can be signed or not, in both cases only first four limbs is used.
                // So limbs goes after this must be zero, this check is used to make sure about it.
                let mut check = value_limbs[4].expr();
                for i in 5..8 {
                    check = check + value_limbs[i].expr();
                }
                let cond = || is_i64_extend_i32_u.expr() + is_i64_extend_i32_s.expr();
                let pos_cond = || is_i64_extend_i32_u.expr() + is_i64_extend_i32_s.expr() * is_value_pos.expr();
                let neg_cond = || is_i64_extend_i32_s.expr() * (1.expr() - is_value_pos.expr());
                vec![
                    check * cond(),
                    ( value.expr() - res.expr() ) * pos_cond(),
                    ( value.expr() + 0xffffffff_00000000_u64.expr() - res.expr() ) * neg_cond(),
                ]
            },
        );

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
            value_limbs,
            res,
            is_value_pos,
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

        self.value.assign(region, offset, Value::known(value.to_scalar().unwrap()))?;
        self.res.assign(region, offset, Value::known(res.to_scalar().unwrap()))?;

        for idx in 0..8 {
            let limb = (value.0[0] >> (idx * 8)) & 0xff;
            self.value_limbs[idx].assign(region, offset, Value::<F>::known(F::from(limb)))?;
        }

        match opcode {
            OpcodeId::I32WrapI64 => {
                self.is_i32_wrap_i64.assign(region, offset, Value::known(true.to_scalar().unwrap()))?;
            }
            OpcodeId::I64ExtendUI32 => {
                self.is_i64_extend_i32_u.assign(region, offset, Value::known(true.to_scalar().unwrap()))?;
            }
            OpcodeId::I64ExtendSI32 => {
                let is_value_pos = (value.as_u32() <= i32::MAX as u32) as u64;
                self.is_value_pos.assign(region, offset, Value::<F>::known(F::from(is_value_pos)))?;
                self.is_i64_extend_i32_s.assign(region, offset, Value::known(true.to_scalar().unwrap()))?;
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

    #[test]
    fn test_i64_extend_u_i32() {
        run_test(bytecode! {
            I32Const[0]
            I64ExtendUI32
            Drop
            I32Const[0xffffffff]
            I64ExtendUI32
            Drop
            I32Const[0x0f0f0f0f]
            I64ExtendUI32
            Drop
        });
    }

    #[test]
    fn test_i64_extend_s_i32() {
        run_test(bytecode! {
            I32Const[0]
            I64ExtendSI32
            Drop
            I32Const[0x70ffffff]
            I64ExtendSI32
            Drop
            I32Const[-0x70ffffff]
            I64ExtendSI32
            Drop
        });
    }


}
