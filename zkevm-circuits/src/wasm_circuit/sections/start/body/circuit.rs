use std::cell::RefCell;
use std::marker::PhantomData;
use std::rc::Rc;

use halo2_proofs::{
    plonk::{Column, ConstraintSystem},
};
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::plonk::{Advice, Fixed};
use halo2_proofs::poly::Rotation;
use log::debug;

use eth_types::Field;
use gadgets::util::{and, Expr, not};

use crate::evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon};
use crate::wasm_circuit::bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::common::{WasmAssignAwareChip, WasmErrorAwareChip, WasmFuncCountAwareChip, WasmMarkupLeb128SectionAwareChip, WasmSharedStateAwareChip};
use crate::wasm_circuit::common::{configure_constraints_for_q_first_and_q_last, configure_transition_check};
use crate::wasm_circuit::error::Error;
use crate::wasm_circuit::leb128::circuit::LEB128Chip;
use crate::wasm_circuit::sections::consts::LebParams;
use crate::wasm_circuit::sections::start::body::types::AssignType;
use crate::wasm_circuit::types::SharedState;

#[derive(Debug, Clone)]
pub struct WasmStartSectionBodyConfig<F: Field> {
    pub q_enable: Column<Fixed>,
    pub q_first: Column<Fixed>,
    pub q_last: Column<Fixed>,
    pub is_func_index: Column<Fixed>,

    pub bytecode_table: Rc<WasmBytecodeTable>,
    pub leb128_chip: Rc<LEB128Chip<F>>,

    pub func_count: Column<Advice>,

    pub error_code: Column<Advice>,

    shared_state: Rc<RefCell<SharedState>>,

    _marker: PhantomData<F>,
}

impl<'a, F: Field> WasmStartSectionBodyConfig<F> {}

#[derive(Debug, Clone)]
pub struct WasmStartSectionBodyChip<F: Field> {
    pub config: WasmStartSectionBodyConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> WasmMarkupLeb128SectionAwareChip<F> for WasmStartSectionBodyChip<F> {}

impl<F: Field> WasmErrorAwareChip<F> for WasmStartSectionBodyChip<F> {
    fn error_code_col(&self) -> Column<Advice> { self.config.error_code }
}

impl<F: Field> WasmSharedStateAwareChip<F> for WasmStartSectionBodyChip<F> {
    fn shared_state(&self) -> Rc<RefCell<SharedState>> { self.config.shared_state.clone() }
}

impl<F: Field> WasmFuncCountAwareChip<F> for WasmStartSectionBodyChip<F> {
    fn func_count_col(&self) -> Column<Advice> { self.config.func_count }
}

impl<F: Field> WasmAssignAwareChip<F> for WasmStartSectionBodyChip<F> {
    type AssignType = AssignType;

    fn assign(
        &self,
        region: &mut Region<F>,
        wb: &WasmBytecode,
        offset: usize,
        assign_types: &[Self::AssignType],
        assign_value: u64,
        leb_params: Option<LebParams>,
    ) -> Result<(), Error> {
        let q_enable = true;
        debug!(
            "assign at offset {} q_enable {} assign_types {:?} assign_value {} byte_val {:x?}",
            offset,
            q_enable,
            assign_types,
            assign_value,
            wb.bytes[offset],
        );
        region.assign_fixed(
            || format!("assign 'q_enable' val {} at {}", q_enable, offset),
            self.config.q_enable,
            offset,
            || Value::known(F::from(q_enable as u64)),
        ).unwrap();
        self.assign_func_count(region, offset);

        for assign_type in assign_types {
            if *assign_type == AssignType::IsFuncsIndex {
                let p = leb_params.unwrap();
                self.config.leb128_chip.assign(
                    region,
                    offset,
                    q_enable,
                    p,
                );
            }
            match assign_type {
                AssignType::QFirst => {
                    region.assign_fixed(
                        || format!("assign 'q_first' val {} at {}", assign_value, offset),
                        self.config.q_first,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::QLast => {
                    region.assign_fixed(
                        || format!("assign 'q_last' val {} at {}", assign_value, offset),
                        self.config.q_last,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsFuncsIndex => {
                    region.assign_fixed(
                        || format!("assign 'is_func_index' val {} at {}", assign_value, offset),
                        self.config.is_func_index,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::ErrorCode => {
                    self.assign_error_code(region, offset, None)
                }
            }
        };
        Ok(())
    }
}

impl<F: Field> WasmStartSectionBodyChip<F>
{
    pub fn construct(config: WasmStartSectionBodyConfig<F>) -> Self {
        let instance = Self {
            config,
            _marker: PhantomData,
        };
        instance
    }

    pub fn configure(
        cs: &mut ConstraintSystem<F>,
        bytecode_table: Rc<WasmBytecodeTable>,
        leb128_chip: Rc<LEB128Chip<F>>,
        func_count: Column<Advice>,
        shared_state: Rc<RefCell<SharedState>>,
        error_code: Column<Advice>,
    ) -> WasmStartSectionBodyConfig<F> {
        let q_enable = cs.fixed_column();
        let q_first = cs.fixed_column();
        let q_last = cs.fixed_column();
        let is_func_index = cs.fixed_column();

        cs.create_gate("WasmStartSectionBody gate", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
            // let q_first_expr = vc.query_fixed(q_first, Rotation::cur());
            let q_last_expr = vc.query_fixed(q_last, Rotation::cur());
            let not_q_last_expr = not::expr(q_last_expr.clone());
            let is_func_index_expr = vc.query_fixed(is_func_index, Rotation::cur());
            let is_func_index_prev_expr = vc.query_fixed(is_func_index, Rotation::prev());

            let _byte_val_expr = vc.query_advice(bytecode_table.value, Rotation::cur());

            let leb128_q_enable_expr = vc.query_fixed(leb128_chip.config.q_enable, Rotation::cur());
            let leb128_is_first_byte_expr = vc.query_fixed(leb128_chip.config.is_first_byte, Rotation::cur());

            cb.require_boolean("q_enable is boolean", q_enable_expr.clone());
            cb.require_boolean("is_func_index is boolean", is_func_index_expr.clone());

            configure_constraints_for_q_first_and_q_last(
                &mut cb,
                vc,
                &q_enable,
                &q_first,
                &[is_func_index],
                &q_last,
                &[is_func_index],
            );

            cb.require_equal(
                "exactly one mark flag active at the same time",
                is_func_index_expr.clone(),
                1.expr(),
            );

            cb.condition(
                is_func_index_expr.clone(),
                |cb| {
                    cb.require_equal(
                        "is_func_index => leb128",
                        leb128_q_enable_expr.clone(),
                        1.expr(),
                    )
                }
            );

            configure_transition_check(
                &mut cb,
                vc,
                "check prev: is_func_index+",
                and::expr([
                    not_q_last_expr.clone(),
                    is_func_index_expr.clone(),
                ]),
                false,
                &[is_func_index],
            );
            cb.condition(
                and::expr([
                    is_func_index_expr.clone(),
                    leb128_is_first_byte_expr.clone(),
                    is_func_index_prev_expr.clone(),
                ]),
                |cb| {
                    let leb128_q_enable_prev_expr = vc.query_fixed(leb128_chip.config.q_enable, Rotation::prev());
                    cb.require_equal(
                        "exactly one leb arg in a row",
                        leb128_q_enable_prev_expr,
                        0.expr(),
                    )
                }
            );

            cb.gate(q_enable_expr.clone())
        });

        let config = WasmStartSectionBodyConfig::<F> {
            _marker: PhantomData,

            q_enable,
            q_first,
            q_last,
            is_func_index,
            bytecode_table,
            leb128_chip,
            func_count,
            error_code,
            shared_state,
        };

        config
    }

    /// returns new offset
    pub fn assign_auto(
        &self,
        region: &mut Region<F>,
        wb: &WasmBytecode,
        offset_start: usize,
    ) -> Result<usize, Error> {
        let mut offset = offset_start;

        let (_funcs_index, funcs_index_leb_len) = self.markup_leb_section(
            region,
            &wb,
            offset,
            &[AssignType::IsFuncsIndex],
        )?;
        self.assign(region, &wb, offset, &[AssignType::QFirst], 1, None)?;
        offset += funcs_index_leb_len;

        if offset != offset_start {
            self.assign(region, &wb, offset - 1, &[AssignType::QLast], 1, None)?;
        }

        Ok(offset)
    }
}