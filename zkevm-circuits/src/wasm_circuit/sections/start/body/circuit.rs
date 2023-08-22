use std::{cell::RefCell, marker::PhantomData, rc::Rc};

use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Fixed},
    poly::Rotation,
};
use log::debug;

use eth_types::Field;
use gadgets::util::{and, not, Expr};

use crate::{
    evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon},
    wasm_circuit::{
        bytecode::{bytecode::WasmBytecode, bytecode_table::WasmBytecodeTable},
        common::{
            configure_constraints_for_q_first_and_q_last, configure_transition_check,
            WasmAssignAwareChip, WasmErrorAwareChip, WasmFuncCountAwareChip,
            WasmMarkupLeb128SectionAwareChip, WasmSharedStateAwareChip,
        },
        error::{remap_error_to_assign_at, Error},
        leb128::circuit::LEB128Chip,
        sections::{consts::LebParams, start::body::types::AssignType},
        types::{NewWbOffsetType, SharedState},
    },
};

#[derive(Debug, Clone)]
pub struct WasmStartSectionBodyConfig<F: Field> {
    pub q_enable: Column<Fixed>,
    pub q_first: Column<Fixed>,
    pub q_last: Column<Fixed>,
    pub is_func_index: Column<Fixed>,

    pub wb_table: Rc<WasmBytecodeTable>,
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
    fn error_code_col(&self) -> Column<Advice> {
        self.config.error_code
    }
}

impl<F: Field> WasmSharedStateAwareChip<F> for WasmStartSectionBodyChip<F> {
    fn shared_state(&self) -> Rc<RefCell<SharedState>> {
        self.config.shared_state.clone()
    }
}

impl<F: Field> WasmFuncCountAwareChip<F> for WasmStartSectionBodyChip<F> {
    fn func_count_col(&self) -> Column<Advice> {
        self.config.func_count
    }
}

impl<F: Field> WasmAssignAwareChip<F> for WasmStartSectionBodyChip<F> {
    type AssignType = AssignType;

    fn assign_internal(
        &self,
        region: &mut Region<F>,
        wb: &WasmBytecode,
        wb_offset: usize,
        assign_delta: usize,
        assign_types: &[Self::AssignType],
        assign_value: u64,
        leb_params: Option<LebParams>,
    ) -> Result<(), Error> {
        let q_enable = true;
        let assign_offset = wb_offset + assign_delta;
        debug!(
            "assign at {} q_enable {} assign_types {:?} assign_value {} byte_val {:x?}",
            assign_offset, q_enable, assign_types, assign_value, wb.bytes[wb_offset],
        );
        region
            .assign_fixed(
                || format!("assign 'q_enable' val {} at {}", q_enable, assign_offset),
                self.config.q_enable,
                assign_offset,
                || Value::known(F::from(q_enable as u64)),
            )
            .map_err(remap_error_to_assign_at(assign_offset))?;
        self.assign_func_count(region, assign_offset)?;

        for assign_type in assign_types {
            if *assign_type == AssignType::IsFuncsIndex {
                let p = leb_params.unwrap();
                self.config
                    .leb128_chip
                    .assign(region, assign_offset, q_enable, p)?;
            }
            match assign_type {
                AssignType::QFirst => {
                    region
                        .assign_fixed(
                            || {
                                format!(
                                    "assign 'q_first' val {} at {}",
                                    assign_value, assign_offset
                                )
                            },
                            self.config.q_first,
                            assign_offset,
                            || Value::known(F::from(assign_value)),
                        )
                        .map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::QLast => {
                    region
                        .assign_fixed(
                            || format!("assign 'q_last' val {} at {}", assign_value, assign_offset),
                            self.config.q_last,
                            assign_offset,
                            || Value::known(F::from(assign_value)),
                        )
                        .map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::IsFuncsIndex => {
                    region
                        .assign_fixed(
                            || {
                                format!(
                                    "assign 'is_func_index' val {} at {}",
                                    assign_value, assign_offset
                                )
                            },
                            self.config.is_func_index,
                            assign_offset,
                            || Value::known(F::from(assign_value)),
                        )
                        .map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::ErrorCode => {
                    self.assign_error_code(region, assign_offset, None)?;
                }
            }
        }
        Ok(())
    }
}

impl<F: Field> WasmStartSectionBodyChip<F> {
    pub fn construct(config: WasmStartSectionBodyConfig<F>) -> Self {
        let instance = Self {
            config,
            _marker: PhantomData,
        };
        instance
    }

    pub fn configure(
        cs: &mut ConstraintSystem<F>,
        wb_table: Rc<WasmBytecodeTable>,
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

            let q_enable_expr = Self::get_selector_expr_enriched_with_error_processing(
                vc,
                q_enable,
                &shared_state.borrow(),
                error_code,
            );
            // let q_first_expr = vc.query_fixed(q_first, Rotation::cur());
            let q_last_expr = vc.query_fixed(q_last, Rotation::cur());
            let not_q_last_expr = not::expr(q_last_expr.clone());
            let is_func_index_expr = vc.query_fixed(is_func_index, Rotation::cur());
            let is_func_index_prev_expr = vc.query_fixed(is_func_index, Rotation::prev());

            let _byte_val_expr = vc.query_advice(wb_table.value, Rotation::cur());

            let leb128_q_enable_expr = vc.query_fixed(leb128_chip.config.q_enable, Rotation::cur());
            let leb128_is_first_byte_expr =
                vc.query_fixed(leb128_chip.config.is_first_byte, Rotation::cur());

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

            cb.condition(is_func_index_expr.clone(), |cb| {
                cb.require_equal(
                    "is_func_index => leb128",
                    leb128_q_enable_expr.clone(),
                    1.expr(),
                )
            });

            configure_transition_check(
                &mut cb,
                vc,
                "check prev: is_func_index+",
                and::expr([not_q_last_expr.clone(), is_func_index_expr.clone()]),
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
                    let leb128_q_enable_prev_expr =
                        vc.query_fixed(leb128_chip.config.q_enable, Rotation::prev());
                    cb.require_equal(
                        "exactly one leb arg in a row",
                        leb128_q_enable_prev_expr,
                        0.expr(),
                    )
                },
            );

            cb.gate(q_enable_expr.clone())
        });

        let config = WasmStartSectionBodyConfig::<F> {
            _marker: PhantomData,

            q_enable,
            q_first,
            q_last,
            is_func_index,
            wb_table,
            leb128_chip,
            func_count,
            error_code,
            shared_state,
        };

        config
    }

    pub fn assign_auto(
        &self,
        region: &mut Region<F>,
        wb: &WasmBytecode,
        wb_offset: usize,
        assign_delta: usize,
    ) -> Result<NewWbOffsetType, Error> {
        let mut offset = wb_offset;

        let (_funcs_index, funcs_index_leb_len) = self.markup_leb_section(
            region,
            &wb,
            offset,
            assign_delta,
            &[AssignType::IsFuncsIndex],
        )?;
        self.assign(
            region,
            &wb,
            offset,
            assign_delta,
            &[AssignType::QFirst],
            1,
            None,
        )?;
        offset += funcs_index_leb_len;

        if offset != wb_offset {
            self.assign(
                region,
                &wb,
                offset - 1,
                assign_delta,
                &[AssignType::QLast],
                1,
                None,
            )?;
        }

        Ok(offset)
    }
}
