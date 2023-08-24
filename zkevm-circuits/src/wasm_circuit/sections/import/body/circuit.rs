use std::{cell::RefCell, marker::PhantomData, rc::Rc};

use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Fixed},
    poly::Rotation,
};
use itertools::Itertools;
use log::debug;

use eth_types::Field;
use gadgets::{
    binary_number::BinaryNumberChip,
    less_than::LtInstruction,
    util::{and, not, or, Expr},
};

use crate::{
    evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon},
    wasm_circuit::{
        bytecode::{bytecode::WasmBytecode, bytecode_table::WasmBytecodeTable},
        common::{
            configure_constraints_for_q_first_and_q_last, configure_transition_check,
            LimitTypeFields, WasmAssignAwareChip, WasmCountPrefixedItemsAwareChip,
            WasmErrorAwareChip, WasmFuncCountAwareChip, WasmLenPrefixedBytesSpanAwareChip,
            WasmLimitTypeAwareChip, WasmMarkupLeb128SectionAwareChip, WasmNameAwareChip,
            WasmSharedStateAwareChip,
        },
        error::{
            remap_error, remap_error_to_assign_at, remap_error_to_invalid_enum_value_at, Error,
        },
        leb128::circuit::LEB128Chip,
        sections::{consts::LebParams, import::body::types::AssignType},
        tables::dynamic_indexes::circuit::DynamicIndexesChip,
        types::{
            AssignDeltaType, AssignValueType, ImportDescType, LimitType, NewWbOffsetType, RefType,
            SharedState, IMPORT_DESC_TYPE_VALUES, MUTABILITY_VALUES, REF_TYPE_VALUES,
        },
        utf8::circuit::UTF8Chip,
    },
};

#[derive(Debug, Clone)]
pub struct WasmImportSectionBodyConfig<F: Field> {
    pub q_enable: Column<Fixed>,
    pub q_first: Column<Fixed>,
    pub q_last: Column<Fixed>,
    pub is_items_count: Column<Fixed>,
    pub is_mod_name_len: Column<Fixed>,
    pub is_mod_name: Column<Fixed>,
    pub is_import_name_len: Column<Fixed>,
    pub is_import_name: Column<Fixed>,
    pub is_importdesc_type: Column<Fixed>,
    pub is_importdesc_type_ctx: Column<Fixed>,
    pub is_importdesc_val: Column<Fixed>,
    pub is_mut_prop: Column<Fixed>,

    pub limit_type_fields: LimitTypeFields<F>,

    pub is_ref_type: Column<Fixed>,

    pub leb128_chip: Rc<LEB128Chip<F>>,
    pub utf8_chip: Rc<UTF8Chip<F>>,
    pub dynamic_indexes_chip: Rc<DynamicIndexesChip<F>>,
    pub importdesc_type: Column<Advice>,
    pub importdesc_type_chip: Rc<BinaryNumberChip<F, ImportDescType, 8>>,

    func_count: Column<Advice>,
    body_byte_rev_index: Column<Advice>,
    body_item_rev_count: Column<Advice>,

    error_code: Column<Advice>,

    shared_state: Rc<RefCell<SharedState>>,

    _marker: PhantomData<F>,
}

impl<'a, F: Field> WasmImportSectionBodyConfig<F> {}

#[derive(Debug, Clone)]
pub struct WasmImportSectionBodyChip<F: Field> {
    pub config: WasmImportSectionBodyConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> WasmMarkupLeb128SectionAwareChip<F> for WasmImportSectionBodyChip<F> {}

impl<F: Field> WasmCountPrefixedItemsAwareChip<F> for WasmImportSectionBodyChip<F> {}

impl<F: Field> WasmLenPrefixedBytesSpanAwareChip<F> for WasmImportSectionBodyChip<F> {}

impl<F: Field> WasmNameAwareChip<F> for WasmImportSectionBodyChip<F> {}

impl<F: Field> WasmLimitTypeAwareChip<F> for WasmImportSectionBodyChip<F> {}

impl<F: Field> WasmErrorAwareChip<F> for WasmImportSectionBodyChip<F> {
    fn error_code_col(&self) -> Column<Advice> {
        self.config.error_code
    }
}

impl<F: Field> WasmSharedStateAwareChip<F> for WasmImportSectionBodyChip<F> {
    fn shared_state(&self) -> Rc<RefCell<SharedState>> {
        self.config.shared_state.clone()
    }
}

impl<F: Field> WasmFuncCountAwareChip<F> for WasmImportSectionBodyChip<F> {
    fn func_count_col(&self) -> Column<Advice> {
        self.config.func_count
    }
}

impl<F: Field> WasmAssignAwareChip<F> for WasmImportSectionBodyChip<F> {
    type AssignType = AssignType;

    fn assign_internal(
        &self,
        region: &mut Region<F>,
        wb: &WasmBytecode,
        wb_offset: usize,
        assign_delta: AssignDeltaType,
        assign_types: &[Self::AssignType],
        assign_value: AssignValueType,
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

        for assign_type in assign_types {
            if [
                AssignType::IsItemsCount,
                AssignType::IsModNameLen,
                AssignType::IsImportNameLen,
                AssignType::IsImportdescVal,
                AssignType::IsLimitMin,
                AssignType::IsLimitMax,
            ]
            .contains(assign_type)
            {
                let p = leb_params.unwrap();
                self.config
                    .leb128_chip
                    .assign(region, assign_offset, true, p)?;
            }
            if [AssignType::IsModName, AssignType::IsImportName].contains(assign_type) {
                let byte_val = wb.bytes[wb_offset];
                self.config
                    .utf8_chip
                    .assign(region, assign_offset, true, byte_val)?;
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
                AssignType::IsItemsCount => {
                    region
                        .assign_fixed(
                            || {
                                format!(
                                    "assign 'is_items_count' val {} at {}",
                                    assign_value, assign_offset
                                )
                            },
                            self.config.is_items_count,
                            assign_offset,
                            || Value::known(F::from(assign_value)),
                        )
                        .map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::IsModNameLen => {
                    region
                        .assign_fixed(
                            || {
                                format!(
                                    "assign 'is_mod_name_len' val {} at {}",
                                    assign_value, assign_offset
                                )
                            },
                            self.config.is_mod_name_len,
                            assign_offset,
                            || Value::known(F::from(assign_value)),
                        )
                        .map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::IsModName => {
                    region
                        .assign_fixed(
                            || {
                                format!(
                                    "assign 'is_mod_name' val {} at {}",
                                    assign_value, assign_offset
                                )
                            },
                            self.config.is_mod_name,
                            assign_offset,
                            || Value::known(F::from(assign_value)),
                        )
                        .map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::IsImportNameLen => {
                    region
                        .assign_fixed(
                            || {
                                format!(
                                    "assign 'is_import_name_len' val {} at {}",
                                    assign_value, assign_offset
                                )
                            },
                            self.config.is_import_name_len,
                            assign_offset,
                            || Value::known(F::from(assign_value)),
                        )
                        .map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::IsImportName => {
                    region
                        .assign_fixed(
                            || {
                                format!(
                                    "assign 'is_import_name' val {} at {}",
                                    assign_value, assign_offset
                                )
                            },
                            self.config.is_import_name,
                            assign_offset,
                            || Value::known(F::from(assign_value)),
                        )
                        .map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::IsImportdescType => {
                    region
                        .assign_fixed(
                            || {
                                format!(
                                    "assign 'is_importdesc_type' val {} at {}",
                                    assign_value, assign_offset
                                )
                            },
                            self.config.is_importdesc_type,
                            assign_offset,
                            || Value::known(F::from(assign_value)),
                        )
                        .map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::IsImportdescVal => {
                    region
                        .assign_fixed(
                            || {
                                format!(
                                    "assign 'is_importdesc_val' val {} at {}",
                                    assign_value, assign_offset
                                )
                            },
                            self.config.is_importdesc_val,
                            assign_offset,
                            || Value::known(F::from(assign_value)),
                        )
                        .map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::IsMut => {
                    region
                        .assign_fixed(
                            || {
                                format!(
                                    "assign 'is_mut_prop' val {} at {}",
                                    assign_value, assign_offset
                                )
                            },
                            self.config.is_mut_prop,
                            assign_offset,
                            || Value::known(F::from(assign_value)),
                        )
                        .map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::IsImportdescTypeCtx => {
                    region
                        .assign_fixed(
                            || {
                                format!(
                                    "assign 'is_importdesc_type_ctx' val {} at {}",
                                    assign_value, assign_offset
                                )
                            },
                            self.config.is_importdesc_type_ctx,
                            assign_offset,
                            || Value::known(F::from(assign_value)),
                        )
                        .map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::ImportdescType => {
                    region
                        .assign_advice(
                            || {
                                format!(
                                    "assign 'importdesc_type' val {} at {}",
                                    assign_value, assign_offset
                                )
                            },
                            self.config.importdesc_type,
                            assign_offset,
                            || Value::known(F::from(assign_value)),
                        )
                        .map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::IsLimitType => {
                    region
                        .assign_fixed(
                            || {
                                format!(
                                    "assign 'is_limit_type' val {} at {}",
                                    assign_value, assign_offset
                                )
                            },
                            self.config.limit_type_fields.is_limit_type,
                            assign_offset,
                            || Value::known(F::from(assign_value)),
                        )
                        .map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::IsLimitMin => {
                    region
                        .assign_fixed(
                            || {
                                format!(
                                    "assign 'is_limit_min' val {} at {}",
                                    assign_value, assign_offset
                                )
                            },
                            self.config.limit_type_fields.is_limit_min,
                            assign_offset,
                            || Value::known(F::from(assign_value)),
                        )
                        .map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::IsLimitMax => {
                    region
                        .assign_fixed(
                            || {
                                format!(
                                    "assign 'is_limit_max' val {} at {}",
                                    assign_value, assign_offset
                                )
                            },
                            self.config.limit_type_fields.is_limit_max,
                            assign_offset,
                            || Value::known(F::from(assign_value)),
                        )
                        .map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::IsLimitTypeCtx => {
                    region
                        .assign_fixed(
                            || {
                                format!(
                                    "assign 'is_limit_type_ctx' val {} at {}",
                                    assign_value, assign_offset
                                )
                            },
                            self.config.limit_type_fields.is_limit_type_ctx,
                            assign_offset,
                            || Value::known(F::from(assign_value)),
                        )
                        .map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::LimitType => {
                    region
                        .assign_advice(
                            || {
                                format!(
                                    "assign 'limit_type' val {} at {}",
                                    assign_value, assign_offset
                                )
                            },
                            self.config.limit_type_fields.limit_type,
                            assign_offset,
                            || Value::known(F::from(assign_value)),
                        )
                        .map_err(remap_error_to_assign_at(assign_offset))?;
                    let limit_type: LimitType = (assign_value as u8)
                        .try_into()
                        .map_err(remap_error_to_invalid_enum_value_at(assign_offset))?;
                    self.config
                        .limit_type_fields
                        .limit_type_chip
                        .assign(region, assign_offset, &limit_type)
                        .map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::IsRefType => {
                    region
                        .assign_fixed(
                            || {
                                format!(
                                    "assign 'is_ref_type' val {} at {}",
                                    assign_value, assign_offset
                                )
                            },
                            self.config.is_ref_type,
                            assign_offset,
                            || Value::known(F::from(assign_value)),
                        )
                        .map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::BodyByteRevIndex => {
                    region
                        .assign_advice(
                            || {
                                format!(
                                    "assign 'body_byte_rev_index' val {} at {}",
                                    assign_value, assign_offset
                                )
                            },
                            self.config.body_byte_rev_index,
                            assign_offset,
                            || Value::known(F::from(assign_value)),
                        )
                        .map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::BodyItemRevCount => {
                    region
                        .assign_advice(
                            || {
                                format!(
                                    "assign 'body_item_rev_count' val {} at {}",
                                    assign_value, assign_offset
                                )
                            },
                            self.config.body_item_rev_count,
                            assign_offset,
                            || Value::known(F::from(assign_value)),
                        )
                        .map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::FuncCount => {
                    self.assign_func_count(region, assign_offset)?;
                }
                AssignType::ErrorCode => {
                    self.assign_error_code(region, assign_offset, None)?;
                }
            }
        }
        Ok(())
    }
}

impl<F: Field> WasmImportSectionBodyChip<F> {
    pub fn construct(config: WasmImportSectionBodyConfig<F>) -> Self {
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
        utf8_chip: Rc<UTF8Chip<F>>,
        dynamic_indexes_chip: Rc<DynamicIndexesChip<F>>,
        func_count: Column<Advice>,
        shared_state: Rc<RefCell<SharedState>>,
        body_byte_rev_index: Column<Advice>,
        body_item_rev_count: Column<Advice>,
        error_code: Column<Advice>,
    ) -> WasmImportSectionBodyConfig<F> {
        let q_enable = cs.fixed_column();
        let q_first = cs.fixed_column();
        let q_last = cs.fixed_column();
        let is_items_count = cs.fixed_column();
        let is_mod_name_len = cs.fixed_column();
        let is_mod_name = cs.fixed_column();
        let is_import_name_len = cs.fixed_column();
        let is_import_name = cs.fixed_column();
        let is_importdesc_type = cs.fixed_column();
        let is_importdesc_val = cs.fixed_column();
        let is_mut_prop = cs.fixed_column();
        let is_ref_type = cs.fixed_column();

        let is_importdesc_type_ctx = cs.fixed_column();

        let importdesc_type = cs.advice_column();

        let config =
            BinaryNumberChip::configure(cs, is_importdesc_type_ctx, Some(importdesc_type.into()));
        let importdesc_type_chip = Rc::new(BinaryNumberChip::construct(config));

        let limit_type_fields =
            Self::construct_limit_type_fields(cs, q_enable, leb128_chip.as_ref());
        Self::configure_limit_type_constraints(
            cs,
            wb_table.as_ref(),
            q_enable,
            leb128_chip.as_ref(),
            &limit_type_fields,
        );

        let LimitTypeFields {
            is_limit_type,
            is_limit_min,
            is_limit_max,
            limit_type_chip,
            ..
        } = limit_type_fields.clone();

        Self::configure_len_prefixed_bytes_span_checks(
            cs,
            leb128_chip.as_ref(),
            |vc| {
                or::expr([
                    vc.query_fixed(is_import_name, Rotation::cur()),
                    vc.query_fixed(is_mod_name, Rotation::cur()),
                ])
            },
            body_byte_rev_index,
            |vc| {
                let is_mod_name_len_expr = vc.query_fixed(is_mod_name_len, Rotation::cur());
                let is_mod_name_next_expr = vc.query_fixed(is_mod_name, Rotation::next());
                let is_import_name_next_expr = vc.query_fixed(is_import_name, Rotation::next());
                let is_import_name_len_expr = vc.query_fixed(is_import_name_len, Rotation::cur());
                let is_import_name_len_next_expr =
                    vc.query_fixed(is_import_name_len, Rotation::next());
                let is_importdesc_type_next_expr =
                    vc.query_fixed(is_importdesc_type, Rotation::next());

                or::expr([
                    and::expr([
                        is_mod_name_len_expr,
                        or::expr([is_mod_name_next_expr, is_import_name_len_next_expr]),
                    ]),
                    and::expr([
                        is_import_name_len_expr,
                        or::expr([is_import_name_next_expr, is_importdesc_type_next_expr]),
                    ]),
                ])
            },
            |vc| {
                let is_mod_name_expr = vc.query_fixed(is_mod_name, Rotation::cur());
                let is_import_name_len_next_expr =
                    vc.query_fixed(is_import_name_len, Rotation::next());
                let is_import_name_expr = vc.query_fixed(is_import_name, Rotation::cur());
                let is_importdesc_type_next_expr =
                    vc.query_fixed(is_importdesc_type, Rotation::next());

                or::expr([
                    and::expr([is_mod_name_expr, is_import_name_len_next_expr]),
                    and::expr([is_import_name_expr, is_importdesc_type_next_expr]),
                ])
            },
        );

        Self::configure_count_prefixed_items_checks(
            cs,
            leb128_chip.as_ref(),
            body_item_rev_count,
            |vc| vc.query_fixed(is_items_count, Rotation::cur()),
            |vc| {
                let q_enable_expr = Self::get_selector_expr_enriched_with_error_processing(
                    vc,
                    q_enable,
                    &shared_state.borrow(),
                    error_code,
                );
                let is_items_count_expr = vc.query_fixed(is_items_count, Rotation::cur());

                and::expr([q_enable_expr, not::expr(is_items_count_expr)])
            },
            |vc| {
                let q_first_expr = vc.query_fixed(q_first, Rotation::cur());
                let is_items_count_prev_expr = vc.query_fixed(is_items_count, Rotation::prev());
                let is_mod_name_len_expr = vc.query_fixed(is_mod_name_len, Rotation::cur());
                let is_mut_prop_prev_expr = vc.query_fixed(is_mut_prop, Rotation::prev());
                let is_limit_min_prev_expr = vc.query_fixed(is_limit_min, Rotation::prev());
                let is_limit_max_prev_expr = vc.query_fixed(is_limit_max, Rotation::prev());
                let is_importdesc_val_prev_expr =
                    vc.query_fixed(is_importdesc_val, Rotation::prev());

                and::expr([
                    not::expr(q_first_expr),
                    is_mod_name_len_expr,
                    or::expr([
                        is_items_count_prev_expr,
                        is_mut_prop_prev_expr,
                        is_limit_min_prev_expr,
                        is_limit_max_prev_expr,
                        is_importdesc_val_prev_expr,
                    ]),
                ])
            },
            |vc| vc.query_fixed(q_last, Rotation::cur()),
        );

        cs.create_gate("WasmImportSectionBody gate", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = Self::get_selector_expr_enriched_with_error_processing(vc, q_enable, &shared_state.borrow(), error_code);
            let q_last_expr = vc.query_fixed(q_last, Rotation::cur());
            let not_q_last_expr = not::expr(q_last_expr.clone());
            let is_items_count_expr = vc.query_fixed(is_items_count, Rotation::cur());
            let is_mod_name_len_expr = vc.query_fixed(is_mod_name_len, Rotation::cur());
            let is_mod_name_expr = vc.query_fixed(is_mod_name, Rotation::cur());
            let is_import_name_len_expr = vc.query_fixed(is_import_name_len, Rotation::cur());
            let is_import_name_expr = vc.query_fixed(is_import_name, Rotation::cur());
            let is_importdesc_type_expr = vc.query_fixed(is_importdesc_type, Rotation::cur());
            let is_importdesc_val_expr = vc.query_fixed(is_importdesc_val, Rotation::cur());
            let is_mut_prop_expr = vc.query_fixed(is_mut_prop, Rotation::cur());
            let is_limit_type_expr = vc.query_fixed(is_limit_type, Rotation::cur());
            let is_limit_min_expr = vc.query_fixed(is_limit_min, Rotation::cur());
            let is_limit_max_expr = vc.query_fixed(is_limit_max, Rotation::cur());
            let is_ref_type_expr = vc.query_fixed(is_ref_type, Rotation::cur());

            let is_importdesc_type_ctx_prev_expr = vc.query_fixed(is_importdesc_type_ctx, Rotation::prev());
            let is_importdesc_type_ctx_expr = vc.query_fixed(is_importdesc_type_ctx, Rotation::cur());

            let byte_val_expr = vc.query_advice(wb_table.value, Rotation::cur());
            let importdesc_type_prev_expr = vc.query_advice(importdesc_type, Rotation::prev());
            let importdesc_type_expr = vc.query_advice(importdesc_type, Rotation::cur());

            let utf8_chip_q_enabled_expr = vc.query_fixed(utf8_chip.config.q_enable, Rotation::cur());
            let leb128_is_last_byte_expr = vc.query_fixed(leb128_chip.config.is_last_byte, Rotation::cur());

            cb.require_boolean("q_enable is boolean", q_enable_expr.clone());
            cb.require_boolean("is_items_count is boolean", is_items_count_expr.clone());
            cb.require_boolean("is_mod_name_len is boolean", is_mod_name_len_expr.clone());
            cb.require_boolean("is_mod_name is boolean", is_mod_name_expr.clone());
            cb.require_boolean("is_import_name_len is boolean", is_import_name_len_expr.clone());
            cb.require_boolean("is_import_name is boolean", is_import_name_expr.clone());
            cb.require_boolean("is_importdesc_type is boolean", is_importdesc_type_expr.clone());
            cb.require_boolean("is_importdesc_val is boolean", is_importdesc_val_expr.clone());
            cb.require_boolean("is_mut_prop is boolean", is_mut_prop_expr.clone());
            cb.require_boolean("is_limit_type is boolean", is_limit_type_expr.clone());
            cb.require_boolean("is_limit_min is boolean", is_limit_min_expr.clone());
            cb.require_boolean("is_limit_max is boolean", is_limit_max_expr.clone());
            cb.require_boolean("is_ref_type is boolean", is_ref_type_expr.clone());

            configure_constraints_for_q_first_and_q_last(
                &mut cb,
                vc,
                &q_enable,
                &q_first,
                &[is_items_count],
                &q_last,
                &[is_importdesc_val, is_mut_prop, is_limit_min, is_limit_max],
            );

            cb.condition(
                or::expr([
                    is_importdesc_type_expr.clone(),
                    is_importdesc_val_expr.clone(),
                    is_mut_prop_expr.clone(),
                ]),
                |cb| {
                    cb.require_equal(
                        "is_importdesc_type || is_importdesc_val || is_mut_prop => is_importdesc_type_ctx",
                        is_importdesc_type_ctx_expr.clone(),
                        1.expr(),
                    )
                }
            );
            cb.condition(
                and::expr([
                    is_importdesc_type_ctx_prev_expr.clone(),
                    is_importdesc_type_ctx_expr.clone(),
                ]),
                |cb| {
                    cb.require_equal(
                        "is_importdesc_type_ctx && prev.is_importdesc_type_ctx => importdesc_type=prev.importdesc_type",
                        importdesc_type_expr.clone(),
                        importdesc_type_prev_expr.clone(),
                    )
                }
            );

            cb.require_equal(
                "exactly one mark flag active at the same time",
                is_items_count_expr.clone()
                    + is_mod_name_len_expr.clone()
                    + is_mod_name_expr.clone()
                    + is_import_name_len_expr.clone()
                    + is_import_name_expr.clone()
                    + is_importdesc_type_expr.clone()
                    + is_importdesc_val_expr.clone()
                    + is_mut_prop_expr.clone()
                    + is_limit_type_expr.clone()
                    + is_limit_min_expr.clone()
                    + is_limit_max_expr.clone()
                    + is_ref_type_expr.clone()
                ,
                1.expr(),
            );

            cb.condition(
                is_ref_type_expr.clone(),
                |cb| {
                    cb.require_in_set(
                        "reference_type => byte value is valid",
                        byte_val_expr.clone(),
                        REF_TYPE_VALUES.iter().map(|&v| v.expr()).collect_vec(),
                    )
                }
            );

            // TODO
            // cb.req(
            //     "is_items_count=1 -> first byte val is not 0",
            //     ,
            //     1.expr(),
            // );

            cb.condition(
                or::expr([
                    is_items_count_expr.clone(),
                    is_mod_name_len_expr.clone(),
                    is_import_name_len_expr.clone(),
                    is_importdesc_val_expr.clone(),
                    is_limit_min_expr.clone(),
                    is_limit_max_expr.clone(),
                ]),
                |cb| {
                    cb.require_equal(
                        "is_items_count || is_mod_name_len || is_import_name_len || is_importdesc_val || is_limit_min || is_limit_max => leb128",
                        vc.query_fixed(leb128_chip.config.q_enable, Rotation::cur()),
                        1.expr(),
                    )
                }
            );

            cb.require_equal(
                "is_mod_name || is_import_name -> utf8",
                or::expr([
                    is_mod_name_expr.clone(),
                    is_import_name_expr.clone(),
                ]),
                utf8_chip_q_enabled_expr.clone(),
            );

            cb.condition(
                is_mut_prop_expr.clone(),
                |cb| {
                    cb.require_in_set(
                        "is_mut_prop => byte_val is valid",
                        byte_val_expr.clone(),
                        MUTABILITY_VALUES.iter().map(|&v| v.expr()).collect_vec(),
                    )
                }
            );

            // is_items_count+ -> is_item+ (is_mod_name_len+ -> is_mod_name* -> is_import_name_len+ -> is_import_name* -> import_desc+)
            // let importdesc_type_is_global_type_prev_expr = importdesc_type_chip.config.value_equals(ImportDescType::GlobalType, Rotation::prev())(vc);
            let importdesc_type_is_typeidx_expr = importdesc_type_chip.config.value_equals(ImportDescType::Typeidx, Rotation::cur())(vc);
            // let importdesc_type_is_typeidx_next_expr = importdesc_type_chip.config.value_equals(ImportDescType::Typeidx, Rotation::next())(vc);
            let importdesc_type_is_mem_type_expr = importdesc_type_chip.config.value_equals(ImportDescType::MemType, Rotation::cur())(vc);
            // let importdesc_type_is_mem_type_next_expr = importdesc_type_chip.config.value_equals(ImportDescType::MemType, Rotation::next())(vc);
            let importdesc_type_is_table_type_expr = importdesc_type_chip.config.value_equals(ImportDescType::TableType, Rotation::cur())(vc);
            // let importdesc_type_is_table_type_next_expr = importdesc_type_chip.config.value_equals(ImportDescType::TableType, Rotation::next())(vc);
            let importdesc_type_is_global_type_expr = importdesc_type_chip.config.value_equals(ImportDescType::GlobalType, Rotation::cur())(vc);
            // let importdesc_type_is_global_type_next_expr = importdesc_type_chip.config.value_equals(ImportDescType::GlobalType, Rotation::next())(vc);

            let limit_type_is_min_only_expr = limit_type_chip.config.value_equals(LimitType::MinOnly, Rotation::cur())(vc);
            let limit_type_is_min_max_expr = limit_type_chip.config.value_equals(LimitType::MinMax, Rotation::cur())(vc);

            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_items_count+ -> is_item+ (is_mod_name_len+ ...",
                and::expr([
                    not_q_last_expr.clone(),
                    is_items_count_expr.clone(),
                    importdesc_type_is_typeidx_expr.clone(),
                ]),
                true,
                &[is_items_count, is_mod_name_len],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_items_count+ -> is_item+ (is_mod_name_len+ ...",
                and::expr([
                    not_q_last_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                    is_items_count_expr.clone(),
                    importdesc_type_is_typeidx_expr.clone(),
                ]),
                true,
                &[is_mod_name_len],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_mod_name_len+ -> is_mod_name* -> is_import_name_len+",
                and::expr([
                    not_q_last_expr.clone(),
                    is_mod_name_len_expr.clone(),
                    importdesc_type_is_typeidx_expr.clone(),
                ]),
                true,
                &[is_mod_name_len, is_mod_name, is_import_name_len],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_mod_name_len+ -> is_mod_name* -> is_import_name_len+",
                and::expr([
                    not_q_last_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                    is_mod_name_len_expr.clone(),
                    importdesc_type_is_typeidx_expr.clone(),
                ]),
                true,
                &[is_mod_name, is_import_name_len],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_mod_name* -> is_import_name_len+",
                and::expr([
                    not_q_last_expr.clone(),
                    is_mod_name_expr.clone(),
                    importdesc_type_is_typeidx_expr.clone(),
                ]),
                true,
                &[is_mod_name, is_import_name_len],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_import_name_len+ -> is_import_name* -> is_importdesc_type{1}",
                and::expr([
                    not_q_last_expr.clone(),
                    is_import_name_len_expr.clone(),
                    importdesc_type_is_typeidx_expr.clone(),
                ]),
                true,
                &[is_import_name_len, is_import_name, is_importdesc_type],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_import_name_len+ -> is_import_name* -> is_importdesc_type{1}",
                and::expr([
                    not_q_last_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                    is_import_name_len_expr.clone(),
                    importdesc_type_is_typeidx_expr.clone(),
                ]),
                true,
                &[is_import_name, is_importdesc_type],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_import_name* -> is_importdesc_type{1}",
                and::expr([
                    not_q_last_expr.clone(),
                    is_import_name_expr.clone(),
                    importdesc_type_is_typeidx_expr.clone(),
                ]),
                true,
                &[is_import_name, is_importdesc_type],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_importdesc_type{1} -> is_importdesc_val+",
                and::expr([
                    not_q_last_expr.clone(),
                    is_importdesc_type_expr.clone(),
                    importdesc_type_is_typeidx_expr.clone(),
                ]),
                true,
                &[is_importdesc_val],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_importdesc_val+",
                and::expr([
                    not_q_last_expr.clone(),
                    is_importdesc_val_expr.clone(),
                    importdesc_type_is_typeidx_expr.clone(),
                ]),
                true,
                &[is_importdesc_val, is_mod_name_len],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_importdesc_val+",
                and::expr([
                    not_q_last_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                    is_importdesc_val_expr.clone(),
                    importdesc_type_is_typeidx_expr.clone(),
                ]),
                true,
                &[is_mod_name_len],
            );
            // importdesc_type{1}=3(ImportDescType::Globaltype): import_desc+(is_importdesc_type{1} -> is_importdesc_val+ -> is_mut_prop{1})
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_items_count+ -> is_item+ (is_mod_name_len+ ...",
                and::expr([
                    not_q_last_expr.clone(),
                    is_items_count_expr.clone(),
                    importdesc_type_is_global_type_expr.clone(),
                ]),
                true,
                &[is_items_count, is_mod_name_len],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_items_count+ -> is_item+ (is_mod_name_len+ ...",
                and::expr([
                    not_q_last_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                    is_items_count_expr.clone(),
                    importdesc_type_is_global_type_expr.clone(),
                ]),
                true,
                &[is_mod_name_len],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_mod_name_len+ -> is_mod_name* -> is_import_name_len+",
                and::expr([
                    not_q_last_expr.clone(),
                    is_mod_name_len_expr.clone(),
                    importdesc_type_is_global_type_expr.clone(),
                ]),
                true,
                &[is_mod_name_len, is_mod_name, is_import_name_len],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_mod_name_len+ -> is_mod_name* -> is_import_name_len+",
                and::expr([
                    not_q_last_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                    is_mod_name_len_expr.clone(),
                    importdesc_type_is_global_type_expr.clone(),
                ]),
                true,
                &[is_mod_name, is_import_name_len],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_mod_name* -> is_import_name_len+",
                and::expr([
                    not_q_last_expr.clone(),
                    is_mod_name_expr.clone(),
                    importdesc_type_is_global_type_expr.clone(),
                ]),
                true,
                &[is_mod_name, is_import_name_len],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_import_name_len+ -> is_import_name* -> is_importdesc_type{1}",
                and::expr([
                    not_q_last_expr.clone(),
                    is_import_name_len_expr.clone(),
                    importdesc_type_is_global_type_expr.clone(),
                ]),
                true,
                &[is_import_name_len, is_import_name, is_importdesc_type],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_import_name_len+ -> is_import_name* -> is_importdesc_type{1}",
                and::expr([
                    not_q_last_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                    is_import_name_len_expr.clone(),
                    importdesc_type_is_global_type_expr.clone(),
                ]),
                true,
                &[is_import_name, is_importdesc_type],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_import_name* -> is_importdesc_type{1}",
                and::expr([
                    not_q_last_expr.clone(),
                    is_import_name_expr.clone(),
                    importdesc_type_is_global_type_expr.clone(),
                ]),
                true,
                &[is_import_name, is_importdesc_type],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_importdesc_type{1} -> is_importdesc_val+",
                and::expr([
                    not_q_last_expr.clone(),
                    is_importdesc_type_expr.clone(),
                    importdesc_type_is_global_type_expr.clone(),
                ]),
                true,
                &[is_importdesc_val],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_importdesc_val+ -> is_mut_prop{1}",
                and::expr([
                    not_q_last_expr.clone(),
                    is_importdesc_val_expr.clone(),
                    importdesc_type_is_global_type_expr.clone(),
                ]),
                true,
                &[is_importdesc_val, is_mut_prop],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_importdesc_val+ -> is_mut_prop{1}",
                and::expr([
                    not_q_last_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                    is_importdesc_val_expr.clone(),
                    importdesc_type_is_global_type_expr.clone(),
                ]),
                true,
                &[is_mut_prop],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_mut_prop{1}",
                and::expr([
                    not_q_last_expr.clone(),
                    is_mut_prop_expr.clone(),
                    importdesc_type_is_global_type_expr.clone(),
                ]),
                true,
                &[is_mod_name_len],
            );
            // importdesc_type{1}=ImportDescType::Memtype: import_desc+(is_importdesc_type{1} -> limit_type{1} -> limit_min+ -> limit_max*)
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_items_count+ -> is_item+ (is_mod_name_len+ ...",
                and::expr([
                    not_q_last_expr.clone(),
                    is_items_count_expr.clone(),
                    importdesc_type_is_mem_type_expr.clone(),
                ]),
                true,
                &[is_items_count, is_mod_name_len],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_items_count+ -> is_item+ (is_mod_name_len+ ...",
                and::expr([
                    not_q_last_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                    is_items_count_expr.clone(),
                    importdesc_type_is_mem_type_expr.clone(),
                ]),
                true,
                &[is_mod_name_len],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_mod_name_len+ -> is_mod_name* -> is_import_name_len+",
                and::expr([
                    not_q_last_expr.clone(),
                    is_mod_name_len_expr.clone(),
                    importdesc_type_is_mem_type_expr.clone(),
                ]),
                true,
                &[is_mod_name_len, is_mod_name, is_import_name_len],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_mod_name_len+ -> is_mod_name* -> is_import_name_len+",
                and::expr([
                    not_q_last_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                    is_mod_name_len_expr.clone(),
                    importdesc_type_is_mem_type_expr.clone(),
                ]),
                true,
                &[is_mod_name, is_import_name_len],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_mod_name* -> is_import_name_len+",
                and::expr([
                    not_q_last_expr.clone(),
                    is_mod_name_expr.clone(),
                    importdesc_type_is_mem_type_expr.clone(),
                ]),
                true,
                &[is_mod_name, is_import_name_len],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_import_name_len+ -> is_import_name* -> is_importdesc_type{1}",
                and::expr([
                    not_q_last_expr.clone(),
                    is_import_name_len_expr.clone(),
                    importdesc_type_is_mem_type_expr.clone(),
                ]),
                true,
                &[is_import_name_len, is_import_name, is_importdesc_type],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_import_name_len+ -> is_import_name* -> is_importdesc_type{1}",
                and::expr([
                    not_q_last_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                    is_import_name_len_expr.clone(),
                    importdesc_type_is_mem_type_expr.clone(),
                ]),
                true,
                &[is_import_name, is_importdesc_type],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_import_name* -> is_importdesc_type{1}",
                and::expr([
                    not_q_last_expr.clone(),
                    is_import_name_expr.clone(),
                    importdesc_type_is_mem_type_expr.clone(),
                ]),
                true,
                &[is_import_name, is_importdesc_type],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_importdesc_type{1} -> limit_type{1}",
                and::expr([
                    not_q_last_expr.clone(),
                    is_importdesc_type_expr.clone(),
                    importdesc_type_is_mem_type_expr.clone(),
                ]),
                true,
                &[is_limit_type],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: limit_type{1} -> limit_min+",
                and::expr([
                    not_q_last_expr.clone(),
                    is_limit_type_expr.clone(),
                    importdesc_type_is_mem_type_expr.clone(),
                ]),
                true,
                &[is_limit_min],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: limit_min+",
                and::expr([
                    not_q_last_expr.clone(),
                    is_limit_min_expr.clone(),
                    limit_type_is_min_only_expr.clone(),
                    importdesc_type_is_mem_type_expr.clone(),
                ]),
                true,
                &[is_limit_min],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: limit_min+",
                and::expr([
                    not_q_last_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                    is_limit_min_expr.clone(),
                    limit_type_is_min_only_expr.clone(),
                    importdesc_type_is_mem_type_expr.clone(),
                ]),
                true,
                &[is_limit_min],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: limit_min+ -> limit_max+",
                and::expr([
                    not_q_last_expr.clone(),
                    is_limit_min_expr.clone(),
                    limit_type_is_min_max_expr.clone(),
                    importdesc_type_is_mem_type_expr.clone(),
                ]),
                true,
                &[is_limit_min, is_limit_max],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: limit_min+ -> limit_max+",
                and::expr([
                    not_q_last_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                    is_limit_min_expr.clone(),
                    limit_type_is_min_max_expr.clone(),
                    importdesc_type_is_mem_type_expr.clone(),
                ]),
                true,
                &[is_limit_max],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: limit_max*",
                and::expr([
                    not_q_last_expr.clone(),
                    is_limit_max_expr.clone(),
                ]),
                true,
                &[is_limit_max, is_mod_name_len],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: limit_max*",
                and::expr([
                    not_q_last_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                    is_limit_max_expr.clone(),
                ]),
                true,
                &[is_mod_name_len],
            );
            // importdesc_type{1}=ImportDescType::Tabletype: import_desc+(is_importdesc_type{1} -> ref_type{1} -> limit_type{1} -> limit_min+ -> limit_max*)
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_items_count+ -> is_item+ (is_mod_name_len+ ...",
                and::expr([
                    not_q_last_expr.clone(),
                    is_items_count_expr.clone(),
                    importdesc_type_is_table_type_expr.clone(),
                ]),
                true,
                &[is_items_count, is_mod_name_len],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_items_count+ -> is_item+ (is_mod_name_len+ ...",
                and::expr([
                    not_q_last_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                    is_items_count_expr.clone(),
                    importdesc_type_is_table_type_expr.clone(),
                ]),
                true,
                &[is_mod_name_len],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_mod_name_len+ -> is_mod_name* -> is_import_name_len+",
                and::expr([
                    not_q_last_expr.clone(),
                    is_mod_name_len_expr.clone(),
                    importdesc_type_is_table_type_expr.clone(),
                ]),
                true,
                &[is_mod_name_len, is_mod_name, is_import_name_len],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_mod_name_len+ -> is_mod_name* -> is_import_name_len+",
                and::expr([
                    not_q_last_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                    is_mod_name_len_expr.clone(),
                    importdesc_type_is_table_type_expr.clone(),
                ]),
                true,
                &[is_mod_name, is_import_name_len],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_mod_name* -> is_import_name_len+",
                and::expr([
                    not_q_last_expr.clone(),
                    is_mod_name_expr.clone(),
                    importdesc_type_is_table_type_expr.clone(),
                ]),
                true,
                &[is_mod_name, is_import_name_len],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_import_name_len+ -> is_import_name* -> is_importdesc_type{1}",
                and::expr([
                    not_q_last_expr.clone(),
                    is_import_name_len_expr.clone(),
                    importdesc_type_is_table_type_expr.clone(),
                ]),
                true,
                &[is_import_name_len, is_import_name, is_importdesc_type],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_import_name_len+ -> is_import_name* -> is_importdesc_type{1}",
                and::expr([
                    not_q_last_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                    is_import_name_len_expr.clone(),
                    importdesc_type_is_table_type_expr.clone(),
                ]),
                true,
                &[is_import_name, is_importdesc_type],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_import_name* -> is_importdesc_type{1}",
                and::expr([
                    not_q_last_expr.clone(),
                    is_import_name_expr.clone(),
                    importdesc_type_is_table_type_expr.clone(),
                ]),
                true,
                &[is_import_name, is_importdesc_type],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_importdesc_type{1} -> ref_type{1}",
                and::expr([
                    not_q_last_expr.clone(),
                    is_importdesc_type_expr.clone(),
                    importdesc_type_is_table_type_expr.clone(),
                ]),
                true,
                &[is_ref_type],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: ref_type{1} -> limit_type{1}",
                and::expr([
                    not_q_last_expr.clone(),
                    is_ref_type_expr.clone(),
                    importdesc_type_is_table_type_expr.clone(),
                ]),
                true,
                &[is_limit_type],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: limit_type{1} -> limit_min+",
                and::expr([
                    not_q_last_expr.clone(),
                    is_limit_type_expr.clone(),
                    importdesc_type_is_table_type_expr.clone(),
                ]),
                true,
                &[is_limit_min],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: limit_min+",
                and::expr([
                    not_q_last_expr.clone(),
                    is_limit_min_expr.clone(),
                    limit_type_is_min_only_expr.clone(),
                    importdesc_type_is_table_type_expr.clone(),
                ]),
                true,
                &[is_limit_min],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: limit_min+",
                and::expr([
                    not_q_last_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                    is_limit_min_expr.clone(),
                    limit_type_is_min_only_expr.clone(),
                    importdesc_type_is_table_type_expr.clone(),
                ]),
                true,
                &[is_limit_min],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: limit_min+ -> limit_max*",
                and::expr([
                    not_q_last_expr.clone(),
                    is_limit_min_expr.clone(),
                    limit_type_is_min_max_expr.clone(),
                    importdesc_type_is_table_type_expr.clone(),
                ]),
                true,
                &[is_limit_min, is_limit_max],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: limit_min+ -> limit_max*",
                and::expr([
                    not_q_last_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                    is_limit_min_expr.clone(),
                    limit_type_is_min_max_expr.clone(),
                    importdesc_type_is_table_type_expr.clone(),
                ]),
                true,
                &[is_limit_max],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: limit_max*",
                and::expr([
                    not_q_last_expr.clone(),
                    is_limit_max_expr.clone(),
                ]),
                true,
                &[is_limit_max, is_mod_name_len],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: limit_max*",
                and::expr([
                    not_q_last_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                    is_limit_max_expr.clone(),
                ]),
                true,
                &[is_mod_name_len],
            );

            cb.condition(
                is_importdesc_type_expr.clone(),
                |cb| {
                    cb.require_in_set(
                        "is_importdesc_type => value is valid",
                        byte_val_expr.clone(),
                        IMPORT_DESC_TYPE_VALUES.iter().map(|&v| v.expr()).collect_vec()
                    );
                    cb.require_equal(
                        "is_importdesc_type => importdesc_type has valid value",
                        importdesc_type_expr.clone(),
                        byte_val_expr.clone(),
                    );
                }
            );

            cb.gate(q_enable_expr.clone())
        });

        let config = WasmImportSectionBodyConfig::<F> {
            _marker: PhantomData,

            q_enable,
            q_first,
            q_last,
            is_items_count,
            is_mod_name_len,
            is_mod_name,
            is_import_name_len,
            is_import_name,
            is_importdesc_type,
            is_importdesc_type_ctx,
            is_importdesc_val,
            is_mut_prop,
            limit_type_fields,
            is_ref_type,
            leb128_chip,
            utf8_chip,
            dynamic_indexes_chip,
            importdesc_type,
            importdesc_type_chip,
            func_count,
            body_byte_rev_index,
            body_item_rev_count,
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
        assign_delta: AssignDeltaType,
    ) -> Result<NewWbOffsetType, Error> {
        let mut offset = wb_offset;

        self.assign(
            region,
            &wb,
            offset,
            assign_delta,
            &[AssignType::QFirst],
            1,
            None,
        )?;
        // is_items_count+
        let (items_count, items_count_leb_len) = self.markup_leb_section(
            region,
            wb,
            offset,
            assign_delta,
            &[AssignType::IsItemsCount, AssignType::FuncCount],
        )?;
        let mut body_item_rev_count = items_count;
        for offset in offset..offset + items_count_leb_len {
            self.assign(
                region,
                &wb,
                offset,
                assign_delta,
                &[AssignType::BodyItemRevCount, AssignType::FuncCount],
                body_item_rev_count,
                None,
            )?;
        }
        offset += items_count_leb_len;

        for _item_index in 0..items_count {
            body_item_rev_count -= 1;
            let item_start_offset = offset;

            // is_mod_name_len+
            let (mod_name_len, mod_name_leb_len) = self.markup_leb_section(
                region,
                wb,
                offset,
                assign_delta,
                &[AssignType::IsModNameLen, AssignType::FuncCount],
            )?;
            let mod_name_len_last_byte_offset = offset + mod_name_leb_len - 1;
            let mod_name_last_byte_offset = mod_name_len_last_byte_offset + mod_name_len as usize;
            for offset in mod_name_len_last_byte_offset..=mod_name_last_byte_offset {
                self.assign(
                    region,
                    &wb,
                    offset,
                    assign_delta,
                    &[AssignType::BodyByteRevIndex, AssignType::FuncCount],
                    (mod_name_last_byte_offset - offset) as u64,
                    None,
                )?;
            }
            offset += mod_name_leb_len;

            // is_mod_name*
            self.markup_name_section(
                region,
                wb,
                offset,
                assign_delta,
                &[AssignType::IsModName, AssignType::FuncCount],
                mod_name_len as usize,
                1,
            )?;
            offset += mod_name_len as usize;

            // is_import_name_len+
            let (import_name_len, import_name_leb_len) = self.markup_leb_section(
                region,
                wb,
                offset,
                assign_delta,
                &[AssignType::IsImportNameLen, AssignType::FuncCount],
            )?;
            let import_name_len_last_byte_offset = offset + import_name_leb_len - 1;
            let import_name_last_byte_offset =
                import_name_len_last_byte_offset + import_name_len as usize;
            for offset in import_name_len_last_byte_offset..=import_name_last_byte_offset {
                self.assign(
                    region,
                    &wb,
                    offset,
                    assign_delta,
                    &[AssignType::BodyByteRevIndex, AssignType::FuncCount],
                    (import_name_last_byte_offset - offset) as u64,
                    None,
                )?;
            }
            offset += import_name_leb_len;

            // is_import_name*
            self.markup_name_section(
                region,
                wb,
                offset,
                assign_delta,
                &[AssignType::IsImportName, AssignType::FuncCount],
                import_name_len as usize,
                1,
            )?;
            offset += import_name_len as usize;

            // is_importdesc_type{1}
            let importdesc_type_val = wb.bytes[offset];
            let importdesc_type: ImportDescType = importdesc_type_val
                .try_into()
                .map_err(remap_error_to_invalid_enum_value_at(offset))?;
            let importdesc_type_val = importdesc_type_val as u64;
            if importdesc_type == ImportDescType::Typeidx {
                self.config.shared_state.borrow_mut().func_count += 1;
            }
            self.assign(
                region,
                wb,
                offset,
                assign_delta,
                &[
                    AssignType::IsImportdescType,
                    AssignType::IsImportdescTypeCtx,
                    AssignType::FuncCount,
                ],
                1,
                None,
            )?;
            self.assign(
                region,
                &wb,
                offset,
                assign_delta,
                &[AssignType::ImportdescType, AssignType::FuncCount],
                importdesc_type_val,
                None,
            )?;
            self.config
                .importdesc_type_chip
                .assign(region, offset + assign_delta, &importdesc_type)
                .map_err(remap_error(Error::FatalAssignExternalChip))?;
            offset += 1;

            // is_importdesc_val+
            match importdesc_type {
                ImportDescType::Typeidx => {
                    let (_importdesc_val, importdesc_val_leb_len) = self.markup_leb_section(
                        region,
                        wb,
                        offset,
                        assign_delta,
                        &[
                            AssignType::IsImportdescVal,
                            AssignType::IsImportdescTypeCtx,
                            AssignType::FuncCount,
                        ],
                    )?;
                    for offset in offset..offset + importdesc_val_leb_len {
                        self.assign(
                            region,
                            &wb,
                            offset,
                            assign_delta,
                            &[AssignType::ImportdescType],
                            importdesc_type_val,
                            None,
                        )?;
                        self.config
                            .importdesc_type_chip
                            .assign(region, offset + assign_delta, &importdesc_type)
                            .map_err(remap_error(Error::FatalAssignExternalChip))?;
                    }
                    offset += importdesc_val_leb_len;
                }
                ImportDescType::GlobalType => {
                    let (_importdesc_val, importdesc_val_leb_len) = self.markup_leb_section(
                        region,
                        wb,
                        offset,
                        assign_delta,
                        &[
                            AssignType::IsImportdescVal,
                            AssignType::IsImportdescTypeCtx,
                            AssignType::FuncCount,
                        ],
                    )?;
                    for offset in offset..offset + importdesc_val_leb_len {
                        self.assign(
                            region,
                            &wb,
                            offset,
                            assign_delta,
                            &[AssignType::ImportdescType, AssignType::FuncCount],
                            importdesc_type_val,
                            None,
                        )?;
                        self.config
                            .importdesc_type_chip
                            .assign(region, offset + assign_delta, &importdesc_type)
                            .map_err(remap_error(Error::FatalAssignExternalChip))?;
                    }
                    offset += importdesc_val_leb_len;

                    self.assign(
                        region,
                        wb,
                        offset,
                        assign_delta,
                        &[
                            AssignType::IsMut,
                            AssignType::IsImportdescTypeCtx,
                            AssignType::FuncCount,
                        ],
                        1,
                        None,
                    )?;
                    for offset in offset..offset + importdesc_val_leb_len {
                        self.assign(
                            region,
                            &wb,
                            offset,
                            assign_delta,
                            &[AssignType::ImportdescType, AssignType::FuncCount],
                            importdesc_type_val,
                            None,
                        )?;
                        self.config
                            .importdesc_type_chip
                            .assign(region, offset + assign_delta, &importdesc_type)
                            .map_err(remap_error(Error::FatalAssignExternalChip))?;
                    }
                    offset += 1;
                }
                ImportDescType::MemType => {
                    // limit_type{1}
                    let limit_type_val = wb.bytes[offset];
                    let limit_type: LimitType = limit_type_val
                        .try_into()
                        .map_err(remap_error_to_invalid_enum_value_at(offset))?;
                    let limit_type_val = limit_type_val as u64;
                    self.assign(
                        region,
                        wb,
                        offset,
                        assign_delta,
                        &[
                            AssignType::IsLimitType,
                            AssignType::IsLimitTypeCtx,
                            AssignType::FuncCount,
                        ],
                        1,
                        None,
                    )?;
                    self.assign(
                        region,
                        wb,
                        offset,
                        assign_delta,
                        &[AssignType::LimitType],
                        limit_type_val,
                        None,
                    )?;
                    offset += 1;

                    // limit_min+
                    let (_limit_min, limit_min_leb_len) = self.markup_leb_section(
                        region,
                        wb,
                        offset,
                        assign_delta,
                        &[
                            AssignType::IsLimitMin,
                            AssignType::IsLimitTypeCtx,
                            AssignType::FuncCount,
                        ],
                    )?;
                    for offset in offset..offset + limit_min_leb_len {
                        self.assign(
                            region,
                            wb,
                            offset,
                            assign_delta,
                            &[AssignType::LimitType],
                            limit_type_val,
                            None,
                        )?;
                    }
                    offset += limit_min_leb_len;

                    // limit_max*
                    if limit_type == LimitType::MinMax {
                        let (_limit_max, limit_max_leb_len) = self.markup_leb_section(
                            region,
                            wb,
                            offset,
                            assign_delta,
                            &[
                                AssignType::IsLimitMax,
                                AssignType::IsLimitTypeCtx,
                                AssignType::FuncCount,
                            ],
                        )?;
                        for offset in offset..offset + limit_max_leb_len {
                            self.assign(
                                region,
                                wb,
                                offset,
                                assign_delta,
                                &[AssignType::LimitType],
                                limit_type_val,
                                None,
                            )?;
                        }
                        offset += limit_max_leb_len;
                    }
                }
                ImportDescType::TableType => {
                    // ref_type{1}
                    let ref_type_val = wb.bytes[offset];
                    let ref_type: RefType = ref_type_val
                        .try_into()
                        .map_err(remap_error_to_invalid_enum_value_at(offset))?;
                    let ref_type_val = ref_type_val as u64;
                    self.assign(
                        region,
                        wb,
                        offset,
                        assign_delta,
                        &[AssignType::IsRefType, AssignType::FuncCount],
                        1,
                        None,
                    )?;
                    offset += 1;

                    // limit_type{1}
                    let limit_type_val = wb.bytes[offset];
                    let limit_type: LimitType = limit_type_val
                        .try_into()
                        .map_err(remap_error_to_invalid_enum_value_at(offset))?;
                    let limit_type_val = limit_type_val as u64;
                    self.assign(
                        region,
                        wb,
                        offset,
                        assign_delta,
                        &[
                            AssignType::IsLimitType,
                            AssignType::IsLimitTypeCtx,
                            AssignType::FuncCount,
                        ],
                        1,
                        None,
                    )?;
                    self.assign(
                        region,
                        wb,
                        offset,
                        assign_delta,
                        &[AssignType::LimitType, AssignType::FuncCount],
                        limit_type_val,
                        None,
                    )?;
                    offset += 1;

                    // limit_min+
                    let (limit_min, limit_min_leb_len) = self.markup_leb_section(
                        region,
                        wb,
                        offset,
                        assign_delta,
                        &[
                            AssignType::IsLimitMin,
                            AssignType::IsLimitTypeCtx,
                            AssignType::FuncCount,
                        ],
                    )?;
                    for offset in offset..offset + limit_min_leb_len {
                        self.assign(
                            region,
                            wb,
                            offset,
                            assign_delta,
                            &[AssignType::LimitType, AssignType::FuncCount],
                            limit_type_val,
                            None,
                        )?;
                    }
                    offset += limit_min_leb_len;

                    // limit_max*
                    if limit_type == LimitType::MinMax {
                        let (limit_max, limit_max_leb_len) = self.markup_leb_section(
                            region,
                            wb,
                            offset,
                            assign_delta,
                            &[
                                AssignType::IsLimitMax,
                                AssignType::IsLimitTypeCtx,
                                AssignType::FuncCount,
                            ],
                        )?;
                        for offset in offset..offset + limit_max_leb_len {
                            self.assign(
                                region,
                                wb,
                                offset,
                                assign_delta,
                                &[AssignType::LimitType, AssignType::FuncCount],
                                limit_type_val,
                                None,
                            )?;
                        }
                        self.config
                            .limit_type_fields
                            .limit_type_params_lt_chip
                            .assign(
                                region,
                                offset + assign_delta,
                                F::from(limit_min),
                                F::from(limit_max),
                            )
                            .map_err(remap_error(Error::FatalAssignExternalChip))?;
                        offset += limit_max_leb_len;
                    }
                }
            }

            for offset in item_start_offset..offset {
                self.assign(
                    region,
                    &wb,
                    offset,
                    assign_delta,
                    &[AssignType::BodyItemRevCount],
                    body_item_rev_count,
                    None,
                )?;
            }
        }

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
