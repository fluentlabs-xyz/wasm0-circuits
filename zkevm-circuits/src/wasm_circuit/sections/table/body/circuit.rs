use std::cell::RefCell;
use std::marker::PhantomData;
use std::rc::Rc;

use halo2_proofs::{
    plonk::{Column, ConstraintSystem},
};
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::plonk::{Advice, Fixed};
use halo2_proofs::poly::Rotation;
use itertools::Itertools;
use log::debug;

use eth_types::Field;
use gadgets::less_than::LtInstruction;
use gadgets::util::{and, Expr, not, or};

use crate::evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon};
use crate::wasm_circuit::bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::common::{LimitTypeFields, WasmAssignAwareChip, WasmErrorAwareChip, WasmFuncCountAwareChip, WasmLimitTypeAwareChip, WasmMarkupLeb128SectionAwareChip, WasmSharedStateAwareChip};
use crate::wasm_circuit::common::{configure_constraints_for_q_first_and_q_last, configure_transition_check};
use crate::wasm_circuit::consts::{LimitType, REF_TYPE_VALUES};
use crate::wasm_circuit::error::{Error, remap_error, remap_error_to_assign_at_offset};
use crate::wasm_circuit::leb128::circuit::LEB128Chip;
use crate::wasm_circuit::sections::consts::LebParams;
use crate::wasm_circuit::sections::table::body::types::AssignType;
use crate::wasm_circuit::tables::dynamic_indexes::circuit::DynamicIndexesChip;
use crate::wasm_circuit::tables::dynamic_indexes::types::Tag;
use crate::wasm_circuit::types::SharedState;

#[derive(Debug, Clone)]
pub struct WasmTableSectionBodyConfig<F: Field> {
    pub q_enable: Column<Fixed>,
    pub q_first: Column<Fixed>,
    pub q_last: Column<Fixed>,
    pub is_reference_type_count: Column<Fixed>,
    pub is_reference_type: Column<Fixed>,

    pub limit_type_fields: LimitTypeFields<F>,

    pub leb128_chip: Rc<LEB128Chip<F>>,
    pub dynamic_indexes_chip: Rc<DynamicIndexesChip<F>>,

    pub func_count: Column<Advice>,
    pub error_code: Column<Advice>,
    shared_state: Rc<RefCell<SharedState>>,

    _marker: PhantomData<F>,
}

impl<'a, F: Field> WasmTableSectionBodyConfig<F>
{}

#[derive(Debug, Clone)]
pub struct WasmTableSectionBodyChip<F: Field> {
    pub config: WasmTableSectionBodyConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> WasmMarkupLeb128SectionAwareChip<F> for WasmTableSectionBodyChip<F> {}

impl<F: Field> WasmLimitTypeAwareChip<F> for WasmTableSectionBodyChip<F> {}

impl<F: Field> WasmErrorAwareChip<F> for WasmTableSectionBodyChip<F> {
    fn error_code_col(&self) -> Column<Advice> { self.config.error_code }
}

impl<F: Field> WasmSharedStateAwareChip<F> for WasmTableSectionBodyChip<F> {
    fn shared_state(&self) -> Rc<RefCell<SharedState>> { self.config.shared_state.clone() }
}

impl<F: Field> WasmFuncCountAwareChip<F> for WasmTableSectionBodyChip<F> {
    fn func_count_col(&self) -> Column<Advice> { self.config.func_count }
}

impl<F: Field> WasmAssignAwareChip<F> for WasmTableSectionBodyChip<F> {
    type AssignType = AssignType;

    fn assign_internal(
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
        ).map_err(remap_error_to_assign_at_offset(offset))?;
        self.assign_func_count(region, offset)?;

        for assign_type in assign_types {
            if [
                AssignType::IsReferenceTypeCount,
                AssignType::IsLimitMin,
                AssignType::IsLimitMax
            ].contains(assign_type) {
                let p = leb_params.unwrap();
                self.config.leb128_chip.assign(
                    region,
                    offset,
                    q_enable,
                    p,
                )?;
            }
            match assign_type {
                AssignType::QFirst => {
                    region.assign_fixed(
                        || format!("assign 'q_first' val {} at {}", assign_value, offset),
                        self.config.q_first,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).map_err(remap_error_to_assign_at_offset(offset))?;
                }
                AssignType::QLast => {
                    region.assign_fixed(
                        || format!("assign 'q_last' val {} at {}", assign_value, offset),
                        self.config.q_last,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).map_err(remap_error_to_assign_at_offset(offset))?;
                }
                AssignType::IsReferenceTypeCount => {
                    region.assign_fixed(
                        || format!("assign 'is_reference_type_count' val {} at {}", assign_value, offset),
                        self.config.is_reference_type_count,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).map_err(remap_error_to_assign_at_offset(offset))?;
                }
                AssignType::IsReferenceType => {
                    region.assign_fixed(
                        || format!("assign 'is_reference_type' val {} at {}", assign_value, offset),
                        self.config.is_reference_type,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).map_err(remap_error_to_assign_at_offset(offset))?;
                }
                AssignType::IsLimitType => {
                    region.assign_fixed(
                        || format!("assign 'is_limit_type' val {} at {}", assign_value, offset),
                        self.config.limit_type_fields.is_limit_type,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).map_err(remap_error_to_assign_at_offset(offset))?;
                }
                AssignType::IsLimitMin => {
                    region.assign_fixed(
                        || format!("assign 'is_limit_min' val {} at {}", assign_value, offset),
                        self.config.limit_type_fields.is_limit_min,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).map_err(remap_error_to_assign_at_offset(offset))?;
                }
                AssignType::IsLimitMax => {
                    region.assign_fixed(
                        || format!("assign 'is_limit_max' val {} at {}", assign_value, offset),
                        self.config.limit_type_fields.is_limit_max,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).map_err(remap_error_to_assign_at_offset(offset))?;
                }
                AssignType::IsLimitTypeCtx => {
                    region.assign_fixed(
                        || format!("assign 'is_limit_type_ctx' val {} at {}", assign_value, offset),
                        self.config.limit_type_fields.is_limit_type_ctx,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).map_err(remap_error_to_assign_at_offset(offset))?;
                }
                AssignType::LimitType => {
                    region.assign_advice(
                        || format!("assign 'limit_type' val {} at {}", assign_value, offset),
                        self.config.limit_type_fields.limit_type,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).map_err(remap_error_to_assign_at_offset(offset))?;
                    let limit_type: LimitType = (assign_value as u8).try_into()?;
                    self.config.limit_type_fields.limit_type_chip.assign(
                        region,
                        offset,
                        &limit_type,
                    ).map_err(remap_error_to_assign_at_offset(offset))?;
                }
                AssignType::ErrorCode => {
                    self.assign_error_code(region, offset, None)?;
                }
            }
        };
        Ok(())
    }
}

impl<F: Field> WasmTableSectionBodyChip<F>
{
    pub fn construct(config: WasmTableSectionBodyConfig<F>) -> Self {
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
        dynamic_indexes_chip: Rc<DynamicIndexesChip<F>>,
        func_count: Column<Advice>,
        error_code: Column<Advice>,
        shared_state: Rc<RefCell<SharedState>>,
    ) -> WasmTableSectionBodyConfig<F> {
        let q_enable = cs.fixed_column();
        let q_first = cs.fixed_column();
        let q_last = cs.fixed_column();
        let is_reference_type_count = cs.fixed_column();
        let is_reference_type = cs.fixed_column();

        let limit_type_fields = Self::construct_limit_type_fields(
            cs,
            q_enable,
            leb128_chip.as_ref(),
        );
        Self::configure_limit_type_constraints(
            cs,
            bytecode_table.as_ref(),
            q_enable,
            leb128_chip.as_ref(),
            &limit_type_fields,
        );

        let LimitTypeFields {
            is_limit_type,
            is_limit_min,
            is_limit_max,
            limit_type,
            limit_type_chip,
            is_limit_type_ctx,
            ..
        } = limit_type_fields.clone();

        cs.create_gate("WasmTableSectionBody gate", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
            // let q_first_expr = vc.query_fixed(q_first, Rotation::cur());
            let q_last_expr = vc.query_fixed(q_last, Rotation::cur());
            let not_q_last_expr = not::expr(q_last_expr.clone());
            let is_reference_type_count_expr = vc.query_fixed(is_reference_type_count, Rotation::cur());
            let is_reference_type_expr = vc.query_fixed(is_reference_type, Rotation::cur());
            let is_limit_type_expr = vc.query_fixed(is_limit_type, Rotation::cur());
            let is_limit_min_expr = vc.query_fixed(is_limit_min, Rotation::cur());
            let is_limit_max_expr = vc.query_fixed(is_limit_max, Rotation::cur());

            let is_limit_type_ctx_expr = vc.query_fixed(is_limit_type_ctx, Rotation::cur());

            let byte_val_expr = vc.query_advice(bytecode_table.value, Rotation::cur());
            let limit_type_prev_expr = vc.query_advice(limit_type, Rotation::prev());
            let limit_type_expr = vc.query_advice(limit_type, Rotation::cur());

            let limit_type_is_min_only_expr = limit_type_chip.config.value_equals(LimitType::MinOnly, Rotation::cur())(vc);
            let limit_type_is_min_max_expr = limit_type_chip.config.value_equals(LimitType::MinMax, Rotation::cur())(vc);

            let leb128_is_last_byte_expr = vc.query_fixed(leb128_chip.config.is_last_byte, Rotation::cur());

            cb.require_boolean("q_enable is boolean", q_enable_expr.clone());
            cb.require_boolean("is_reference_type_count is boolean", is_reference_type_count_expr.clone());
            cb.require_boolean("is_reference_type is boolean", is_reference_type_expr.clone());
            cb.require_boolean("is_limit_type is boolean", is_limit_type_expr.clone());
            cb.require_boolean("is_limit_min is boolean", is_limit_min_expr.clone());
            cb.require_boolean("is_limit_max is boolean", is_limit_max_expr.clone());
            cb.require_boolean("is_limit_type_ctx is boolean", is_limit_type_ctx_expr.clone());

            configure_constraints_for_q_first_and_q_last(
                &mut cb,
                vc,
                &q_enable,
                &q_first,
                &[is_reference_type_count],
                &q_last,
                &[is_limit_min, is_limit_max],
            );

            cb.require_equal(
                "exactly one mark flag active at the same time",
                is_reference_type_count_expr.clone()
                    + is_reference_type_expr.clone()
                    + is_limit_type_expr.clone()
                    + is_limit_min_expr.clone()
                    + is_limit_max_expr.clone(),
                1.expr(),
            );

            cb.condition(
                or::expr([
                    is_reference_type_count_expr.clone(),
                    is_limit_min_expr.clone(),
                    is_limit_max_expr.clone(),
                ]),
                |cb| {
                    cb.require_equal(
                        "is_reference_type_count || is_limit_min || is_limit_max => leb128",
                        vc.query_fixed(leb128_chip.config.q_enable, Rotation::cur()),
                        1.expr(),
                    )
                }
            );

            cb.condition(
                is_reference_type_expr.clone(),
                |cb| {
                    cb.require_in_set(
                        "reference_type => byte value is valid",
                        byte_val_expr.clone(),
                        REF_TYPE_VALUES.iter().map(|&v| v.expr()).collect_vec(),
                    )
                }
            );

            cb.condition(
                is_limit_type_expr.clone(),
                |cb| {
                    cb.require_in_set(
                        "limit_type => byte value is valid",
                        byte_val_expr.clone(),
                        vec![
                            LimitType::MinOnly.expr(),
                            LimitType::MinMax.expr(),
                        ],
                    )
                }
            );
            cb.require_equal(
                "is_limit_type_ctx active on a specific flags only",
                is_limit_type_expr.clone()
                    + is_limit_min_expr.clone()
                    + is_limit_max_expr.clone()
                ,
                is_limit_type_ctx_expr.clone(),
            );
            cb.condition(
                is_limit_type_expr.clone(),
                |cb| {
                    cb.require_equal(
                        "is_limit_type => limit_type=byte_val",
                        limit_type_expr.clone(),
                        byte_val_expr.clone(),
                    );
                }
            );
            cb.condition(
                is_limit_type_ctx_expr.clone(),
                |cb| {
                    let is_limit_type_ctx_prev_expr = vc.query_fixed(is_limit_type_ctx, Rotation::prev());
                    cb.require_zero(
                        "is_limit_type_ctx && prev.is_limit_type_ctx => limit_type=prev.limit_type",
                        is_limit_type_ctx_prev_expr * (limit_type_expr.clone() - limit_type_prev_expr.clone()),
                    );
                }
            );

            // reference_type_count+ -> reference_type{1} -> limit_type{1} -> limit_min+ -> limit_max*
            configure_transition_check(
                &mut cb,
                vc,
                "check next: reference_type_count+ -> reference_type(1)",
                and::expr([
                    not_q_last_expr.clone(),
                    is_reference_type_count_expr.clone(),
                ]),
                true,
                &[is_reference_type_count, is_reference_type],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next (last leb byte): reference_type_count+ -> reference_type(1)",
                and::expr([
                    not_q_last_expr.clone(),
                    is_reference_type_count_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                ]),
                true,
                &[is_reference_type],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: reference_type(1) -> limit_type(1)",
                and::expr([
                    not_q_last_expr.clone(),
                    is_reference_type_expr.clone(),
                ]),
                true,
                &[is_limit_type],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: limit_type(1) -> limit_min+",
                and::expr([
                    not_q_last_expr.clone(),
                    is_limit_type_expr.clone(),
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
                    limit_type_is_min_only_expr.clone(),
                    is_limit_min_expr.clone(),
                ]),
                true,
                &[is_limit_min],
            );
            cb.condition(
                and::expr([
                    limit_type_is_min_only_expr.clone(),
                    is_limit_min_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                ]),
                |cb| {
                    cb.require_equal(
                        "limit_type_is_min_only && is_limit_min && leb128_is_last_byte => q_last",
                        q_last_expr.clone(),
                        1.expr(),
                    );
                }
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: limit_min+ -> limit_max*",
                and::expr([
                    not_q_last_expr.clone(),
                    limit_type_is_min_max_expr.clone(),
                    is_limit_min_expr.clone(),
                ]),
                true,
                &[is_limit_min, is_limit_max],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next (last leb byte): limit_min+ -> limit_max*",
                and::expr([
                    not_q_last_expr.clone(),
                    limit_type_is_min_max_expr.clone(),
                    is_limit_min_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
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
                &[is_limit_max],
            );
            cb.condition(
                and::expr([
                    limit_type_is_min_max_expr.clone(),
                    is_limit_max_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                ]),
                |cb| {
                    cb.require_equal(
                        "limit_type_is_min_max && is_limit_max && leb128_is_last_byte => q_last",
                        q_last_expr.clone(),
                        1.expr(),
                    );
                }
            );

            cb.gate(q_enable_expr.clone())
        });

        let config = WasmTableSectionBodyConfig::<F> {
            _marker: PhantomData,

            q_enable,
            q_first,
            q_last,
            is_reference_type_count,
            is_reference_type,
            limit_type_fields,
            leb128_chip,
            dynamic_indexes_chip,
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

        // reference_type_count+
        let (_reference_type_count, reference_type_count_leb_len) = self.markup_leb_section(
            region,
            wb,
            offset,
            &[AssignType::IsReferenceTypeCount],
        )?;
        self.assign(region, &wb, offset, &[AssignType::QFirst], 1, None)?;
        offset += reference_type_count_leb_len;

        // reference_type{1}
        self.assign(
            region,
            wb,
            offset,
            &[AssignType::IsReferenceType],
            1,
            None,
        )?;
        let dynamic_indexes_offset = self.config.dynamic_indexes_chip.assign_auto(
            region,
            self.config.shared_state.borrow().dynamic_indexes_offset,
            1,
            Tag::TableIndex,
        )?;
        self.config.shared_state.borrow_mut().dynamic_indexes_offset = dynamic_indexes_offset;
        offset += 1;

        // limit_type{1}
        let limit_type_val = wb.bytes[offset];
        let limit_type: LimitType = limit_type_val.try_into()?;
        let limit_type_val = limit_type_val as u64;
        self.assign(
            region,
            wb,
            offset,
            &[AssignType::IsLimitType, AssignType::IsLimitTypeCtx],
            1,
            None,
        )?;
        self.assign(region, wb, offset, &[AssignType::LimitType], limit_type_val, None)?;
        offset += 1;

        // limit_min+
        let (limit_min, limit_min_leb_len) = self.markup_leb_section(
            region,
            wb,
            offset,
            &[AssignType::IsLimitMin, AssignType::IsLimitTypeCtx],
        )?;
        for offset in offset..offset + limit_min_leb_len {
            self.assign(region, wb, offset, &[AssignType::LimitType], limit_type_val, None)?;
        }
        offset += limit_min_leb_len;

        // limit_max*
        if limit_type == LimitType::MinMax {
            let (limit_max, limit_max_leb_len) = self.markup_leb_section(
                region,
                wb,
                offset,
                &[AssignType::IsLimitMax, AssignType::IsLimitTypeCtx],
            )?;
            for offset in offset..offset + limit_max_leb_len {
                self.assign(region, wb, offset, &[AssignType::LimitType], limit_type_val, None)?;
            }
            self.config.limit_type_fields.limit_type_params_lt_chip
                .assign(region, offset, F::from(limit_min), F::from(limit_max))
                .map_err(remap_error(Error::AssignExternalChip))?;
            offset += limit_max_leb_len;
        }

        if offset != offset_start {
            self.assign(region, &wb, offset - 1, &[AssignType::QLast], 1, None)?;
        }

        Ok(offset)
    }
}