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
use crate::wasm_circuit::common::{LimitTypeFields, WasmAssignAwareChip, WasmCountPrefixedItemsAwareChip, WasmErrorAwareChip, WasmFuncCountAwareChip, WasmLimitTypeAwareChip, WasmMarkupLeb128SectionAwareChip, WasmSharedStateAwareChip};
use crate::wasm_circuit::common::{configure_constraints_for_q_first_and_q_last, configure_transition_check};
use crate::wasm_circuit::consts::{LIMIT_TYPE_VALUES, LimitType};
use crate::wasm_circuit::error::{Error, remap_error, remap_error_to_assign_at_offset};
use crate::wasm_circuit::leb128::circuit::LEB128Chip;
use crate::wasm_circuit::sections::consts::LebParams;
use crate::wasm_circuit::sections::memory::body::types::AssignType;
use crate::wasm_circuit::tables::dynamic_indexes::circuit::DynamicIndexesChip;
use crate::wasm_circuit::tables::dynamic_indexes::types::{LookupArgsParams, Tag};
use crate::wasm_circuit::types::SharedState;

#[derive(Debug, Clone)]
pub struct WasmMemorySectionBodyConfig<F: Field> {
    pub q_enable: Column<Fixed>,
    pub q_first: Column<Fixed>,
    pub q_last: Column<Fixed>,
    pub is_items_count: Column<Fixed>,

    pub limit_type_fields: LimitTypeFields<F>,

    pub leb128_chip: Rc<LEB128Chip<F>>,
    pub dynamic_indexes_chip: Rc<DynamicIndexesChip<F>>,

    func_count: Column<Advice>,
    body_item_rev_count: Column<Advice>,

    error_code: Column<Advice>,

    shared_state: Rc<RefCell<SharedState>>,

    _marker: PhantomData<F>,
}

impl<'a, F: Field> WasmMemorySectionBodyConfig<F> {}

#[derive(Debug, Clone)]
pub struct WasmMemorySectionBodyChip<F: Field> {
    pub config: WasmMemorySectionBodyConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> WasmMarkupLeb128SectionAwareChip<F> for WasmMemorySectionBodyChip<F> {}

impl<F: Field> WasmCountPrefixedItemsAwareChip<F> for WasmMemorySectionBodyChip<F> {}

impl<F: Field> WasmLimitTypeAwareChip<F> for WasmMemorySectionBodyChip<F> {}

impl<F: Field> WasmErrorAwareChip<F> for WasmMemorySectionBodyChip<F> {
    fn error_code_col(&self) -> Column<Advice> { self.config.error_code }
}

impl<F: Field> WasmSharedStateAwareChip<F> for WasmMemorySectionBodyChip<F> {
    fn shared_state(&self) -> Rc<RefCell<SharedState>> { self.config.shared_state.clone() }
}

impl<F: Field> WasmFuncCountAwareChip<F> for WasmMemorySectionBodyChip<F> {
    fn func_count_col(&self) -> Column<Advice> { self.config.func_count }
}

impl<F: Field> WasmAssignAwareChip<F> for WasmMemorySectionBodyChip<F> {
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
                AssignType::IsItemsCount,
                AssignType::IsLimitMin,
                AssignType::IsLimitMax,
            ].contains(&assign_type) {
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
                AssignType::IsItemsCount => {
                    region.assign_fixed(
                        || format!("assign 'is_items_count' val {} at {}", assign_value, offset),
                        self.config.is_items_count,
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
                AssignType::BodyItemRevCount => {
                    region.assign_advice(
                        || format!("assign 'body_item_rev_count' val {} at {}", assign_value, offset),
                        self.config.body_item_rev_count,
                        offset,
                        || Value::known(F::from(assign_value)),
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

impl<F: Field> WasmMemorySectionBodyChip<F>
{
    pub fn construct(config: WasmMemorySectionBodyConfig<F>) -> Self {
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
        shared_state: Rc<RefCell<SharedState>>,
        body_item_rev_count: Column<Advice>,
        error_code: Column<Advice>,
    ) -> WasmMemorySectionBodyConfig<F> {
        let q_enable = cs.fixed_column();
        let q_first = cs.fixed_column();
        let q_last = cs.fixed_column();

        let is_items_count = cs.fixed_column();

        dynamic_indexes_chip.lookup_args(
            "memory section has valid setup for mem indexes",
            cs,
            |vc| {
                LookupArgsParams {
                    cond: vc.query_fixed(is_items_count, Rotation::cur()),
                    index: vc.query_advice(leb128_chip.config.sn, Rotation::cur()),
                    tag: Tag::MemIndex.expr(),
                    is_terminator: true.expr(),
                }
            }
        );

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
            limit_type_chip,
            ..
        } = limit_type_fields.clone();

        Self::configure_count_prefixed_items_checks(
            cs,
            leb128_chip.as_ref(),
            body_item_rev_count,
            |vc| vc.query_fixed(is_items_count, Rotation::cur()),
            |vc| {
                let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
                let is_items_count_expr = vc.query_fixed(is_items_count, Rotation::cur());

                and::expr([
                    q_enable_expr,
                    not::expr(is_items_count_expr),
                ])
            },
            |vc| vc.query_fixed(is_limit_type, Rotation::cur()),
            |vc| vc.query_fixed(q_last, Rotation::cur()),
        );

        cs.create_gate("WasmMemorySectionBody gate", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
            // let q_first_expr = vc.query_fixed(q_first, Rotation::cur());
            let q_last_expr = vc.query_fixed(q_last, Rotation::cur());
            let not_q_last_expr = not::expr(q_last_expr.clone());
            let is_items_count_expr = vc.query_fixed(is_items_count, Rotation::cur());
            let is_limit_type_expr = vc.query_fixed(is_limit_type, Rotation::cur());
            let is_limit_min_expr = vc.query_fixed(is_limit_min, Rotation::cur());
            let is_limit_max_expr = vc.query_fixed(is_limit_max, Rotation::cur());

            // let is_limit_type_ctx_expr = vc.query_fixed(is_limit_type_ctx, Rotation::cur());

            let byte_val_expr = vc.query_advice(bytecode_table.value, Rotation::cur());
            // let limit_type_prev_expr = vc.query_advice(limit_type, Rotation::prev());
            // let limit_type_expr = vc.query_advice(limit_type, Rotation::cur());

            let limit_type_is_min_only_expr = limit_type_chip.config.value_equals(LimitType::MinOnly, Rotation::cur())(vc);
            let limit_type_is_min_max_expr = limit_type_chip.config.value_equals(LimitType::MinMax, Rotation::cur())(vc);

            let leb128_is_last_byte_expr = vc.query_fixed(leb128_chip.config.is_last_byte, Rotation::cur());

            cb.require_boolean("q_enable is boolean", q_enable_expr.clone());
            cb.require_boolean("is_items_count is boolean", is_items_count_expr.clone());

            configure_constraints_for_q_first_and_q_last(
                &mut cb,
                vc,
                &q_enable,
                &q_first,
                &[is_items_count],
                &q_last,
                &[is_limit_min, is_limit_max],
            );

            cb.require_equal(
                "exactly one mark flag active at the same time",
                is_items_count_expr.clone()
                    + is_limit_type_expr.clone()
                    + is_limit_min_expr.clone()
                    + is_limit_max_expr.clone(),
                1.expr(),
            );

            cb.condition(
                or::expr([
                    is_items_count_expr.clone(),
                    is_limit_min_expr.clone(),
                    is_limit_max_expr.clone(),
                ]),
                |cb| {
                    cb.require_equal(
                        "is_items_count || is_limit_min || is_limit_max -> leb128",
                        vc.query_fixed(leb128_chip.config.q_enable, Rotation::cur()),
                        1.expr(),
                    )
                }
            );

            cb.condition(
                is_items_count_expr.clone(),
                |cb| {
                    cb.require_equal(
                        "only 1 memory block is allowed",
                        vc.query_advice(leb128_chip.config.sn, Rotation::cur()),
                        1.expr(),
                    )
                }
            );

            // is_items_count+ -> is_limit_type{1} -> is_limit_type_val+
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_items_count+ -> is_limit_type{1}",
                and::expr([
                    not_q_last_expr.clone(),
                    is_items_count_expr.clone(),
                ]),
                true,
                &[is_items_count, is_limit_type],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next (last leb byte): is_items_count+ -> is_limit_type{1}",
                and::expr([
                    not_q_last_expr.clone(),
                    is_items_count_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                ]),
                true,
                &[is_limit_type],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_limit_type{1} -> is_limit_min+",
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
                "check next: is_limit_min+",
                and::expr([
                    not_q_last_expr.clone(),
                    is_limit_min_expr.clone(),
                    limit_type_is_min_only_expr.clone(),
                ]),
                true,
                &[is_limit_min],
            );
            cb.condition(
                and::expr([
                    leb128_is_last_byte_expr.clone(),
                    is_limit_min_expr.clone(),
                    limit_type_is_min_only_expr.clone(),
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
                "check next: is_limit_min+ -> is_limit_max*",
                and::expr([
                    not_q_last_expr.clone(),
                    is_limit_min_expr.clone(),
                    limit_type_is_min_max_expr.clone(),
                ]),
                true,
                &[is_limit_min, is_limit_max],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next (last leb byte): is_limit_min+ -> is_limit_max*",
                and::expr([
                    not_q_last_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                    is_limit_min_expr.clone(),
                    limit_type_is_min_max_expr.clone(),
                ]),
                true,
                &[is_limit_max],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_limit_max*",
                and::expr([
                    not_q_last_expr.clone(),
                    is_limit_max_expr.clone(),
                    limit_type_is_min_max_expr.clone(),
                ]),
                true,
                &[is_limit_max],
            );
            cb.condition(
                and::expr([
                    leb128_is_last_byte_expr.clone(),
                    is_limit_max_expr.clone(),
                    limit_type_is_min_max_expr.clone(),
                ]),
                |cb| {
                    cb.require_equal(
                        "limit_type_is_min_max && is_limit_max && leb128_is_last_byte => q_last",
                        q_last_expr.clone(),
                        1.expr(),
                    );
                }
            );

            cb.condition(
                is_limit_type_expr.clone(),
                |cb| {
                    cb.require_in_set(
                        "is_limit_type -> byte_val is valid",
                        byte_val_expr.clone(),
                        LIMIT_TYPE_VALUES.iter().map(|&v| v.expr()).collect_vec(),
                    );
                }
            );

            cb.gate(q_enable_expr.clone())
        });

        let config = WasmMemorySectionBodyConfig::<F> {
            _marker: PhantomData,

            q_enable,
            q_first,
            q_last,
            is_items_count,
            limit_type_fields,
            leb128_chip,
            dynamic_indexes_chip,
            func_count,
            body_item_rev_count,
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

        let (items_count, items_count_leb_len) = self.markup_leb_section(
            region,
            wb,
            offset,
            &[AssignType::IsItemsCount],
        )?;
        let mut body_item_rev_count = items_count;
        for offset in offset..offset + items_count_leb_len {
            self.assign(
                region,
                &wb,
                offset,
                &[AssignType::BodyItemRevCount],
                body_item_rev_count,
                None,
            )?;
        }
        let dynamic_indexes_offset = self.config.dynamic_indexes_chip.assign_auto(
            region,
            self.config.shared_state.borrow().dynamic_indexes_offset,
            items_count as usize,
            Tag::MemIndex,
        )?;
        self.config.shared_state.borrow_mut().dynamic_indexes_offset = dynamic_indexes_offset;
        self.assign(region, &wb, offset, &[AssignType::QFirst], 1, None)?;
        offset += items_count_leb_len;

        for _item_index in 0..items_count {
            body_item_rev_count -= 1;
            let item_start_offset = offset;

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

            for offset in item_start_offset..offset {
                self.assign(
                    region,
                    &wb,
                    offset,
                    &[AssignType::BodyItemRevCount],
                    body_item_rev_count,
                    None,
                )?;
            }
        }

        if offset != offset_start {
            self.assign(region, &wb, offset - 1, &[AssignType::QLast], 1, None)?;
        }

        Ok(offset)
    }
}