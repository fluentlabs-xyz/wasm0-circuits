use std::{cell::RefCell, marker::PhantomData, rc::Rc};

use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Fixed},
    poly::Rotation,
};
use itertools::Itertools;
use log::debug;

use eth_types::Field;
use gadgets::util::{and, not, or, Expr};

use crate::{
    evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon},
    wasm_circuit::{
        bytecode::{bytecode::WasmBytecode, bytecode_table::WasmBytecodeTable},
        common::{
            configure_constraints_for_q_first_and_q_last, configure_transition_check,
            WasmAssignAwareChip, WasmCountPrefixedItemsAwareChip, WasmErrorAwareChip,
            WasmFuncCountAwareChip, WasmMarkupLeb128SectionAwareChip, WasmSharedStateAwareChip,
        },
        error::{remap_error_to_assign_at, Error},
        leb128::circuit::LEB128Chip,
        sections::{
            consts::LebParams,
            r#type::item::{consts::Type::FuncType, types::AssignType},
        },
        types::{NumType, SharedState},
    },
};

#[derive(Debug, Clone)]
pub struct WasmTypeSectionItemConfig<F> {
    pub q_enable: Column<Fixed>,
    pub q_first: Column<Fixed>,
    pub q_last: Column<Fixed>,
    pub is_type: Column<Fixed>,
    pub is_input_count: Column<Fixed>,
    pub is_input_type: Column<Fixed>,
    pub is_output_count: Column<Fixed>,
    pub is_output_type: Column<Fixed>,

    pub leb128_chip: Rc<LEB128Chip<F>>,

    func_count: Column<Advice>,
    error_code: Column<Advice>,
    body_item_rev_count: Column<Advice>,

    shared_state: Rc<RefCell<SharedState>>,

    _marker: PhantomData<F>,
}

impl<'a, F: Field> WasmTypeSectionItemConfig<F> {}

#[derive(Debug, Clone)]
pub struct WasmTypeSectionItemChip<F> {
    pub config: WasmTypeSectionItemConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> WasmMarkupLeb128SectionAwareChip<F> for WasmTypeSectionItemChip<F> {}

impl<F: Field> WasmCountPrefixedItemsAwareChip<F> for WasmTypeSectionItemChip<F> {}

impl<F: Field> WasmErrorAwareChip<F> for WasmTypeSectionItemChip<F> {
    fn error_code_col(&self) -> Column<Advice> {
        self.config.error_code
    }
}

impl<F: Field> WasmSharedStateAwareChip<F> for WasmTypeSectionItemChip<F> {
    fn shared_state(&self) -> Rc<RefCell<SharedState>> {
        self.config.shared_state.clone()
    }
}

impl<F: Field> WasmFuncCountAwareChip<F> for WasmTypeSectionItemChip<F> {
    fn func_count_col(&self) -> Column<Advice> {
        self.config.func_count
    }
}

impl<F: Field> WasmAssignAwareChip<F> for WasmTypeSectionItemChip<F> {
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
            "assign at offset {} q_enable {} assign_types {:?} assign_value {} byte_val {:x?}",
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
            if [AssignType::IsInputCount, AssignType::IsOutputCount].contains(&assign_type) {
                let p = leb_params.unwrap();
                self.config
                    .leb128_chip
                    .assign(region, assign_offset, true, p)?;
            }
            match assign_type {
                AssignType::IsType => {
                    region
                        .assign_fixed(
                            || {
                                format!(
                                    "assign 'is_type' val {} at {}",
                                    assign_value, assign_offset
                                )
                            },
                            self.config.is_type,
                            assign_offset,
                            || Value::known(F::from(assign_value)),
                        )
                        .map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::IsInputCount => {
                    region
                        .assign_fixed(
                            || {
                                format!(
                                    "assign 'is_input_count' val {} at {}",
                                    assign_value, assign_offset
                                )
                            },
                            self.config.is_input_count,
                            assign_offset,
                            || Value::known(F::from(assign_value)),
                        )
                        .map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::IsInputType => {
                    region
                        .assign_fixed(
                            || {
                                format!(
                                    "assign 'is_input_type' val {} at {}",
                                    assign_value, assign_offset
                                )
                            },
                            self.config.is_input_type,
                            assign_offset,
                            || Value::known(F::from(assign_value)),
                        )
                        .map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::IsOutputCount => {
                    region
                        .assign_fixed(
                            || {
                                format!(
                                    "assign 'is_output_count' val {} at {}",
                                    assign_value, assign_offset
                                )
                            },
                            self.config.is_output_count,
                            assign_offset,
                            || Value::known(F::from(assign_value)),
                        )
                        .map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::IsOutputType => {
                    region
                        .assign_fixed(
                            || {
                                format!(
                                    "assign 'is_output_type' val {} at {}",
                                    assign_value, assign_offset
                                )
                            },
                            self.config.is_output_type,
                            assign_offset,
                            || Value::known(F::from(assign_value)),
                        )
                        .map_err(remap_error_to_assign_at(assign_offset))?;
                }
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
                AssignType::ErrorCode => {
                    self.assign_error_code(region, assign_offset, None)?;
                }
            }
        }

        Ok(())
    }
}

impl<F: Field> WasmTypeSectionItemChip<F> {
    pub fn construct(config: WasmTypeSectionItemConfig<F>) -> Self {
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
        body_item_rev_count: Column<Advice>,
        error_code: Column<Advice>,
    ) -> WasmTypeSectionItemConfig<F> {
        let q_enable = cs.fixed_column();
        let q_first = cs.fixed_column();
        let q_last = cs.fixed_column();
        let is_type = cs.fixed_column();
        let is_input_count = cs.fixed_column();
        let is_input_type = cs.fixed_column();
        let is_output_count = cs.fixed_column();
        let is_output_type = cs.fixed_column();

        Self::configure_count_prefixed_items_checks(
            cs,
            leb128_chip.as_ref(),
            body_item_rev_count,
            |vc| vc.query_fixed(is_input_count, Rotation::cur()),
            |vc| {
                let q_enable_expr = Self::get_selector_expr_enriched_with_error_processing(
                    vc,
                    q_enable,
                    &shared_state.borrow(),
                    error_code,
                );
                let is_type_expr = vc.query_fixed(is_type, Rotation::cur());
                let is_input_count_expr = vc.query_fixed(is_input_count, Rotation::cur());
                let is_output_count_expr = vc.query_fixed(is_output_count, Rotation::cur());

                and::expr([
                    q_enable_expr,
                    not::expr(is_type_expr),
                    not::expr(is_input_count_expr),
                    not::expr(is_output_count_expr),
                ])
            },
            |vc| {
                let is_input_type_expr = vc.query_fixed(is_input_type, Rotation::cur());
                let is_output_type_expr = vc.query_fixed(is_output_type, Rotation::cur());

                or::expr([is_input_type_expr, is_output_type_expr])
            },
            |vc| {
                let q_last_expr = vc.query_fixed(q_last, Rotation::cur());
                let is_input_type_expr = vc.query_fixed(is_input_type, Rotation::cur());
                let is_output_count_next_expr = vc.query_fixed(is_output_count, Rotation::next());

                or::expr([
                    q_last_expr.clone(),
                    and::expr([
                        not::expr(q_last_expr),
                        is_input_type_expr,
                        is_output_count_next_expr,
                    ]),
                ])
            },
        );

        cs.create_gate("WasmTypeSectionItem gate", |vc| {
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
            let is_type_expr = vc.query_fixed(is_type, Rotation::cur());
            let is_input_count_expr = vc.query_fixed(is_input_count, Rotation::cur());
            let is_input_type_expr = vc.query_fixed(is_input_type, Rotation::cur());
            let is_output_count_expr = vc.query_fixed(is_output_count, Rotation::cur());
            let is_output_type_expr = vc.query_fixed(is_output_type, Rotation::cur());

            let byte_value_expr = vc.query_advice(bytecode_table.value, Rotation::cur());

            let leb128_is_last_byte_expr =
                vc.query_fixed(leb128_chip.config.is_last_byte, Rotation::cur());

            cb.require_boolean("q_enable is boolean", q_enable_expr.clone());
            cb.require_boolean("is_type is boolean", is_type_expr.clone());
            cb.require_boolean("is_input_count is boolean", is_input_count_expr.clone());
            cb.require_boolean("is_input_type is boolean", is_input_type_expr.clone());
            cb.require_boolean("is_output_count is boolean", is_output_count_expr.clone());
            cb.require_boolean("is_output_type is boolean", is_output_type_expr.clone());

            configure_constraints_for_q_first_and_q_last(
                &mut cb,
                vc,
                &q_enable,
                &q_first,
                &[is_type],
                &q_last,
                &[is_output_type, is_output_count],
            );

            cb.condition(is_type_expr.clone(), |cb| {
                cb.require_equal(
                    "type_section_item type has valid value",
                    byte_value_expr.clone(),
                    FuncType.expr(),
                )
            });

            cb.condition(
                or::expr([is_input_type_expr.clone(), is_output_type_expr.clone()]),
                |cb| {
                    cb.require_in_set(
                        "type_section_item input/output type has valid value",
                        byte_value_expr.clone(),
                        vec![NumType::I32.expr(), NumType::I64.expr()],
                    )
                },
            );

            cb.condition(
                or::expr([is_input_count_expr.clone(), is_output_count_expr.clone()]),
                |cb| {
                    cb.require_zero(
                        "is_input/output_count -> leb128",
                        not::expr(
                            vc.query_fixed(leb128_chip.config.q_enable.clone(), Rotation::cur()),
                        ),
                    )
                },
            );

            cb.require_equal(
                "exactly one mark flag active at the same time",
                is_type_expr.clone()
                    + is_input_count_expr.clone()
                    + is_input_type_expr.clone()
                    + is_output_count_expr.clone()
                    + is_output_type_expr.clone(),
                1.expr(),
            );

            // is_type{1} -> is_input_count+ -> is_input_type* -> is_output_count+ ->
            // is_output_type*
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_type{1} -> is_input_count+",
                and::expr([not_q_last_expr.clone(), is_type_expr.clone()]),
                true,
                &[is_input_count],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_input_count+ -> is_input_type* -> is_output_count+",
                and::expr([not_q_last_expr.clone(), is_input_count_expr.clone()]),
                true,
                &[is_input_count, is_input_type, is_output_count],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next (last leb byte): is_input_count+ -> is_input_type* -> is_output_count+",
                and::expr([
                    not_q_last_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                    is_input_count_expr.clone(),
                ]),
                true,
                &[is_input_type, is_output_count],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_input_type* -> is_output_count+",
                and::expr([not_q_last_expr.clone(), is_input_type_expr.clone()]),
                true,
                &[is_input_type, is_output_count],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_output_count+ -> is_output_type*",
                and::expr([not_q_last_expr.clone(), is_output_count_expr.clone()]),
                true,
                &[is_output_count, is_output_type],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next (last leb byte): is_output_count+ -> is_output_type*",
                and::expr([
                    not_q_last_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                    is_output_count_expr.clone(),
                ]),
                true,
                &[is_output_type],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_output_type*",
                and::expr([not_q_last_expr.clone(), is_output_count_expr.clone()]),
                true,
                &[is_output_type],
            );

            cb.gate(q_enable_expr.clone())
        });

        let config = WasmTypeSectionItemConfig::<F> {
            _marker: PhantomData,

            q_enable,
            q_first,
            q_last,
            is_type,
            is_input_count,
            is_input_type,
            is_output_count,
            is_output_type,
            leb128_chip,
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
        wb_offset: usize,
        assign_delta: usize,
    ) -> Result<usize, Error> {
        let mut offset = wb_offset;
        // is_type{1}
        self.assign(
            region,
            wb,
            offset,
            assign_delta,
            &[AssignType::IsType],
            1,
            None,
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
        offset += 1;

        // is_input_count+
        let (input_count, input_count_leb_len) = self.markup_leb_section(
            region,
            wb,
            offset,
            assign_delta,
            &[AssignType::IsInputCount],
        )?;
        let mut body_item_rev_count = input_count;
        for offset in offset..offset + input_count_leb_len {
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
        offset += input_count_leb_len;
        // is_input_type*
        for offset in offset..(offset + input_count as usize) {
            self.assign(
                region,
                wb,
                offset,
                assign_delta,
                &[AssignType::IsInputType],
                1,
                None,
            )?;
            body_item_rev_count -= 1;
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
        offset += input_count as usize;

        // is_output_count+
        let (output_count, output_count_leb_len) = self.markup_leb_section(
            region,
            wb,
            offset,
            assign_delta,
            &[AssignType::IsOutputCount],
        )?;
        let mut body_item_rev_count = output_count;
        for offset in offset..offset + output_count_leb_len {
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
        offset += output_count_leb_len;
        // is_output_type*
        for offset in offset..(offset + output_count as usize) {
            self.assign(
                region,
                wb,
                offset,
                assign_delta,
                &[AssignType::IsOutputType],
                1,
                None,
            )?;
            body_item_rev_count -= 1;
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
        offset += output_count as usize;

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
