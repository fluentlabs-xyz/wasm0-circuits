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
use gadgets::binary_number::BinaryNumberChip;
use gadgets::util::{and, Expr, not, or};

use crate::evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon};
use crate::wasm_circuit::bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::common::{WasmAssignAwareChip, WasmCountPrefixedItemsAwareChip, WasmErrorAwareChip, WasmFuncCountAwareChip, WasmMarkupLeb128SectionAwareChip, WasmSharedStateAwareChip};
use crate::wasm_circuit::common::{configure_constraints_for_q_first_and_q_last, configure_transition_check};
use crate::wasm_circuit::error::{Error, remap_error_to_assign_at, remap_error_to_invalid_enum_value_at};
use crate::wasm_circuit::leb128::circuit::LEB128Chip;
use crate::wasm_circuit::sections::consts::LebParams;
use crate::wasm_circuit::sections::element::body::consts::ElementType;
use crate::wasm_circuit::sections::element::body::types::AssignType;
use crate::wasm_circuit::types::SharedState;

#[derive(Debug, Clone)]
pub struct WasmElementSectionBodyConfig<F: Field> {
    pub q_enable: Column<Fixed>,
    pub q_first: Column<Fixed>,
    pub q_last: Column<Fixed>,
    pub is_items_count: Column<Fixed>,
    pub is_elem_type: Column<Fixed>,
    pub is_elem_type_ctx: Column<Fixed>,
    pub is_numeric_instruction: Column<Fixed>,
    pub is_numeric_instruction_leb_arg: Column<Fixed>,
    pub is_block_end: Column<Fixed>,
    pub is_funcs_idx_count: Column<Fixed>,
    pub is_func_idx: Column<Fixed>,
    pub is_elem_kind: Column<Fixed>,

    pub elem_type: Column<Advice>,

    pub elem_type_chip: Rc<BinaryNumberChip<F, ElementType, 8>>,

    pub leb128_chip: Rc<LEB128Chip<F>>,

    pub func_count: Column<Advice>,
    body_item_rev_count: Column<Advice>,

    error_code: Column<Advice>,

    shared_state: Rc<RefCell<SharedState>>,

    _marker: PhantomData<F>,
}

impl<'a, F: Field> WasmElementSectionBodyConfig<F> {}

#[derive(Debug, Clone)]
pub struct WasmElementSectionBodyChip<F: Field> {
    pub config: WasmElementSectionBodyConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> WasmMarkupLeb128SectionAwareChip<F> for WasmElementSectionBodyChip<F> {}

impl<F: Field> WasmCountPrefixedItemsAwareChip<F> for WasmElementSectionBodyChip<F> {}

impl<F: Field> WasmErrorAwareChip<F> for WasmElementSectionBodyChip<F> {
    fn error_code_col(&self) -> Column<Advice> { self.config.error_code }
}

impl<F: Field> WasmSharedStateAwareChip<F> for WasmElementSectionBodyChip<F> {
    fn shared_state(&self) -> Rc<RefCell<SharedState>> { self.config.shared_state.clone() }
}

impl<F: Field> WasmFuncCountAwareChip<F> for WasmElementSectionBodyChip<F> {
    fn func_count_col(&self) -> Column<Advice> { self.config.func_count }
}

impl<F: Field> WasmAssignAwareChip<F> for WasmElementSectionBodyChip<F> {
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
        let byte_val = wb.bytes[wb_offset];
        debug!(
            "assign at offset {} q_enable {} assign_types {:?} assign_value {} byte_val {:x?}",
            assign_offset,
            q_enable,
            assign_types,
            assign_value,
            byte_val,
        );
        region.assign_fixed(
            || format!("assign 'q_enable' val {} at {}", q_enable, assign_offset),
            self.config.q_enable,
            assign_offset,
            || Value::known(F::from(q_enable as u64)),
        ).map_err(remap_error_to_assign_at(assign_offset))?;
        self.assign_func_count(region, assign_offset)?;

        for assign_type in assign_types {
            if [
                AssignType::IsItemsCount,
                AssignType::IsNumericInstructionLebArg,
                AssignType::IsFuncsIdxCount,
                AssignType::IsFuncIdx,
            ].contains(&assign_type) {
                let p = leb_params.unwrap();
                self.config.leb128_chip.assign(
                    region,
                    assign_offset,
                    q_enable,
                    p,
                )?;
            }
            match assign_type {
                AssignType::QFirst => {
                    region.assign_fixed(
                        || format!("assign 'q_first' val {} at {}", assign_value, assign_offset),
                        self.config.q_first,
                        assign_offset,
                        || Value::known(F::from(assign_value)),
                    ).map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::QLast => {
                    region.assign_fixed(
                        || format!("assign 'q_last' val {} at {}", assign_value, assign_offset),
                        self.config.q_last,
                        assign_offset,
                        || Value::known(F::from(assign_value)),
                    ).map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::IsItemsCount => {
                    region.assign_fixed(
                        || format!("assign 'is_items_count' val {} at {}", assign_value, assign_offset),
                        self.config.is_items_count,
                        assign_offset,
                        || Value::known(F::from(assign_value)),
                    ).map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::IsElemTypeCtx => {
                    region.assign_fixed(
                        || format!("assign 'is_elem_type_ctx' val {} at {}", 1, assign_offset),
                        self.config.is_elem_type_ctx,
                        assign_offset,
                        || Value::known(F::from(assign_value)),
                    ).map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::IsElemType => {
                    region.assign_fixed(
                        || format!("assign 'is_elem_type' val {} at {}", assign_value, assign_offset),
                        self.config.is_elem_type,
                        assign_offset,
                        || Value::known(F::from(assign_value)),
                    ).map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::IsNumericInstruction => {
                    region.assign_fixed(
                        || format!("assign 'is_numeric_instruction' val {} at {}", assign_value, assign_offset),
                        self.config.is_numeric_instruction,
                        assign_offset,
                        || Value::known(F::from(assign_value)),
                    ).map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::IsNumericInstructionLebArg => {
                    region.assign_fixed(
                        || format!("assign 'is_numeric_instruction_leb_arg' val {} at {}", assign_value, assign_offset),
                        self.config.is_numeric_instruction_leb_arg,
                        assign_offset,
                        || Value::known(F::from(assign_value)),
                    ).map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::IsBlockEnd => {
                    region.assign_fixed(
                        || format!("assign 'is_block_end' val {} at {}", assign_value, assign_offset),
                        self.config.is_block_end,
                        assign_offset,
                        || Value::known(F::from(assign_value)),
                    ).map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::IsFuncsIdxCount => {
                    region.assign_fixed(
                        || format!("assign 'is_funcs_idx_count' val {} at {}", assign_value, assign_offset),
                        self.config.is_funcs_idx_count,
                        assign_offset,
                        || Value::known(F::from(assign_value)),
                    ).map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::IsFuncIdx => {
                    region.assign_fixed(
                        || format!("assign 'is_func_idx' val {} at {}", assign_value, assign_offset),
                        self.config.is_func_idx,
                        assign_offset,
                        || Value::known(F::from(assign_value)),
                    ).map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::IsElemKind => {
                    region.assign_fixed(
                        || format!("assign 'is_elem_kind' val {} at {}", assign_value, assign_offset),
                        self.config.is_elem_kind,
                        assign_offset,
                        || Value::known(F::from(assign_value)),
                    ).map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::ElemType => {
                    region.assign_advice(
                        || format!("assign 'elem_type' val {} at {}", assign_value, assign_offset),
                        self.config.elem_type,
                        assign_offset,
                        || Value::known(F::from(assign_value)),
                    ).map_err(remap_error_to_assign_at(assign_offset))?;
                    let opcode: ElementType = (assign_value as u8).try_into().map_err(remap_error_to_invalid_enum_value_at(assign_offset))?;
                    self.config.elem_type_chip.assign(
                        region,
                        assign_offset,
                        &opcode,
                    ).map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::BodyItemRevCount => {
                    region.assign_advice(
                        || format!("assign 'body_item_rev_count' val {} at {}", assign_value, assign_offset),
                        self.config.body_item_rev_count,
                        assign_offset,
                        || Value::known(F::from(assign_value)),
                    ).map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::ErrorCode => {}
            }
        };
        Ok(())
    }
}

impl<F: Field> WasmElementSectionBodyChip<F>
{
    pub fn construct(config: WasmElementSectionBodyConfig<F>) -> Self {
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
    ) -> WasmElementSectionBodyConfig<F> {
        let q_enable = cs.fixed_column();
        let q_first = cs.fixed_column();
        let q_last = cs.fixed_column();
        let is_items_count = cs.fixed_column();
        let is_elem_type = cs.fixed_column();
        let is_elem_type_ctx = cs.fixed_column();
        let is_numeric_instruction = cs.fixed_column();
        let is_numeric_instruction_leb_arg = cs.fixed_column();
        let is_block_end = cs.fixed_column();
        let is_funcs_idx_count = cs.fixed_column();
        let is_func_idx = cs.fixed_column();
        let is_elem_kind = cs.fixed_column();

        let elem_type = cs.advice_column();
        let config = BinaryNumberChip::configure(
            cs,
            is_elem_type_ctx,
            Some(elem_type.into()),
        );
        let elem_type_chip = Rc::new(BinaryNumberChip::construct(config));

        Self::configure_count_prefixed_items_checks(
            cs,
            leb128_chip.as_ref(),
            body_item_rev_count,
            |vc| vc.query_fixed(is_items_count, Rotation::cur()),
            |vc| {
                let q_enable_expr = Self::get_selector_expr_enriched_with_error_processing(vc, q_enable, &shared_state.borrow(), error_code);
                let is_items_count_expr = vc.query_fixed(is_items_count, Rotation::cur());

                and::expr([
                    q_enable_expr,
                    not::expr(is_items_count_expr),
                ])
            },
            |vc| vc.query_fixed(is_elem_type, Rotation::cur()),
            |vc| vc.query_fixed(q_last, Rotation::cur()),
        );

        cs.create_gate("WasmElementSectionBody gate", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = Self::get_selector_expr_enriched_with_error_processing(vc, q_enable, &shared_state.borrow(), error_code);
            let q_last_expr = vc.query_fixed(q_last, Rotation::cur());
            let not_q_last_expr = not::expr(q_last_expr.clone());
            let is_items_count_expr = vc.query_fixed(is_items_count, Rotation::cur());
            let is_elem_type_expr = vc.query_fixed(is_elem_type, Rotation::cur());
            let is_elem_type_ctx_expr = vc.query_fixed(is_elem_type_ctx, Rotation::cur());
            let is_numeric_instruction_expr = vc.query_fixed(is_numeric_instruction, Rotation::cur());
            let is_numeric_instruction_leb_arg_expr = vc.query_fixed(is_numeric_instruction_leb_arg, Rotation::cur());
            let is_block_end_expr = vc.query_fixed(is_block_end, Rotation::cur());
            let is_funcs_idx_count_expr = vc.query_fixed(is_funcs_idx_count, Rotation::cur());
            let is_func_idx_expr = vc.query_fixed(is_func_idx, Rotation::cur());
            let is_elem_kind_expr = vc.query_fixed(is_elem_kind, Rotation::cur());

            let byte_val_expr = vc.query_advice(bytecode_table.value, Rotation::cur());

            let elem_type_expr = vc.query_advice(elem_type, Rotation::cur());

            let elem_type_is_0_expr = elem_type_chip.config.value_equals(ElementType::_0, Rotation::cur())(vc);
            let elem_type_is_1_expr = elem_type_chip.config.value_equals(ElementType::_1, Rotation::cur())(vc);
            // let elem_type_is_0_next_expr = elem_type_chip.config.value_equals(ElementType::_0, Rotation::next())(vc);
            let elem_type_is_1_next_expr = elem_type_chip.config.value_equals(ElementType::_1, Rotation::next())(vc);

            let leb128_sn_expr = vc.query_advice(leb128_chip.config.sn, Rotation::cur());
            let leb128_is_last_byte_expr = vc.query_fixed(leb128_chip.config.is_last_byte, Rotation::cur());

            cb.require_boolean("q_enable is boolean", q_enable_expr.clone());
            cb.require_boolean("is_items_count is boolean", is_items_count_expr.clone());
            cb.require_boolean("is_elem_type is boolean", is_elem_type_expr.clone());
            cb.require_boolean("is_elem_type_ctx is boolean", is_elem_type_ctx_expr.clone());
            cb.require_boolean("is_numeric_instruction is boolean", is_numeric_instruction_expr.clone());
            cb.require_boolean("is_numeric_instruction_leb_arg is boolean", is_numeric_instruction_leb_arg_expr.clone());
            cb.require_boolean("is_block_end is boolean", is_block_end_expr.clone());
            cb.require_boolean("is_funcs_idx_count is boolean", is_funcs_idx_count_expr.clone());
            cb.require_boolean("is_func_idx is boolean", is_func_idx_expr.clone());
            cb.require_boolean("is_elem_kind is boolean", is_elem_kind_expr.clone());

            configure_constraints_for_q_first_and_q_last(
                &mut cb,
                vc,
                &q_enable,
                &q_first,
                &[is_items_count],
                &q_last,
                &[is_funcs_idx_count, is_func_idx],
            );

            cb.require_equal(
                "exactly one mark flag active at the same time",
                is_items_count_expr.clone() +
                    is_elem_type_expr.clone() +
                    is_numeric_instruction_expr.clone() +
                    is_numeric_instruction_leb_arg_expr.clone() +
                    is_block_end_expr.clone() +
                    is_funcs_idx_count_expr.clone() +
                    is_func_idx_expr.clone() +
                    is_elem_kind_expr.clone(),
                1.expr(),
            );

            cb.condition(
                or::expr([
                    is_items_count_expr.clone(),
                    is_funcs_idx_count_expr.clone(),
                    is_func_idx_expr.clone(),
                    is_numeric_instruction_leb_arg_expr.clone(),
                ]),
                |cb| {
                    cb.require_equal(
                        "is_items_count || is_funcs_idx_count || is_func_idx || is_numeric_instruction_leb_arg => leb128",
                        vc.query_fixed(leb128_chip.config.q_enable, Rotation::cur()),
                        1.expr(),
                    )
                }
            );

            cb.condition(
                is_elem_type_expr.clone(),
                |cb| {
                    cb.require_in_set(
                        "is_elem_type -> byte_val is valid",
                        byte_val_expr.clone(),
                        vec![
                            ElementType::_0.expr(),
                            ElementType::_1.expr(),
                            // TODO
                            // ElementType::_2.expr(),
                            // ElementType::_3.expr(),
                            // ElementType::_4.expr(),
                            // ElementType::_5.expr(),
                            // ElementType::_6.expr(),
                            // ElementType::_7.expr(),
                        ],
                    );
                }
            );

            cb.require_equal(
                "check relation of is_elem_type_ctx with other flags",
                is_elem_type_expr.clone()
                    + is_numeric_instruction_expr.clone()
                    + is_numeric_instruction_leb_arg_expr.clone()
                    + is_block_end_expr.clone()
                    + is_funcs_idx_count_expr.clone()
                    + is_func_idx_expr.clone()
                    + is_elem_kind_expr.clone(),
                is_elem_type_ctx_expr.clone()
            );
            cb.condition(
                is_elem_type_expr.clone(),
                |cb| {
                    cb.require_equal(
                        "is_elem_type => elem_type=byte_val",
                        elem_type_expr.clone(),
                        byte_val_expr.clone(),
                    );
                }
            );
            cb.condition(
                is_elem_type_ctx_expr.clone(),
                |cb| {
                    let is_elem_type_ctx_prev_expr = vc.query_fixed(is_elem_type_ctx, Rotation::prev());
                    let elem_type_prev_expr = vc.query_advice(elem_type, Rotation::prev());
                    let not_is_elem_type_prev_expr = vc.query_fixed(is_elem_type, Rotation::prev());
                    cb.require_zero(
                        "is_elem_type_ctx && prev.is_elem_type_ctx => elem_type=prev.elem_type",
                        not_is_elem_type_prev_expr.clone() * is_elem_type_ctx_prev_expr.clone() * (elem_type_expr.clone() - elem_type_prev_expr.clone()),
                    );
                }
            );

            // is_items_count+ -> elem+(is_elem_type{1} -> elem_body+)
            // elem_body+(is_elem_type{1}=0 -> is_numeric_instruction{1} -> is_numeric_instruction_leb_arg+ -> is_block_end{1} -> is_funcs_idx_count+ -> is_func_idx*)
            // elem_body+(is_elem_type{1}=1 -> is_elem_kind{1} -> is_funcs_idx_count+ -> is_func_idx*)
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_items_count+ -> elem+(is_elem_type{1} ...",
                and::expr([
                    not_q_last_expr.clone(),
                    is_items_count_expr.clone(),
                ]),
                true,
                &[is_items_count, is_elem_type],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next (last leb byte): is_items_count+ -> elem+(is_elem_type{1} ...",
                and::expr([
                    not_q_last_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                    is_items_count_expr.clone(),
                ]),
                true,
                &[is_elem_type],
            );
            // elem_body+(is_elem_type{1}=0 -> is_numeric_instruction{1} -> is_numeric_instruction_leb_arg+ -> is_block_end{1} -> is_funcs_idx_count+ -> is_func_idx*)
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_elem_type{1}=0 -> is_numeric_instruction{1}",
                and::expr([
                    not_q_last_expr.clone(),
                    is_elem_type_expr.clone(),
                    elem_type_is_0_expr.clone(),
                ]),
                true,
                &[is_numeric_instruction, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_numeric_instruction{1} -> is_numeric_instruction_leb_arg+",
                and::expr([
                    not_q_last_expr.clone(),
                    is_numeric_instruction_expr.clone(),
                    elem_type_is_0_expr.clone(),
                ]),
                true,
                &[is_numeric_instruction_leb_arg, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_numeric_instruction_leb_arg+ -> is_block_end{1}",
                and::expr([
                    not_q_last_expr.clone(),
                    is_numeric_instruction_leb_arg_expr.clone(),
                    elem_type_is_0_expr.clone(),
                ]),
                true,
                &[is_numeric_instruction_leb_arg, is_block_end, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next (last leb byte): is_numeric_instruction_leb_arg+ -> is_block_end{1}",
                and::expr([
                    not_q_last_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                    is_numeric_instruction_leb_arg_expr.clone(),
                    elem_type_is_0_expr.clone(),
                ]),
                true,
                &[is_block_end],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_block_end{1} -> is_funcs_idx_count+",
                and::expr([
                    not_q_last_expr.clone(),
                    is_block_end_expr.clone(),
                    elem_type_is_0_expr.clone(),
                ]),
                true,
                &[is_funcs_idx_count, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_funcs_idx_count+ -> is_func_idx*",
                and::expr([
                    not_q_last_expr.clone(),
                    is_funcs_idx_count_expr.clone(),
                    elem_type_is_0_expr.clone(),
                ]) * leb128_sn_expr.clone(),
                true,
                &[is_funcs_idx_count, is_func_idx, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next (last leb byte): is_funcs_idx_count+ -> is_func_idx*",
                and::expr([
                    not_q_last_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                    is_funcs_idx_count_expr.clone(),
                    elem_type_is_0_expr.clone(),
                ]) * leb128_sn_expr.clone(),
                true,
                &[is_func_idx],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_func_idx*",
                and::expr([
                    not_q_last_expr.clone(),
                    is_func_idx_expr.clone(),
                    elem_type_is_0_expr.clone(),
                ]),
                true,
                &[is_func_idx, is_elem_type],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next (last leb byte): is_func_idx*",
                and::expr([
                    not_q_last_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                    is_func_idx_expr.clone(),
                    elem_type_is_0_expr.clone(),
                ]),
                true,
                &[is_elem_type],
            );
            // elem_body+(is_elem_type{1}=1 -> is_elem_kind{1} -> is_funcs_idx_count+ -> is_func_idx*)
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_elem_type{1}=1 -> is_elem_kind{1}",
                and::expr([
                    not_q_last_expr.clone(),
                    is_elem_type_expr.clone(),
                    elem_type_is_1_next_expr.clone(),
                ]),
                true,
                &[is_elem_kind, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_elem_kind{1} -> is_funcs_idx_count+",
                and::expr([
                    not_q_last_expr.clone(),
                    is_elem_kind_expr.clone(),
                    elem_type_is_1_expr.clone(),
                ]),
                true,
                &[is_funcs_idx_count, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_funcs_idx_count+ -> is_func_idx*",
                and::expr([
                    not_q_last_expr.clone(),
                    is_funcs_idx_count_expr.clone(),
                    elem_type_is_1_expr.clone(),
                ]) * leb128_sn_expr.clone(),
                true,
                &[is_funcs_idx_count, is_func_idx],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next (last leb byte): is_funcs_idx_count+ -> is_func_idx*",
                and::expr([
                    not_q_last_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                    is_funcs_idx_count_expr.clone(),
                    elem_type_is_1_expr.clone(),
                ]) * leb128_sn_expr.clone(),
                true,
                &[is_func_idx],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_func_idx*",
                and::expr([
                    not_q_last_expr.clone(),
                    is_func_idx_expr.clone(),
                    elem_type_is_1_expr.clone(),
                ]),
                true,
                &[is_func_idx, is_elem_type],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next (last leb byte): is_func_idx*",
                and::expr([
                    not_q_last_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                    is_func_idx_expr.clone(),
                    elem_type_is_1_expr.clone(),
                ]),
                true,
                &[is_func_idx, is_elem_type],
            );

            cb.gate(q_enable_expr.clone())
        });

        let config = WasmElementSectionBodyConfig::<F> {
            _marker: PhantomData,

            q_enable,
            q_first,
            q_last,
            is_items_count,
            is_elem_type,
            is_elem_type_ctx,
            is_numeric_instruction,
            is_numeric_instruction_leb_arg,
            is_block_end,
            is_funcs_idx_count,
            is_func_idx,
            is_elem_kind,
            elem_type,
            elem_type_chip,
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

        // items_count+
        let (items_count, items_count_leb_len) = self.markup_leb_section(
            region,
            wb,
            offset,
            assign_delta,
            &[AssignType::IsItemsCount],
        )?;
        let mut body_item_rev_count = items_count;
        for offset in offset..offset + items_count_leb_len {
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
        self.assign(region, &wb, offset, assign_delta, &[AssignType::QFirst], 1, None)?;
        offset += items_count_leb_len;

        for _item_index in 0..items_count {
            body_item_rev_count -= 1;
            let item_start_offset = offset;

            // elem_type{1}
            let elem_type_val = wb.bytes[offset];
            let elem_type: ElementType = elem_type_val.try_into().map_err(remap_error_to_invalid_enum_value_at(offset + assign_delta))?;
            let elem_type_val = elem_type_val as u64;
            self.assign(
                region,
                wb,
                offset,
                assign_delta,
                &[AssignType::IsElemType, AssignType::IsElemTypeCtx],
                1,
                None,
            )?;
            self.assign(region, wb, offset, assign_delta, &[AssignType::ElemType], elem_type_val, None)?;
            offset += 1;

            match elem_type {
                ElementType::_0 => {
                    // numeric_instruction{1}
                    self.assign(
                        region,
                        wb,
                        offset,
                        assign_delta,
                        &[AssignType::IsNumericInstruction, AssignType::IsElemTypeCtx],
                        1,
                        None,
                    )?;
                    self.assign(region, wb, offset, assign_delta, &[AssignType::ElemType], elem_type_val, None)?;
                    offset += 1;

                    // numeric_instruction_leb_arg+
                    let (_numeric_instruction_leb_arg, numeric_instruction_leb_arg_leb_len) = self.markup_leb_section(
                        region,
                        wb,
                        offset,
                        assign_delta,
                        &[AssignType::IsNumericInstructionLebArg, AssignType::IsElemTypeCtx],
                    )?;
                    for offset in offset..offset + numeric_instruction_leb_arg_leb_len {
                        self.assign(region, wb, offset, assign_delta, &[AssignType::ElemType], elem_type_val, None)?;
                    }
                    offset += numeric_instruction_leb_arg_leb_len;

                    // numeric_instruction_block_end{1}
                    self.assign(
                        region,
                        wb,
                        offset,
                        assign_delta,
                        &[AssignType::IsBlockEnd, AssignType::IsElemTypeCtx],
                        1,
                        None,
                    )?;
                    self.assign(region, wb, offset, assign_delta, &[AssignType::ElemType], elem_type_val, None)?;
                    offset += 1;

                    // funcs_idx_count+
                    let (funcs_idx_count, funcs_idx_count_leb_len) = self.markup_leb_section(
                        region,
                        wb,
                        offset,
                        assign_delta,
                        &[AssignType::IsFuncsIdxCount, AssignType::IsElemTypeCtx],
                    )?;
                    for offset in offset..offset + funcs_idx_count_leb_len {
                        self.assign(region, wb, offset, assign_delta, &[AssignType::ElemType], elem_type_val, None)?;
                    }
                    offset += funcs_idx_count_leb_len;

                    for _funcs_idx_index in 0..funcs_idx_count {
                        // func_idx+
                        let (_func_idx, func_idx_leb_len) = self.markup_leb_section(
                            region,
                            wb,
                            offset,
                            assign_delta,
                            &[AssignType::IsFuncIdx, AssignType::IsElemTypeCtx],
                        )?;
                        for offset in offset..offset + func_idx_leb_len {
                            self.assign(region, wb, offset, assign_delta, &[AssignType::ElemType], elem_type_val, None)?;
                        }
                        offset += func_idx_leb_len;
                    }
                }
                ElementType::_1 => {
                    // elem_kind{1}
                    self.assign(
                        region,
                        wb,
                        offset,
                        assign_delta,
                        &[AssignType::IsElemKind, AssignType::IsElemTypeCtx],
                        1,
                        None,
                    )?;
                    self.assign(region, wb, offset, assign_delta, &[AssignType::ElemType], elem_type_val, None)?;
                    offset += 1;

                    // funcs_idx_count+
                    let (funcs_idx_count, funcs_idx_count_leb_len) = self.markup_leb_section(
                        region,
                        wb,
                        offset,
                        assign_delta,
                        &[AssignType::IsFuncsIdxCount, AssignType::IsElemTypeCtx],
                    )?;
                    for offset in offset..offset + funcs_idx_count_leb_len {
                        self.assign(region, wb, offset, assign_delta, &[AssignType::ElemType], elem_type_val, None)?;
                    }
                    offset += funcs_idx_count_leb_len;

                    for _funcs_idx_index in 0..funcs_idx_count {
                        // func_idxs+
                        let (_func_idxs, func_idxs_leb_len) = self.markup_leb_section(
                            region,
                            wb,
                            offset,
                            assign_delta,
                            &[AssignType::IsFuncIdx, AssignType::IsElemTypeCtx],
                        )?;
                        for offset in offset..offset + func_idxs_leb_len {
                            self.assign(region, wb, offset, assign_delta, &[AssignType::ElemType], elem_type_val, None)?;
                        }
                        offset += func_idxs_leb_len;
                    }
                }
                _ => { return Err(Error::FatalUnsupportedTypeValue(format!("unsupported element type '{:?}'", elem_type))) }
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
            self.assign(region, &wb, offset - 1, assign_delta, &[AssignType::QLast], 1, None)?;
        }

        Ok(offset)
    }
}