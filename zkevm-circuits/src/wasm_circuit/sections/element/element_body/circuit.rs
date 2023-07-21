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
use crate::wasm_circuit::common::WasmChipTrait;
use crate::wasm_circuit::error::Error;
use crate::wasm_circuit::leb128_circuit::circuit::LEB128Chip;
use crate::wasm_circuit::leb128_circuit::helpers::{leb128_compute_sn, leb128_compute_sn_recovered_at_position};
use crate::wasm_circuit::sections::consts::LebParams;
use crate::wasm_circuit::sections::element::element_body::consts::ElementType;
use crate::wasm_circuit::sections::element::element_body::types::AssignType;
use crate::wasm_circuit::sections::helpers::{configure_constraints_for_q_first_and_q_last, configure_transition_check};
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

    shared_state: Rc<RefCell<SharedState>>,

    _marker: PhantomData<F>,
}

impl<'a, F: Field> WasmElementSectionBodyConfig<F>
{}

#[derive(Debug, Clone)]
pub struct WasmElementSectionBodyChip<F: Field> {
    pub config: WasmElementSectionBodyConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> WasmChipTrait<F> for WasmElementSectionBodyChip<F> {
    fn shared_state(&self) -> Rc<RefCell<SharedState>> {
        self.config.shared_state.clone()
    }

    fn func_count_col(&self) -> Column<Advice> {
        self.config.func_count
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

        cs.create_gate("WasmElementSectionBody gate", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
            let q_first_expr = vc.query_fixed(q_first, Rotation::cur());
            let not_q_first_expr = not::expr(q_first_expr.clone());
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
            let elem_type_is_0_next_expr = elem_type_chip.config.value_equals(ElementType::_0, Rotation::next())(vc);
            let elem_type_is_1_next_expr = elem_type_chip.config.value_equals(ElementType::_1, Rotation::next())(vc);

            let leb128_sn_expr = vc.query_advice(leb128_chip.config.sn, Rotation::cur());

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
                |bcb| {
                    bcb.require_equal(
                        "is_items_count || is_funcs_idx_count || is_func_idx || is_numeric_instruction_leb_arg => leb128",
                        vc.query_fixed(leb128_chip.config.q_enable, Rotation::cur()),
                        1.expr(),
                    )
                }
            );

            cb.condition(
                is_elem_type_expr.clone(),
                |bcb| {
                    bcb.require_in_set(
                        "is_elem_type -> byte_val has valid value",
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
                |bcb| {
                    bcb.require_equal(
                        "is_elem_type -> elem_type=byte_val",
                        elem_type_expr.clone(),
                        byte_val_expr.clone(),
                    );
                }
            );
            cb.condition(
                is_elem_type_ctx_expr.clone(),
                |bcb| {
                    let is_elem_type_ctx_prev_expr = vc.query_fixed(is_elem_type_ctx, Rotation::prev());
                    let elem_type_prev_expr = vc.query_advice(elem_type, Rotation::prev());
                    let not_is_elem_type_prev_expr = vc.query_fixed(is_elem_type, Rotation::prev());
                    bcb.require_zero(
                        "is_elem_type_ctx && prev.is_elem_type_ctx -> elem_type=prev.elem_type",
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
                is_items_count_expr.clone() * not_q_last_expr.clone(),
                true,
                &[is_items_count, is_elem_type, ],
            );
            // elem_body+(is_elem_type{1}=0 -> is_numeric_instruction{1} -> is_numeric_instruction_leb_arg+ -> is_block_end{1} -> is_funcs_idx_count+ -> is_func_idx*)
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_elem_type{1}=0 -> is_numeric_instruction{1}",
                and::expr([
                    is_elem_type_expr.clone(),
                    elem_type_is_0_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_numeric_instruction, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_numeric_instruction{1} -> is_numeric_instruction_leb_arg+",
                and::expr([
                    is_numeric_instruction_expr.clone(),
                    elem_type_is_0_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_numeric_instruction_leb_arg, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_numeric_instruction_leb_arg+ -> is_block_end{1}",
                and::expr([
                    is_numeric_instruction_leb_arg_expr.clone(),
                    elem_type_is_0_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_numeric_instruction_leb_arg, is_block_end, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_block_end{1} -> is_funcs_idx_count+",
                and::expr([
                    is_block_end_expr.clone(),
                    elem_type_is_0_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_funcs_idx_count, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_funcs_idx_count+ -> is_func_idx*",
                and::expr([
                    is_funcs_idx_count_expr.clone(),
                    elem_type_is_0_expr.clone(),
                    not_q_last_expr.clone(),
                ]) * leb128_sn_expr.clone(),
                true,
                &[is_funcs_idx_count, is_func_idx, ],
            );
            // elem_body+(is_elem_type{1}=1 -> is_elem_kind{1} -> is_funcs_idx_count+ -> is_func_idx*)
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_elem_type{1}=1 -> is_elem_kind{1}",
                and::expr([
                    is_elem_type_expr.clone(),
                    elem_type_is_1_next_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_elem_kind, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_elem_kind{1} -> is_funcs_idx_count+",
                and::expr([
                    is_elem_kind_expr.clone(),
                    elem_type_is_1_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_funcs_idx_count, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_funcs_idx_count+ -> is_func_idx*",
                and::expr([
                    is_funcs_idx_count_expr.clone(),
                    elem_type_is_1_expr.clone(),
                    not_q_last_expr.clone(),
                ]) * leb128_sn_expr.clone(),
                true,
                &[is_funcs_idx_count, is_func_idx, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_func_idx*",
                and::expr([
                    is_funcs_idx_count_expr.clone(),
                    elem_type_is_1_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_func_idx, is_elem_type],
            );

            cb.gate(q_enable_expr.clone())
        });

        let config = WasmElementSectionBodyConfig::<F> {
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
            shared_state,

            _marker: PhantomData,
        };

        config
    }

    pub fn assign(
        &self,
        region: &mut Region<F>,
        wasm_bytecode: &WasmBytecode,
        offset: usize,
        assign_types: &[AssignType],
        assign_value: u64,
        leb_params: Option<LebParams>,
    ) {
        let q_enable = true;
        let byte_val = wasm_bytecode.bytes[offset];
        debug!(
            "element_section_body: assign at offset {} q_enable {} assign_types {:?} assign_value {} byte_val {:x?}",
            offset,
            q_enable,
            assign_types,
            assign_value,
            byte_val,
        );
        region.assign_fixed(
            || format!("assign 'q_enable' val {} at {}", q_enable, offset),
            self.config.q_enable,
            offset,
            || Value::known(F::from(q_enable as u64)),
        ).unwrap();
        self.assign_func_count(region, offset);

        assign_types.iter().for_each(|&assign_type| {
            if [
                AssignType::IsItemsCount,
                AssignType::IsNumericInstructionLebArg,
                AssignType::IsFuncsIdxCount,
                AssignType::IsFuncIdx,
            ].contains(&assign_type) {
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
                AssignType::IsItemsCount => {
                    region.assign_fixed(
                        || format!("assign 'is_items_count' val {} at {}", assign_value, offset),
                        self.config.is_items_count,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsElemTypeCtx => {
                    region.assign_fixed(
                        || format!("assign 'is_elem_type_ctx' val {} at {}", 1, offset),
                        self.config.is_elem_type_ctx,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsElemType => {
                    region.assign_fixed(
                        || format!("assign 'is_elem_type' val {} at {}", assign_value, offset),
                        self.config.is_elem_type,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsNumericInstruction => {
                    region.assign_fixed(
                        || format!("assign 'is_numeric_instruction' val {} at {}", assign_value, offset),
                        self.config.is_numeric_instruction,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsNumericInstructionLebArg => {
                    region.assign_fixed(
                        || format!("assign 'is_numeric_instruction_leb_arg' val {} at {}", assign_value, offset),
                        self.config.is_numeric_instruction_leb_arg,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsBlockEnd => {
                    region.assign_fixed(
                        || format!("assign 'is_block_end' val {} at {}", assign_value, offset),
                        self.config.is_block_end,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsFuncsIdxCount => {
                    region.assign_fixed(
                        || format!("assign 'is_funcs_idx_count' val {} at {}", assign_value, offset),
                        self.config.is_funcs_idx_count,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsFuncIdx => {
                    region.assign_fixed(
                        || format!("assign 'is_func_idx' val {} at {}", assign_value, offset),
                        self.config.is_func_idx,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsElemKind => {
                    region.assign_fixed(
                        || format!("assign 'is_elem_kind' val {} at {}", assign_value, offset),
                        self.config.is_elem_kind,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::ElemType => {
                    region.assign_advice(
                        || format!("assign 'elem_type' val {} at {}", assign_value, offset),
                        self.config.elem_type,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                    let opcode: ElementType = (assign_value as u8).try_into().unwrap();
                    self.config.elem_type_chip.assign(
                        region,
                        offset,
                        &opcode,
                    ).unwrap();
                }
            }
        })
    }

    /// returns sn and leb len
    fn markup_leb_section(
        &self,
        region: &mut Region<F>,
        wasm_bytecode: &WasmBytecode,
        leb_bytes_offset: usize,
        assign_type: &[AssignType],
    ) -> (u64, usize) {
        let is_signed = false;
        let (sn, last_byte_offset) = leb128_compute_sn(wasm_bytecode.bytes.as_slice(), is_signed, leb_bytes_offset).unwrap();
        let mut sn_recovered_at_pos = 0;
        let last_byte_rel_offset = last_byte_offset - leb_bytes_offset;
        for byte_rel_offset in 0..=last_byte_rel_offset {
            let offset = leb_bytes_offset + byte_rel_offset;
            sn_recovered_at_pos = leb128_compute_sn_recovered_at_position(
                sn_recovered_at_pos,
                is_signed,
                byte_rel_offset,
                last_byte_rel_offset,
                wasm_bytecode.bytes[offset],
            );
            self.assign(
                region,
                wasm_bytecode,
                offset,
                assign_type,
                1,
                Some(LebParams {
                    is_signed,
                    byte_rel_offset,
                    last_byte_rel_offset,
                    sn,
                    sn_recovered_at_pos,
                }),
            );
        }

        (sn, last_byte_rel_offset + 1)
    }

    /// returns new offset
    pub fn assign_auto(
        &self,
        region: &mut Region<F>,
        wasm_bytecode: &WasmBytecode,
        offset_start: usize,
    ) -> Result<usize, Error> {
        let mut offset = offset_start;

        // items_count+
        let (items_count, items_count_leb_len) = self.markup_leb_section(
            region,
            wasm_bytecode,
            offset,
            &[AssignType::IsItemsCount],
        );
        self.assign(region, &wasm_bytecode, offset, &[AssignType::QFirst], 1, None);
        offset += items_count_leb_len;

        for _item_index in 0..items_count {
            // elem_type{1}
            let elem_type_val = wasm_bytecode.bytes[offset];
            let elem_type: ElementType = elem_type_val.try_into().unwrap();
            let elem_type_val = elem_type_val as u64;
            self.assign(
                region,
                wasm_bytecode,
                offset,
                &[AssignType::IsElemType, AssignType::IsElemTypeCtx],
                1,
                None,
            );
            self.assign(region, wasm_bytecode, offset, &[AssignType::ElemType], elem_type_val, None);
            offset += 1;

            match elem_type_val {
                0 => {
                    // numeric_instruction{1}
                    self.assign(
                        region,
                        wasm_bytecode,
                        offset,
                        &[AssignType::IsNumericInstruction, AssignType::IsElemTypeCtx],
                        1,
                        None,
                    );
                    self.assign(region, wasm_bytecode, offset, &[AssignType::ElemType], elem_type_val, None);
                    offset += 1;

                    // numeric_instruction_leb_arg+
                    let (_numeric_instruction_leb_arg, numeric_instruction_leb_arg_leb_len) = self.markup_leb_section(
                        region,
                        wasm_bytecode,
                        offset,
                        &[AssignType::IsNumericInstructionLebArg, AssignType::IsElemTypeCtx],
                    );
                    for offset in offset..offset + numeric_instruction_leb_arg_leb_len {
                        self.assign(region, wasm_bytecode, offset, &[AssignType::ElemType], elem_type_val, None);
                    }
                    offset += numeric_instruction_leb_arg_leb_len;

                    // numeric_instruction_block_end{1}
                    self.assign(
                        region,
                        wasm_bytecode,
                        offset,
                        &[AssignType::IsBlockEnd, AssignType::IsElemTypeCtx],
                        1,
                        None,
                    );
                    self.assign(region, wasm_bytecode, offset, &[AssignType::ElemType], elem_type_val, None);
                    offset += 1;

                    // funcs_idx_count+
                    let (funcs_idx_count, funcs_idx_count_leb_len) = self.markup_leb_section(
                        region,
                        wasm_bytecode,
                        offset,
                        &[AssignType::IsFuncsIdxCount, AssignType::IsElemTypeCtx],
                    );
                    for offset in offset..offset + funcs_idx_count_leb_len {
                        self.assign(region, wasm_bytecode, offset, &[AssignType::ElemType], elem_type_val, None);
                    }
                    offset += funcs_idx_count_leb_len;

                    for _funcs_idx_index in 0..funcs_idx_count {
                        // func_idx+
                        let (_func_idx, func_idx_leb_len) = self.markup_leb_section(
                            region,
                            wasm_bytecode,
                            offset,
                            &[AssignType::IsFuncIdx, AssignType::IsElemTypeCtx],
                        );
                        for offset in offset..offset + func_idx_leb_len {
                            self.assign(region, wasm_bytecode, offset, &[AssignType::ElemType], elem_type_val, None);
                        }
                        offset += func_idx_leb_len;
                    }
                }
                1 => {
                    // elem_kind{1}
                    self.assign(
                        region,
                        wasm_bytecode,
                        offset,
                        &[AssignType::IsElemKind, AssignType::IsElemTypeCtx],
                        1,
                        None,
                    );
                    self.assign(region, wasm_bytecode, offset, &[AssignType::ElemType], elem_type_val, None);
                    offset += 1;

                    // funcs_idx_count+
                    let (funcs_idx_count, funcs_idx_count_leb_len) = self.markup_leb_section(
                        region,
                        wasm_bytecode,
                        offset,
                        &[AssignType::IsFuncsIdxCount, AssignType::IsElemTypeCtx],
                    );
                    for offset in offset..offset + funcs_idx_count_leb_len {
                        self.assign(region, wasm_bytecode, offset, &[AssignType::ElemType], elem_type_val, None);
                    }
                    offset += funcs_idx_count_leb_len;

                    for _funcs_idx_index in 0..funcs_idx_count {
                        // func_idxs+
                        let (_func_idxs, func_idxs_leb_len) = self.markup_leb_section(
                            region,
                            wasm_bytecode,
                            offset,
                            &[AssignType::IsFuncIdx, AssignType::IsElemTypeCtx],
                        );
                        for offset in offset..offset + func_idxs_leb_len {
                            self.assign(region, wasm_bytecode, offset, &[AssignType::ElemType], elem_type_val, None);
                        }
                        offset += func_idxs_leb_len;
                    }
                }
                _ => { panic!("unsupported element type {}", elem_type_val) }
            }
        }

        if offset != offset_start {
            self.assign(region, &wasm_bytecode, offset - 1, &[AssignType::QLast], 1, None);
        }

        Ok(offset)
    }
}