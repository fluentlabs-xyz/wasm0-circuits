use halo2_proofs::{
    plonk::{Column, ConstraintSystem},
};
use std::{marker::PhantomData};
use std::rc::Rc;
use ethers_core::k256::pkcs8::der::Encode;
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::plonk::{Advice, Fixed, VirtualCells};
use halo2_proofs::poly::Rotation;
use log::debug;
use eth_types::Field;
use gadgets::binary_number::BinaryNumberChip;
use gadgets::util::{Expr, or};
use crate::evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon};
use crate::wasm_circuit::consts::NumericInstruction::I32Const;
use crate::wasm_circuit::consts::{LimitsType, MemSegmentType, ReferenceType, WASM_BLOCK_END};
use crate::wasm_circuit::error::Error;
use crate::wasm_circuit::leb128_circuit::circuit::LEB128Chip;
use crate::wasm_circuit::leb128_circuit::helpers::{leb128_compute_sn, leb128_compute_sn_recovered_at_position};
use crate::wasm_circuit::wasm_bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::wasm_bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::wasm_sections::consts::LebParams;
use crate::wasm_circuit::wasm_sections::helpers::configure_check_for_transition;
use crate::wasm_circuit::wasm_sections::wasm_element_section::wasm_element_section_body::consts::ElementType;
use crate::wasm_circuit::wasm_sections::wasm_element_section::wasm_element_section_body::types::AssignType;

#[derive(Debug, Clone)]
pub struct WasmElementSectionBodyConfig<F: Field> {
    pub q_enable: Column<Fixed>,
    pub is_items_count: Column<Fixed>,
    pub is_elem_type: Column<Fixed>,
    pub is_elem_body: Column<Fixed>,
    pub is_numeric_instruction: Column<Fixed>,
    pub is_numeric_instruction_leb_arg: Column<Fixed>,
    pub is_block_end: Column<Fixed>,
    pub is_funcs_idx_count: Column<Fixed>,
    pub is_func_idx: Column<Fixed>,
    pub is_elem_kind: Column<Fixed>,

    pub elem_body_type: Column<Advice>,

    pub elem_type_chip: Rc<BinaryNumberChip<F, ElementType, 8>>,

    pub leb128_chip: Rc<LEB128Chip<F>>,

    _marker: PhantomData<F>,
}

impl<'a, F: Field> WasmElementSectionBodyConfig<F>
{}

#[derive(Debug, Clone)]
pub struct WasmElementSectionBodyChip<F: Field> {
    pub config: WasmElementSectionBodyConfig<F>,
    _marker: PhantomData<F>,
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
    ) -> WasmElementSectionBodyConfig<F> {
        let q_enable = cs.fixed_column();
        let is_items_count = cs.fixed_column();
        let is_elem_type = cs.fixed_column();
        let is_elem_body = cs.fixed_column();
        let is_numeric_instruction = cs.fixed_column();
        let is_numeric_instruction_leb_arg = cs.fixed_column();
        let is_block_end = cs.fixed_column();
        let is_funcs_idx_count = cs.fixed_column();
        let is_func_idx = cs.fixed_column();
        let is_elem_kind = cs.fixed_column();

        let elem_body_type = cs.advice_column();
        let config = BinaryNumberChip::configure(
            cs,
            is_elem_body,
            Some(elem_body_type.into()),
        );
        let elem_type_chip = Rc::new(BinaryNumberChip::construct(config));

        cs.create_gate("WasmElementSectionBody gate", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
            let is_items_count_expr = vc.query_fixed(is_items_count, Rotation::cur());
            let is_elem_type_expr = vc.query_fixed(is_elem_type, Rotation::cur());
            let is_elem_body_expr = vc.query_fixed(is_elem_body, Rotation::cur());
            let is_numeric_instruction_expr = vc.query_fixed(is_numeric_instruction, Rotation::cur());
            let is_numeric_instruction_leb_arg_expr = vc.query_fixed(is_numeric_instruction_leb_arg, Rotation::cur());
            let is_block_end_expr = vc.query_fixed(is_block_end, Rotation::cur());
            let is_funcs_idx_count_expr = vc.query_fixed(is_funcs_idx_count, Rotation::cur());
            let is_func_idx_expr = vc.query_fixed(is_func_idx, Rotation::cur());
            let is_elem_kind_expr = vc.query_fixed(is_elem_kind, Rotation::cur());

            let byte_val_expr = vc.query_advice(bytecode_table.value, Rotation::cur());

            cb.require_boolean("q_enable is boolean", q_enable_expr.clone());
            cb.require_boolean("is_items_count is boolean", is_items_count_expr.clone());
            cb.require_boolean("is_elem_type is boolean", is_elem_type_expr.clone());
            cb.require_boolean("is_elem_body is boolean", is_elem_body_expr.clone());
            cb.require_boolean("is_numeric_instruction is boolean", is_numeric_instruction_expr.clone());
            cb.require_boolean("is_numeric_instruction_leb_arg is boolean", is_numeric_instruction_leb_arg_expr.clone());
            cb.require_boolean("is_block_end is boolean", is_block_end_expr.clone());
            cb.require_boolean("is_funcs_idx_count is boolean", is_funcs_idx_count_expr.clone());
            cb.require_boolean("is_func_idx is boolean", is_func_idx_expr.clone());
            cb.require_boolean("is_elem_kind is boolean", is_elem_kind_expr.clone());

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

            cb.require_equal(
                "is_elem_body check relation with other flags",
                is_numeric_instruction_expr.clone() +
                    is_numeric_instruction_leb_arg_expr.clone() +
                    is_block_end_expr.clone() +
                    is_funcs_idx_count_expr.clone() +
                    is_func_idx_expr.clone() +
                    is_elem_kind_expr.clone(),
                is_elem_body_expr.clone()
            );

            cb.condition(
                or::expr([
                    is_items_count_expr.clone(),
                    is_funcs_idx_count_expr.clone(),
                    is_func_idx_expr.clone(),
                    is_numeric_instruction_leb_arg_expr.clone(),
                ]),
                |cbc| {
                    cbc.require_equal(
                        "is_items_count || is_funcs_idx_count || is_func_idx || is_numeric_instruction_leb_arg => leb128",
                        vc.query_fixed(leb128_chip.config.q_enable, Rotation::cur()),
                        1.expr(),
                    )
                }
            );

            // TODO
            // items_count+ -> elem+(elem_type(1) -> elem_body+)
            // elem_body+(elem_type(1)==0 -> numeric_instruction(1) -> numeric_instruction_leb_arg+ -> numeric_instruction_block_end+ -> funcs_idx_count+ -> func_idxs+)
            // elem_body+(elem_type(1)==1 -> elem_kind(1) -> funcs_idx_count+ -> func_idxs+)
            // configure_check_for_transition(
            //     &mut cb,
            //     vc,
            //     "check next: reference_type_count+ -> reference_type(1)",
            //     is_reference_type_count_expr.clone(),
            //     true,
            //     &[is_reference_type_count, is_reference_type, ],
            // );
            // configure_check_for_transition(
            //     &mut cb,
            //     vc,
            //     "check prev: reference_type_count+ -> reference_type(1)",
            //     is_reference_type_expr.clone(),
            //     false,
            //     &[is_reference_type_count, ],
            // );

            cb.gate(q_enable_expr.clone())
        });

        let config = WasmElementSectionBodyConfig::<F> {
            q_enable,
            is_items_count,
            is_elem_type,
            is_elem_body,
            is_numeric_instruction,
            is_numeric_instruction_leb_arg,
            is_block_end,
            is_funcs_idx_count,
            is_func_idx,
            is_elem_kind,
            elem_body_type,
            elem_type_chip,
            leb128_chip,
            _marker: PhantomData,
        };

        config
    }

    pub fn assign(
        &self,
        region: &mut Region<F>,
        offset: usize,
        assign_type: AssignType,
        assign_value: u64,
        leb_params: Option<LebParams>,
    ) {
        let q_enable = true;
        debug!(
            "assign at offset {} q_enable {} assign_type {:?} assign_value {}",
            offset,
            q_enable,
            assign_type,
            assign_value,
        );
        region.assign_fixed(
            || format!("assign 'q_enable' val {} at {}", q_enable, offset),
            self.config.q_enable,
            offset,
            || Value::known(F::from(q_enable as u64)),
        ).unwrap();
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
            AssignType::Unknown => {
                panic!("unknown assign type")
            }
            AssignType::IsItemsCount => {
                region.assign_fixed(
                    || format!("assign 'is_items_count' val {} at {}", assign_value, offset),
                    self.config.is_items_count,
                    offset,
                    || Value::known(F::from(assign_value)),
                ).unwrap();
            }
            AssignType::IsElemBody => {
                region.assign_fixed(
                    || format!("assign 'is_elem_body' val {} at {}", 1, offset),
                    self.config.is_elem_body,
                    offset,
                    || Value::known(F::from(1)),
                ).unwrap();
                region.assign_advice(
                    || format!("assign 'is_elem_body' val {} at {}", assign_value, offset),
                    self.config.elem_body_type,
                    offset,
                    || Value::known(F::from(assign_value)),
                ).unwrap();
                let opcode = (assign_value as i32).try_into().unwrap();
                self.config.elem_type_chip.assign(
                    region,
                    offset,
                    &opcode,
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
        }
    }

    /// returns sn and leb len
    fn markup_leb_section(
        &self,
        region: &mut Region<F>,
        bytecode: &WasmBytecode,
        leb_start_offset: usize,
        assign_type: AssignType,
        assign_value: bool,
    ) -> (u64, usize) {
        if ![
            AssignType::IsItemsCount,
            AssignType::IsNumericInstructionLebArg,
            AssignType::IsFuncsIdxCount,
            AssignType::IsFuncIdx,
        ].contains(&assign_type) {
            panic!("unsupported assign type {:?}", assign_type)
        }
        const OFFSET: usize = 0;
        let is_signed_leb = false;
        let (sn, last_byte_rel_offset) = leb128_compute_sn(&bytecode.bytes[leb_start_offset..], is_signed_leb, OFFSET).unwrap();
        let mut sn_recovered_at_pos = 0;
        for byte_rel_offset in OFFSET..=last_byte_rel_offset {
            let offset = leb_start_offset + byte_rel_offset;
            let byte_val = bytecode.bytes[offset];
            sn_recovered_at_pos = leb128_compute_sn_recovered_at_position(
                sn_recovered_at_pos,
                false,
                byte_rel_offset,
                last_byte_rel_offset,
                byte_val,
            );
            self.assign(
                region,
                offset,
                assign_type,
                assign_value as u64,
                Some(LebParams {
                    is_signed: is_signed_leb,
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
            &wasm_bytecode,
            offset,
            AssignType::IsItemsCount,
            true,
        );
        offset += items_count_leb_len;

        for _item_index in 0..items_count {
            // elem_type(1)
            let elem_type = wasm_bytecode.bytes[offset];
            self.assign(
                region,
                offset,
                AssignType::IsElemType,
                1,
                None,
            );
            offset += 1;

            match elem_type {
                0 => {
                    // numeric_instruction(1)
                    self.assign(
                        region,
                        offset,
                        AssignType::IsNumericInstruction,
                        1,
                        None,
                    );
                    self.assign(region, offset, AssignType::IsElemBody, elem_type as u64, None);
                    offset += 1;

                    // numeric_instruction_leb_arg+
                    let (_numeric_instruction_leb_arg, numeric_instruction_leb_arg_leb_len) = self.markup_leb_section(
                        region,
                        &wasm_bytecode,
                        offset,
                        AssignType::IsNumericInstructionLebArg,
                        true,
                    );
                    for offset in offset..offset + numeric_instruction_leb_arg_leb_len {
                        self.assign(region, offset, AssignType::IsElemBody, elem_type as u64, None);
                    }
                    offset += numeric_instruction_leb_arg_leb_len;

                    // numeric_instruction_block_end(1)
                    self.assign(
                        region,
                        offset,
                        AssignType::IsBlockEnd,
                        1,
                        None,
                    );
                    self.assign(region, offset, AssignType::IsElemBody, elem_type as u64, None);
                    offset += 1;

                    // funcs_idx_count+
                    let (funcs_idx_count, funcs_idx_count_leb_len) = self.markup_leb_section(
                        region,
                        &wasm_bytecode,
                        offset,
                        AssignType::IsFuncsIdxCount,
                        true,
                    );
                    for offset in offset..offset + funcs_idx_count_leb_len {
                        self.assign(region, offset, AssignType::IsElemBody, elem_type as u64, None);
                    }
                    offset += funcs_idx_count_leb_len;

                    for _funcs_idx_index in 0..funcs_idx_count {
                        // func_idx+
                        let (_func_idx, func_idx_leb_len) = self.markup_leb_section(
                            region,
                            &wasm_bytecode,
                            offset,
                            AssignType::IsFuncIdx,
                            true,
                        );
                        for offset in offset..offset + func_idx_leb_len {
                            self.assign(region, offset, AssignType::IsElemBody, elem_type as u64, None);
                        }
                        offset += func_idx_leb_len;
                    }
                }
                1 => {
                    // elem_kind(1)
                    self.assign(
                        region,
                        offset,
                        AssignType::IsElemKind,
                        1,
                        None,
                    );
                    self.assign(region, offset, AssignType::IsElemBody, elem_type as u64, None);
                    offset += 1;

                    // funcs_idx_count+
                    let (funcs_idx_count, funcs_idx_count_leb_len) = self.markup_leb_section(
                        region,
                        &wasm_bytecode,
                        offset,
                        AssignType::IsFuncsIdxCount,
                        true,
                    );
                    for offset in offset..offset + funcs_idx_count_leb_len {
                        self.assign(region, offset, AssignType::IsElemBody, elem_type as u64, None);
                    }
                    offset += funcs_idx_count_leb_len;

                    for _funcs_idx_index in 0..funcs_idx_count {
                        // func_idxs+
                        let (_func_idxs, func_idxs_leb_len) = self.markup_leb_section(
                            region,
                            &wasm_bytecode,
                            offset,
                            AssignType::IsFuncIdx,
                            true,
                        );
                        for offset in offset..offset + func_idxs_leb_len {
                            self.assign(region, offset, AssignType::IsElemBody, elem_type as u64, None);
                        }
                        offset += func_idxs_leb_len;
                    }
                }
                _ => { panic!("unsupported element type {}", elem_type) }
            }
        }

        Ok(offset)
    }
}