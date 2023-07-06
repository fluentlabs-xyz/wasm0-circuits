use halo2_proofs::{
    plonk::{Column, ConstraintSystem},
};
use std::{marker::PhantomData};
use std::rc::Rc;
use ethers_core::k256::pkcs8::der::Encode;
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::plonk::{Fixed, VirtualCells};
use halo2_proofs::poly::Rotation;
use itertools::Itertools;
use log::debug;
use eth_types::Field;
use gadgets::util::{Expr, or};
use crate::evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon};
use crate::wasm_circuit::consts::{NumType, WASM_BLOCK_END};
use crate::wasm_circuit::consts::NumericInstruction::{F32Const, F64Const, I32Const, I64Const};
use crate::wasm_circuit::error::Error;
use crate::wasm_circuit::leb128_circuit::circuit::LEB128Chip;
use crate::wasm_circuit::leb128_circuit::helpers::{leb128_compute_sn, leb128_compute_sn_recovered_at_position};
use crate::wasm_circuit::wasm_bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::wasm_bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::wasm_sections::consts::LebParams;
use crate::wasm_circuit::wasm_sections::helpers::configure_check_for_transition;
use crate::wasm_circuit::wasm_sections::global::global_body::types::AssignType;

#[derive(Debug, Clone)]
pub struct WasmGlobalSectionBodyConfig<F: Field> {
    pub q_enable: Column<Fixed>,
    pub is_items_count: Column<Fixed>,
    pub is_global_type: Column<Fixed>,
    pub is_mut_prop: Column<Fixed>,
    pub is_init_opcode: Column<Fixed>,
    pub is_init_val: Column<Fixed>,
    pub is_expr_delimiter: Column<Fixed>,

    pub leb128_chip: Rc<LEB128Chip<F>>,

    _marker: PhantomData<F>,
}

impl<'a, F: Field> WasmGlobalSectionBodyConfig<F>
{}

#[derive(Debug, Clone)]
pub struct WasmGlobalSectionBodyChip<F: Field> {
    pub config: WasmGlobalSectionBodyConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> WasmGlobalSectionBodyChip<F>
{
    pub fn construct(config: WasmGlobalSectionBodyConfig<F>) -> Self {
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
    ) -> WasmGlobalSectionBodyConfig<F> {
        let q_enable = cs.fixed_column();
        let is_items_count = cs.fixed_column();
        let is_global_type = cs.fixed_column();
        let is_mut_prop = cs.fixed_column();
        let is_init_opcode = cs.fixed_column();
        let is_init_val = cs.fixed_column();
        let is_expr_delimiter = cs.fixed_column();

        cs.create_gate("WasmGlobalSectionBody gate", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
            let is_items_count_expr = vc.query_fixed(is_items_count, Rotation::cur());
            let is_global_type_expr = vc.query_fixed(is_global_type, Rotation::cur());
            let is_mut_prop_expr = vc.query_fixed(is_mut_prop, Rotation::cur());
            let is_init_opcode_expr = vc.query_fixed(is_init_opcode, Rotation::cur());
            let is_init_val_expr = vc.query_fixed(is_init_val, Rotation::cur());
            let is_expr_delimiter_expr = vc.query_fixed(is_expr_delimiter, Rotation::cur());

            let byte_val_expr = vc.query_advice(bytecode_table.value, Rotation::cur());

            cb.require_boolean("q_enable is boolean", q_enable_expr.clone());
            cb.require_boolean("is_items_count is boolean", is_items_count_expr.clone());
            cb.require_boolean("is_global_type is boolean", is_global_type_expr.clone());
            cb.require_boolean("is_mut_prop is boolean", is_mut_prop_expr.clone());
            cb.require_boolean("is_init_opcode is boolean", is_init_opcode_expr.clone());
            cb.require_boolean("is_init_val is boolean", is_init_val_expr.clone());
            cb.require_boolean("is_expr_delimiter is boolean", is_expr_delimiter_expr.clone());

            cb.require_equal(
                "exactly one mark flag active at the same time",
                is_items_count_expr.clone()
                    + is_global_type_expr.clone()
                    + is_mut_prop_expr.clone()
                    + is_init_opcode_expr.clone()
                    + is_init_val_expr.clone()
                    + is_expr_delimiter_expr.clone()
                ,
                1.expr(),
            );

            cb.condition(
                or::expr([
                    is_items_count_expr.clone(),
                    is_init_val_expr.clone(),
                ]),
                |bcb| {
                    bcb.require_equal(
                        "is_items_count || is_init_val -> leb128",
                        vc.query_fixed(leb128_chip.config.q_enable, Rotation::cur()),
                        1.expr(),
                    )
                }
            );

            // is_items_count+ -> item+(is_global_type{1} -> is_mut_prop{1} -> is_init_opcode{1} -> is_init_val+ -> is_expr_delimiter{1})
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_items_count+ -> item+(is_global_type{1} ...",
                is_items_count_expr.clone(),
                true,
                &[is_items_count, is_global_type, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_items_count+ -> item+(is_global_type{1} ...",
                is_global_type_expr.clone(),
                false,
                &[is_items_count, is_expr_delimiter, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_global_type{1} -> is_mut_prop{1}",
                is_global_type_expr.clone(),
                true,
                &[is_mut_prop, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_global_type{1} -> is_mut_prop{1}",
                is_mut_prop_expr.clone(),
                false,
                &[is_global_type, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_mut_prop{1} -> is_init_opcode{1}",
                is_mut_prop_expr.clone(),
                true,
                &[is_init_opcode, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_mut_prop{1} -> is_init_opcode{1}",
                is_init_opcode_expr.clone(),
                false,
                &[is_mut_prop, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_init_opcode{1} -> is_init_val+",
                is_init_opcode_expr.clone(),
                true,
                &[is_init_val, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_init_opcode{1} -> is_init_val+",
                is_init_val_expr.clone(),
                false,
                &[is_init_opcode, is_init_val, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_init_val+ -> is_expr_delimiter{1}",
                is_init_val_expr.clone(),
                true,
                &[is_init_val, is_expr_delimiter],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_init_val+ -> is_expr_delimiter{1}",
                is_expr_delimiter_expr.clone(),
                false,
                &[is_init_val, ],
            );

            cb.condition(
                is_global_type_expr.clone(),
                |bcb| {
                    bcb.require_in_set(
                        "is_global_type has eligible byte value",
                        byte_val_expr.clone(),
                        vec![
                            (NumType::I32 as i32).expr(),
                            (NumType::I64 as i32).expr(),
                            // TODO add support for float types
                            // (NumType::F32 as i32).expr(),
                            // (NumType::F64 as i32).expr(),
                        ],
                    )
                }
            );

            cb.condition(
                is_mut_prop_expr.clone(),
                |bcb| {
                    bcb.require_boolean(
                        "is_mut_prop -> bool",
                        byte_val_expr.clone(),
                    )
                }
            );

            cb.condition(
                is_init_opcode_expr.clone(),
                |bcb| {
                    bcb.require_in_set(
                        "is_init_opcode has eligible byte value",
                        byte_val_expr.clone(),
                        vec![
                            (I32Const as i32).expr(),
                            (I64Const as i32).expr(),
                            // TODO add support for float types
                            // (F32Const as i32).expr(),
                            // (F64Const as i32).expr(),
                        ],
                    )
                }
            );

            // TODO constraint is_global_type_expr based on is_init_opcode_expr

            cb.condition(
                is_expr_delimiter_expr.clone(),
                |bcb| {
                    bcb.require_equal(
                        "is_expr_delimiter -> byte value == WASM_BLOCK_END",
                        byte_val_expr.clone(),
                        WASM_BLOCK_END.expr(),
                    )
                }
            );

            cb.gate(q_enable_expr.clone())
        });

        let config = WasmGlobalSectionBodyConfig::<F> {
            q_enable,
            is_items_count,
            is_global_type,
            is_mut_prop,
            is_init_opcode,
            is_init_val,
            is_expr_delimiter,
            leb128_chip,
            _marker: PhantomData,
        };

        config
    }

    pub fn assign(
        &self,
        region: &mut Region<F>,
        wasm_bytecode: &WasmBytecode,
        offset: usize,
        assign_type: AssignType,
        assign_value: u64,
        leb_params: Option<LebParams>,
    ) {
        let q_enable = true;
        debug!(
            "global_section_body: assign at offset {} q_enable {} assign_type {:?} assign_value {} byte_val {:x?}",
            offset,
            q_enable,
            assign_type,
            assign_value,
            wasm_bytecode.bytes[offset],
        );
        if [
            AssignType::IsItemsCount,
            AssignType::IsInitVal,
        ].contains(&assign_type) {
            let p = leb_params.unwrap();
            self.config.leb128_chip.assign(
                region,
                offset,
                q_enable,
                p,
            );
        }
        region.assign_fixed(
            || format!("assign 'q_enable' val {} at {}", q_enable, offset),
            self.config.q_enable,
            offset,
            || Value::known(F::from(q_enable as u64)),
        ).unwrap();
        match assign_type {
            AssignType::IsItemsCount => {
                region.assign_fixed(
                    || format!("assign 'is_items_count' val {} at {}", assign_value, offset),
                    self.config.is_items_count,
                    offset,
                    || Value::known(F::from(assign_value)),
                ).unwrap();
            }
            AssignType::IsGlobalType => {
                region.assign_fixed(
                    || format!("assign 'is_global_type' val {} at {}", assign_value, offset),
                    self.config.is_global_type,
                    offset,
                    || Value::known(F::from(assign_value)),
                ).unwrap();
            }
            AssignType::IsMutProp => {
                region.assign_fixed(
                    || format!("assign 'is_mut_prop' val {} at {}", assign_value, offset),
                    self.config.is_mut_prop,
                    offset,
                    || Value::known(F::from(assign_value)),
                ).unwrap();
            }
            AssignType::IsInitOpcode => {
                region.assign_fixed(
                    || format!("assign 'is_init_opcode' val {} at {}", assign_value, offset),
                    self.config.is_init_opcode,
                    offset,
                    || Value::known(F::from(assign_value)),
                ).unwrap();
            }
            AssignType::IsInitVal => {
                region.assign_fixed(
                    || format!("assign 'is_init_val' val {} at {}", assign_value, offset),
                    self.config.is_init_val,
                    offset,
                    || Value::known(F::from(assign_value)),
                ).unwrap();
            }
            AssignType::IsExprDelimiter => {
                region.assign_fixed(
                    || format!("assign 'is_expr_delimiter' val {} at {}", assign_value, offset),
                    self.config.is_expr_delimiter,
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
        wasm_bytecode: &WasmBytecode,
        leb_bytes_offset: usize,
        assign_type: AssignType,
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
                Some(LebParams{
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

        let (items_count, items_count_leb_len) = self.markup_leb_section(
            region,
            wasm_bytecode,
            offset,
            AssignType::IsItemsCount,
        );
        offset += items_count_leb_len;

        for _item_index in 0..items_count {
            // is_global_type{1}
            self.assign(
                region,
                wasm_bytecode,
                offset,
                AssignType::IsGlobalType,
                1,
                None,
            );
            offset += 1;

            // is_mut_prop{1}
            self.assign(
                region,
                wasm_bytecode,
                offset,
                AssignType::IsMutProp,
                1,
                None,
            );
            offset += 1;

            // is_init_opcode{1}
            self.assign(
                region,
                wasm_bytecode,
                offset,
                AssignType::IsInitOpcode,
                1,
                None,
            );
            offset += 1;

            // is_init_val+
            let (_init_val, init_val_leb_len) = self.markup_leb_section(
                region,
                wasm_bytecode,
                offset,
                AssignType::IsInitVal,
            );
            offset += init_val_leb_len;

            // is_expr_delimiter{1}
            self.assign(
                region,
                wasm_bytecode,
                offset,
                AssignType::IsExprDelimiter,
                1,
                None,
            );
            offset += 1;
        }

        Ok(offset)
    }
}