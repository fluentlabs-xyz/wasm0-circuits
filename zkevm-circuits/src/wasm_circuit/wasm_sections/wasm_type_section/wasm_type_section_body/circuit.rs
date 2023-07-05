use halo2_proofs::{
    plonk::{Column, ConstraintSystem},
};
use std::{marker::PhantomData};
use std::rc::Rc;
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::plonk::Fixed;
use halo2_proofs::poly::Rotation;
use itertools::Itertools;
use log::debug;
use eth_types::Field;
use gadgets::util::not;
use crate::evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon};
use crate::wasm_circuit::error::Error;
use crate::wasm_circuit::leb128_circuit::circuit::LEB128Chip;
use crate::wasm_circuit::leb128_circuit::helpers::{leb128_compute_sn, leb128_compute_sn_recovered_at_position};
use crate::wasm_circuit::wasm_bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::wasm_bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::wasm_sections::consts::LebParams;
use crate::wasm_circuit::wasm_sections::wasm_type_section::wasm_type_section_body::types::AssignType;
use crate::wasm_circuit::wasm_sections::wasm_type_section::wasm_type_section_item::circuit::WasmTypeSectionItemChip;

#[derive(Debug, Clone)]
pub struct WasmTypeSectionBodyConfig<F> {
    pub q_enable: Column<Fixed>,
    pub is_body_items_count: Column<Fixed>,
    pub is_body: Column<Fixed>,

    pub wasm_type_section_item_chip: Rc<WasmTypeSectionItemChip<F>>,
    pub leb128_chip: Rc<LEB128Chip<F>>,

    _marker: PhantomData<F>,
}

impl<'a, F: Field> WasmTypeSectionBodyConfig<F>
{}

#[derive(Debug, Clone)]
pub struct WasmTypeSectionBodyChip<F> {
    pub config: WasmTypeSectionBodyConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> WasmTypeSectionBodyChip<F>
{
    pub fn construct(config: WasmTypeSectionBodyConfig<F>) -> Self {
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
        wasm_type_section_item_chip: Rc<WasmTypeSectionItemChip<F>>,
    ) -> WasmTypeSectionBodyConfig<F> {
        let q_enable = cs.fixed_column();
        let is_body_items_count= cs.fixed_column();
        let is_body= cs.fixed_column();

        cs.create_gate("WasmTypeSectionBody gate", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
            let is_body_items_count_expr = vc.query_fixed(is_body_items_count, Rotation::cur());
            let is_body_expr = vc.query_fixed(is_body, Rotation::cur());

            let byte_value_expr = vc.query_advice(bytecode_table.value, Rotation::cur());

            cb.require_boolean("q_enable is boolean", q_enable_expr.clone());
            cb.require_boolean("is_body_items_count is boolean", is_body_items_count_expr.clone());
            cb.require_boolean("is_body is boolean", is_body_expr.clone());

            cb.condition(
                is_body_items_count_expr.clone(),
                |bcb| {
                    bcb.require_zero(
                        "if is_body_items_count -> leb128",
                        not::expr(vc.query_fixed(leb128_chip.config.q_enable, Rotation::cur()))
                    );
                }
            );

            cb.require_equal(
                "if is_body_expr <-> wasm_type_section_item",
                is_body_expr.clone(),
                vc.query_fixed(wasm_type_section_item_chip.config.q_enable, Rotation::cur()),
            );

            // TODO add constraints

            cb.gate(q_enable_expr.clone())
        });

        let config = WasmTypeSectionBodyConfig::<F> {
            q_enable,
            is_body_items_count,
            is_body,
            leb128_chip,
            wasm_type_section_item_chip,
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
            "assign at offset {} q_enable {} assign_type {:?} assign_value {} byte_val {}",
            offset,
            q_enable,
            assign_type,
            assign_value,
            wasm_bytecode.bytes[offset],
        );
        if [
            AssignType::IsBodyItemsCount,
        ].contains(&assign_type) {
            let p = leb_params.unwrap();
            self.config.leb128_chip.assign(
                region,
                offset,
                true,
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
            AssignType::IsBodyItemsCount => {
                region.assign_fixed(
                    || format!("assign 'is_body_items_count' val {} at {}", assign_value, offset),
                    self.config.is_body_items_count,
                    offset,
                    || Value::known(F::from(assign_value)),
                ).unwrap();
            }
            AssignType::IsBody => {
                region.assign_fixed(
                    || format!("assign 'is_body' val {} at {}", assign_value, offset),
                    self.config.is_body,
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

    pub fn assign_auto(
        &self,
        region: &mut Region<F>,
        wasm_bytecode: &WasmBytecode,
        offset_start: usize,
    ) -> Result<usize, Error> {
        let mut offset = offset_start;
        let (body_items_count, body_items_count_leb_len) = self.markup_leb_section(
            region,
            wasm_bytecode,
            offset,
            AssignType::IsBodyItemsCount,
        );
        offset += body_items_count_leb_len;

        for _body_item_index in 0..body_items_count {
            let next_body_item_offset = self.config.wasm_type_section_item_chip.assign_auto(
                region,
                wasm_bytecode,
                offset,
            )?;
            for offset in offset..next_body_item_offset {
                self.assign(
                    region,
                    wasm_bytecode,
                    offset,
                    AssignType::IsBody,
                    1,
                    None,
                );
            }
            offset = next_body_item_offset;
        }

        Ok(offset)
    }
}