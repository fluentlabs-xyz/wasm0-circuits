use halo2_proofs::{
    plonk::{Column, ConstraintSystem},
};
use std::{marker::PhantomData};
use std::rc::Rc;
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::plonk::Fixed;
use halo2_proofs::poly::Rotation;
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
        offset: usize,
        is_body_items_count: bool,
        is_body: bool,
        leb_params: Option<LebParams>,
    ) {
        if is_body_items_count || is_body_items_count {
            let p = leb_params.unwrap();
            self.config.leb128_chip.assign(
                region,
                offset,
                true,
                p,
            );
        }
        let val = is_body_items_count || is_body;
        region.assign_fixed(
            || format!("assign 'q_enable' val {} at {}", val, offset),
            self.config.q_enable,
            offset,
            || Value::known(F::from(val as u64)),
        ).unwrap();
        region.assign_fixed(
            || format!("assign 'is_body_items_count' val {} at {}", is_body_items_count, offset),
            self.config.is_body_items_count,
            offset,
            || Value::known(F::from(is_body_items_count as u64)),
        ).unwrap();
        region.assign_fixed(
            || format!("assign 'is_body' val {} at {}", is_body, offset),
            self.config.is_body,
            offset,
            || Value::known(F::from(is_body as u64)),
        ).unwrap();
    }

    /// returns sn and leb len
    fn markup_leb_section(
        &self,
        region: &mut Region<F>,
        leb_bytes: &[u8],
        leb_bytes_start_offset: usize,
        is_body_items_count: bool,
    ) -> (u64, usize) {
        const OFFSET: usize = 0;
        let is_signed_leb = false;
        let (sn, last_byte_rel_offset) = leb128_compute_sn(leb_bytes, is_signed_leb, OFFSET).unwrap();
        let mut sn_recovered_at_pos = 0;
        for byte_rel_offset in OFFSET..=last_byte_rel_offset {
            let offset = leb_bytes_start_offset + byte_rel_offset;
            sn_recovered_at_pos = leb128_compute_sn_recovered_at_position(
                sn_recovered_at_pos,
                false,
                byte_rel_offset,
                last_byte_rel_offset,
                leb_bytes[byte_rel_offset],
            );
            self.assign(
                region,
                offset,
                is_body_items_count,
                false,
                Some(LebParams{
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

    pub fn assign_auto(
        &self,
        region: &mut Region<F>,
        wasm_bytecode: &WasmBytecode,
        offset_start: usize,
    ) -> Result<usize, Error> {
        let mut offset = offset_start;
        let (body_items_count_sn, body_items_count_leb_len) = self.markup_leb_section(
            region,
            &wasm_bytecode.bytes[offset..],
            offset,
            true,
        );
        offset += body_items_count_leb_len;

        for _body_item_index in 0..body_items_count_sn {
            let next_body_item_offset = self.config.wasm_type_section_item_chip.assign_auto(
                region,
                wasm_bytecode,
                offset,
            )?;
            for offset in offset..next_body_item_offset {
                self.assign(
                    region,
                    offset,
                    false,
                    true,
                    None,
                );
            }
            offset = next_body_item_offset;
        }

        Ok(offset)
    }
}