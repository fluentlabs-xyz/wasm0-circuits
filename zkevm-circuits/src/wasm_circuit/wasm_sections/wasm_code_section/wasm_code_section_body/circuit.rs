use halo2_proofs::{
    plonk::{Column, ConstraintSystem},
};
use std::{marker::PhantomData};
use std::rc::Rc;
use ethers_core::k256::pkcs8::der::Encode;
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::plonk::{Fixed, VirtualCells};
use halo2_proofs::poly::Rotation;
use log::debug;
use eth_types::Field;
use gadgets::util::{Expr, or};
use crate::evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon};
use crate::wasm_circuit::error::Error;
use crate::wasm_circuit::leb128_circuit::circuit::LEB128Chip;
use crate::wasm_circuit::leb128_circuit::helpers::{leb128_compute_sn, leb128_compute_sn_recovered_at_position};
use crate::wasm_circuit::wasm_bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::wasm_bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::wasm_sections::consts::LimitsType;
use crate::wasm_circuit::wasm_sections::helpers::configure_check_for_transition;
use crate::wasm_circuit::wasm_sections::wasm_code_section::wasm_code_section_body::consts::ExportDesc;

#[derive(Debug, Clone)]
pub struct WasmCodeSectionBodyConfig<F: Field> {
    pub q_enable: Column<Fixed>,
    pub is_funcs_count: Column<Fixed>,
    pub is_func_len: Column<Fixed>,
    pub is_valtype_transitions_count: Column<Fixed>,
    pub is_valtype_repetition_count: Column<Fixed>,
    pub is_valtype: Column<Fixed>,
    pub is_code_body: Column<Fixed>,

    pub leb128_chip: Rc<LEB128Chip<F>>,

    _marker: PhantomData<F>,
}

impl<'a, F: Field> WasmCodeSectionBodyConfig<F>
{}

#[derive(Debug, Clone)]
pub struct WasmCodeSectionBodyChip<F: Field> {
    pub config: WasmCodeSectionBodyConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> WasmCodeSectionBodyChip<F>
{
    pub fn construct(config: WasmCodeSectionBodyConfig<F>) -> Self {
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
    ) -> WasmCodeSectionBodyConfig<F> {
        let q_enable = cs.fixed_column();
        let is_items_count = cs.fixed_column();
        let is_export_name_len = cs.fixed_column();
        let is_export_name = cs.fixed_column();
        let is_exportdesc_type = cs.fixed_column();
        let is_exportdesc_val = cs.fixed_column();

        cs.create_gate("WasmCodeSectionBody gate", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
            let is_funcs_count = vc.query_fixed(q_enable, Rotation::cur());
            let is_func_len = vc.query_fixed(q_enable, Rotation::cur());
            let is_valtype_transitions_count = vc.query_fixed(q_enable, Rotation::cur());
            let is_valtype_repetition_count = vc.query_fixed(q_enable, Rotation::cur());
            let is_valtype = vc.query_fixed(q_enable, Rotation::cur());
            let is_code_body = vc.query_fixed(q_enable, Rotation::cur());

            let byte_val_expr = vc.query_advice(bytecode_table.value, Rotation::cur());

            cb.require_boolean("q_enable is boolean", q_enable_expr.clone());
            cb.require_boolean("is_funcs_count is boolean", is_funcs_count.clone());
            cb.require_boolean("is_func_len is boolean", is_func_len.clone());
            cb.require_boolean("is_valtype_transitions_count is boolean", is_valtype_transitions_count.clone());
            cb.require_boolean("is_valtype_repetition_count is boolean", is_valtype_repetition_count.clone());
            cb.require_boolean("is_valtype is boolean", is_valtype.clone());
            cb.require_boolean("is_code_body is boolean", is_code_body.clone());

            cb.require_equal(
                "exactly one mark flag active at the same time",
                is_funcs_count.clone()
                    + is_func_len.clone()
                    + is_valtype_transitions_count.clone()
                    + is_valtype_repetition_count.clone()
                    + is_valtype.clone()
                    + is_code_body.clone(),
                1.expr(),
            );

            cb.condition(
                or::expr([
                    is_funcs_count.clone(),
                    is_func_len.clone(),
                    is_valtype_transitions_count.clone(),
                    is_valtype_repetition_count.clone(),
                ]),
                |cbc| {
                    cbc.require_equal(
                        "is_funcs_count || is_func_len || is_valtype_transitions_count || is_valtype_repetition_count -> leb128",
                        vc.query_fixed(leb128_chip.config.q_enable, Rotation::cur()),
                        1.expr(),
                    )
                }
            );

            // funcs_count -> func_len -> valtype_transitions_count -> valtype_repetition_count -> valtype -> code_body (TODO)
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_items_count+ -> item+(is_export_name_len+ ...",
                is_items_count_expr.clone(),
                true,
                &[is_items_count, is_export_name_len],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_items_count+ -> item+(is_export_name_len+ ...",
                is_export_name_len_expr.clone(),
                false,
                &[is_items_count, is_exportdesc_val, is_export_name_len],
            );

            cb.gate(q_enable_expr.clone())
        });

        let config = WasmCodeSectionBodyConfig::<F> {
            q_enable,
            is_funcs_count,
            is_func_len,
            is_valtype_transitions_count,
            is_valtype_repetition_count,
            is_valtype,
            is_code_body,
            leb128_chip,
            _marker: PhantomData,
        };

        config
    }

    pub fn assign_init(
        &self,
        region: &mut Region<F>,
        offset_max: usize,
    ) {
        for offset in 0..=offset_max {
            self.assign(
                region,
                offset,
                false,
                false,
                false,
                false,
                false,
                0,
                0,
                0,
                0,
            );
        }
    }

    pub fn assign(
        &self,
        region: &mut Region<F>,
        offset: usize,
        is_funcs_count: bool,
        is_func_len: bool,
        is_valtype_transitions_count: bool,
        is_valtype_repetition_count: bool,
        is_valtype: bool,
        is_code_body: bool,
        leb_byte_rel_offset: usize,
        leb_last_byte_rel_offset: usize,
        leb_sn: u64,
        leb_sn_recovered_at_pos: u64,
    ) {
        let q_enable = is_funcs_count || is_func_len || is_valtype_transitions_count || is_valtype_repetition_count || is_valtype || is_code_body;
        debug!(
            "offset {} q_enable {} is_funcs_count {} is_func_len {} is_valtype_transitions_count {} is_valtype_repetition_count {} is_valtype {} is_code_body {}",
            offset,
            q_enable,
            is_funcs_count ,
            is_func_len ,
            is_valtype_transitions_count ,
            is_valtype_repetition_count ,
            is_valtype ,
            is_code_body,
        );
        if is_funcs_count || is_func_len || is_valtype_transitions_count || is_valtype_repetition_count {
            let is_first_leb_byte = leb_byte_rel_offset == 0;
            let is_last_leb_byte = leb_byte_rel_offset == leb_last_byte_rel_offset;
            let is_leb_byte_has_cb = leb_byte_rel_offset < leb_last_byte_rel_offset;
            self.config.leb128_chip.assign(
                region,
                offset,
                leb_byte_rel_offset,
                q_enable,
                is_first_leb_byte,
                is_last_leb_byte,
                is_leb_byte_has_cb,
                false,
                leb_sn,
                leb_sn_recovered_at_pos,
            );
        }
        region.assign_fixed(
            || format!("assign 'q_enable' val {} at {}", q_enable, offset),
            self.config.q_enable,
            offset,
            || Value::known(F::from(q_enable as u64)),
        ).unwrap();
        // TODO
    }

    /// returns sn and leb len
    fn markup_leb_section(
        &self,
        region: &mut Region<F>,
        leb_bytes: &[u8],
        leb_bytes_start_offset: usize,
        is_funcs_count: bool,
        is_func_len: bool,
        is_valtype_transitions_count: bool,
        is_valtype_repetition_count: bool,
    ) -> (u64, usize) {
        const OFFSET: usize = 0;
        let (leb_sn, last_byte_offset) = leb128_compute_sn(leb_bytes, false, OFFSET).unwrap();
        let mut leb_sn_recovered_at_pos = 0;
        for byte_offset in OFFSET..=last_byte_offset {
            leb_sn_recovered_at_pos = leb128_compute_sn_recovered_at_position(
                leb_sn_recovered_at_pos,
                false,
                byte_offset,
                last_byte_offset,
                leb_bytes[byte_offset],
            );
            let offset = leb_bytes_start_offset + byte_offset;
            self.assign(
                region,
                offset,
                is_funcs_count,
                is_func_len,
                is_valtype_transitions_count,
                is_valtype_repetition_count,
                false,
                false,
                byte_offset,
                last_byte_offset,
                leb_sn,
                leb_sn_recovered_at_pos,
            );
        }

        (leb_sn, last_byte_offset + 1)
    }

    /// returns new offset
    pub fn assign_auto(
        &self,
        region: &mut Region<F>,
        wasm_bytecode: &WasmBytecode,
        offset_start: usize,
    ) -> Result<usize, Error> {
        let mut offset = offset_start;
        debug!("offset_start {}", offset);

        let (items_count, items_count_leb_len) = self.markup_leb_section(
            region,
            &wasm_bytecode.bytes.as_slice()[offset..],
            offset,
            true,
            false,
            false,
        );
        debug!("offset {} items_count {} items_count_leb_len {}", offset, items_count, items_count_leb_len);
        offset += items_count_leb_len;

        for _item_index in 0..items_count {
            let (export_name_len, export_name_len_leb_len) = self.markup_leb_section(
                region,
                &wasm_bytecode.bytes.as_slice()[offset..],
                offset,
                false,
                true,
                false,
            );
            debug!("offset {} export_name_len {} export_name_len_leb_len {}", offset, export_name_len, export_name_len_leb_len);
            offset += export_name_len_leb_len;

            let export_name_new_offset = self.markup_name_section(
                region,
                offset,
                true,
                export_name_len as usize,
            );
            debug!("offset {} export_name_new_offset {}", offset, export_name_new_offset);
            offset = export_name_new_offset;

            let exportdesc_type = wasm_bytecode.bytes.as_slice()[offset];
            debug!("offset {} export_desc_type {}", offset, exportdesc_type);
            self.assign(
                region,
                offset,
                false,
                false,
                false,
                true,
                false,
                0,
                0,
                0,
                0,
            );
            offset += 1;

            let (exportdesc_val, exportdesc_val_leb_len) = self.markup_leb_section(
                region,
                &wasm_bytecode.bytes.as_slice()[offset..],
                offset,
                false,
                false,
                true,
            );
            debug!("offset {} exportdesc_val {} exportdesc_val_leb_len {}", offset, exportdesc_val, exportdesc_val_leb_len);
            offset += exportdesc_val_leb_len;
        }

        Ok(offset)
    }
}