use halo2_proofs::{
    plonk::{Column, ConstraintSystem},
};
use std::{marker::PhantomData};
use std::rc::Rc;
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::plonk::{Expression, Fixed, VirtualCells};
use halo2_proofs::poly::Rotation;
use log::debug;
use eth_types::Field;
use gadgets::util::{Expr, not, or};
use crate::evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon};
use crate::wasm_circuit::error::Error;
use crate::wasm_circuit::leb128_circuit::circuit::LEB128Chip;
use crate::wasm_circuit::leb128_circuit::helpers::{leb128_compute_sn, leb128_compute_sn_recovered_at_position};
use crate::wasm_circuit::utf8_circuit::circuit::UTF8Chip;
use crate::wasm_circuit::wasm_bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::wasm_bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::wasm_sections::consts::NumType;
use crate::wasm_circuit::wasm_sections::helpers::configure_check_for_transition;
use crate::wasm_circuit::wasm_sections::wasm_import_section::wasm_import_section_body::consts::ImportDescType::TypeImportDescType;
use crate::wasm_circuit::wasm_sections::wasm_type_section::wasm_type_section_item::consts::Type::FuncType;

#[derive(Debug, Clone)]
pub struct WasmImportSectionBodyConfig<F: Field> {
    pub q_enable: Column<Fixed>,
    pub is_items_count: Column<Fixed>,
    pub is_mod_name_len: Column<Fixed>,
    pub is_mod_name: Column<Fixed>,
    pub is_import_name_len: Column<Fixed>,
    pub is_import_name: Column<Fixed>,
    pub is_importdesc_type: Column<Fixed>,
    pub is_importdesc_val: Column<Fixed>,

    pub leb128_chip: Rc<LEB128Chip<F>>,
    pub utf8_chip: Rc<UTF8Chip<F>>,

    _marker: PhantomData<F>,
}

impl<'a, F: Field> WasmImportSectionBodyConfig<F>
{}

#[derive(Debug, Clone)]
pub struct WasmImportSectionBodyChip<F: Field> {
    pub config: WasmImportSectionBodyConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> WasmImportSectionBodyChip<F>
{
    pub fn construct(config: WasmImportSectionBodyConfig<F>) -> Self {
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
        utf8_chip: Rc<UTF8Chip<F>>,
    ) -> WasmImportSectionBodyConfig<F> {
        let q_enable = cs.fixed_column();
        let is_items_count = cs.fixed_column();
        let is_mod_name_len = cs.fixed_column();
        let is_mod_name = cs.fixed_column();
        let is_import_name_len = cs.fixed_column();
        let is_import_name = cs.fixed_column();
        let is_importdesc_type = cs.fixed_column();
        let is_importdesc_val = cs.fixed_column();

        cs.create_gate("WasmImportSectionBody gate", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
            let is_items_count_expr = vc.query_fixed(is_items_count, Rotation::cur());
            let is_mod_name_len_expr = vc.query_fixed(is_mod_name_len, Rotation::cur());
            let is_mod_name_expr = vc.query_fixed(is_mod_name, Rotation::cur());
            let is_import_name_len_expr = vc.query_fixed(is_import_name_len, Rotation::cur());
            let is_import_name_expr = vc.query_fixed(is_import_name, Rotation::cur());
            let is_importdesc_type_expr = vc.query_fixed(is_importdesc_type, Rotation::cur());
            let is_importdesc_val_expr = vc.query_fixed(is_importdesc_val, Rotation::cur());

            let byte_value_expr = vc.query_advice(bytecode_table.value, Rotation::cur());

            let utf8_q_enabled_expr = vc.query_fixed(utf8_chip.config.q_enable, Rotation::cur());

            cb.require_boolean("q_enable is boolean", q_enable_expr.clone());
            cb.require_boolean("is_items_count is boolean", is_items_count_expr.clone());
            cb.require_boolean("is_mod_name_len is boolean", is_mod_name_len_expr.clone());
            cb.require_boolean("is_mod_name is boolean", is_mod_name_expr.clone());
            cb.require_boolean("is_import_name_len is boolean", is_import_name_len_expr.clone());
            cb.require_boolean("is_import_name is boolean", is_import_name_expr.clone());
            cb.require_boolean("is_importdesc_type is boolean", is_importdesc_type_expr.clone());
            cb.require_boolean("is_importdesc_val is boolean", is_importdesc_val_expr.clone());

            cb.require_equal(
                "exactly one mark flag active at the same time",
                is_items_count_expr.clone() + is_mod_name_len_expr.clone() + is_mod_name_expr.clone() + is_import_name_len_expr.clone() + is_import_name_expr.clone() + is_importdesc_type_expr.clone() + is_importdesc_val_expr.clone(),
                1.expr(),
            );

            // TODO
            // cb.req(
            //     "is_items_count==1 -> first byte val is not 0",
            //     ,
            //     1.expr(),
            // );

            cb.condition(
                or::expr([
                    is_items_count_expr.clone(),
                    is_mod_name_len_expr.clone(),
                    is_import_name_len_expr.clone(),
                    is_importdesc_val_expr.clone()
                ]),
                |cbc| {
                    cbc.require_equal(
                        "is_items_count || is_mod_name_len || is_import_name_len || is_importdesc_val -> leb128",
                        vc.query_fixed(leb128_chip.config.q_enable, Rotation::cur()),
                        1.expr(),
                    )
                }
            );

            // is_items_count+ -> is_item+ (is_mod_name_len+ -> is_mod_name* -> is_import_name_len+ -> is_import_name* -> is_importdesc_type(1) -> is_importdesc_val+
            // importdesc: (0x0 -> typeidx | 0x1 -> tabletype | 0x2 -> memtype | 0x3 -> globaltype))
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_items_count+ -> is_item+ (is_mod_name_len+ ...",
                is_items_count_expr.clone(),
                true,
                &[is_items_count, is_mod_name_len, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_items_count+ -> is_item+ (is_mod_name_len+ ...",
                is_mod_name_len_expr.clone(),
                false,
                &[is_items_count, is_mod_name_len, is_importdesc_val, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_mod_name_len+ -> is_mod_name* -> is_import_name_len+",
                is_mod_name_len_expr.clone(),
                true,
                &[is_mod_name_len, is_mod_name, is_import_name_len, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_mod_name_len+ -> is_mod_name*",
                is_mod_name_expr.clone(),
                false,
                &[is_mod_name, is_mod_name_len, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_mod_name* -> is_import_name_len+",
                is_mod_name_expr.clone(),
                true,
                &[is_mod_name, is_import_name_len, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_mod_name_len+ -> is_mod_name* -> is_import_name_len+",
                is_import_name_len_expr.clone(),
                false,
                &[is_mod_name_len, is_mod_name, is_import_name_len, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_import_name_len+ -> is_import_name* -> is_importdesc_type(1)",
                is_import_name_len_expr.clone(),
                true,
                &[is_import_name_len, is_import_name, is_importdesc_type, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_import_name_len+ -> is_import_name*",
                is_import_name_expr.clone(),
                false,
                &[is_import_name_len, is_import_name, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_import_name* -> is_importdesc_type(1)",
                is_import_name_expr.clone(),
                true,
                &[is_import_name, is_importdesc_type, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_import_name_len+ -> is_import_name* -> is_importdesc_type(1)",
                is_importdesc_type_expr.clone(),
                false,
                &[is_import_name_len, is_import_name, is_importdesc_type, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_importdesc_type(1) -> is_importdesc_val+",
                is_importdesc_type_expr.clone(),
                true,
                &[is_importdesc_val, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_importdesc_type(1) -> is_importdesc_val+",
                is_importdesc_val_expr.clone(),
                false,
                &[is_importdesc_type, is_importdesc_val, ],
            );

            cb.condition(
                is_importdesc_type_expr.clone(),
                |bcb| {
                    bcb.require_zero(
                        "is_importdesc_type has valid value",
                        // TODO add support for other types
                        byte_value_expr.clone() - (TypeImportDescType as i32).expr(),
                    )
                }
            );

            cb.require_equal(
                "is_mod_name || is_import_name -> utf8",
                or::expr([
                    is_mod_name_expr.clone(),
                    is_import_name_expr.clone(),
                ]),
                utf8_q_enabled_expr.clone(),
            );

            cb.gate(q_enable_expr.clone())
        });

        let config = WasmImportSectionBodyConfig::<F> {
            q_enable,
            is_items_count,
            is_mod_name_len,
            is_mod_name,
            is_import_name_len,
            is_import_name,
            is_importdesc_type,
            is_importdesc_val,
            leb128_chip,
            utf8_chip,
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
                false,
                false,
                0,
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
        is_items_count: bool,
        is_mod_name_len: bool,
        is_mod_name: bool,
        is_import_name_len: bool,
        is_import_name: bool,
        is_importdesc_type: bool,
        is_importdesc_val: bool,
        leb_byte_rel_offset: usize,
        leb_last_byte_rel_offset: usize,
        leb_sn: u64,
        leb_sn_recovered_at_pos: u64,
        byte_val: u8,
    ) {
        if is_items_count || is_mod_name_len || is_import_name_len || is_importdesc_val {
            let is_first_leb_byte = leb_byte_rel_offset == 0;
            let is_last_leb_byte = leb_byte_rel_offset == leb_last_byte_rel_offset;
            let is_leb_byte_has_cb = leb_byte_rel_offset < leb_last_byte_rel_offset;
            self.config.leb128_chip.assign(
                region,
                offset,
                leb_byte_rel_offset,
                true,
                is_first_leb_byte,
                is_last_leb_byte,
                is_leb_byte_has_cb,
                false,
                leb_sn,
                leb_sn_recovered_at_pos,
            );
        }
        if is_mod_name || is_import_name {
            self.config.utf8_chip.assign(
                region,
                offset,
                true,
                byte_val,
            );
        }
        let q_enable = is_items_count || is_mod_name_len || is_mod_name || is_import_name_len || is_import_name || is_importdesc_type || is_importdesc_val;
        region.assign_fixed(
            || format!("assign 'q_enable' val {} at {}", q_enable, offset),
            self.config.q_enable,
            offset,
            || Value::known(F::from(q_enable as u64)),
        ).unwrap();
        region.assign_fixed(
            || format!("assign 'is_items_count' val {} at {}", is_items_count, offset),
            self.config.is_items_count,
            offset,
            || Value::known(F::from(is_items_count as u64)),
        ).unwrap();
        region.assign_fixed(
            || format!("assign 'is_mod_name_len' val {} at {}", is_mod_name_len, offset),
            self.config.is_mod_name_len,
            offset,
            || Value::known(F::from(is_mod_name_len as u64)),
        ).unwrap();
        region.assign_fixed(
            || format!("assign 'is_mod_name' val {} at {}", is_mod_name, offset),
            self.config.is_mod_name,
            offset,
            || Value::known(F::from(is_mod_name as u64)),
        ).unwrap();
        region.assign_fixed(
            || format!("assign 'is_import_name_len' val {} at {}", is_import_name_len, offset),
            self.config.is_import_name_len,
            offset,
            || Value::known(F::from(is_import_name_len as u64)),
        ).unwrap();
        region.assign_fixed(
            || format!("assign 'is_import_name' val {} at {}", is_import_name, offset),
            self.config.is_import_name,
            offset,
            || Value::known(F::from(is_import_name as u64)),
        ).unwrap();
        region.assign_fixed(
            || format!("assign 'is_importdesc_type' val {} at {}", is_importdesc_type, offset),
            self.config.is_importdesc_type,
            offset,
            || Value::known(F::from(is_importdesc_type as u64)),
        ).unwrap();
        region.assign_fixed(
            || format!("assign 'is_importdesc_val' val {} at {}", is_importdesc_val, offset),
            self.config.is_importdesc_val,
            offset,
            || Value::known(F::from(is_importdesc_val as u64)),
        ).unwrap();
    }

    /// returns sn and leb len
    fn markup_leb_section(
        &self,
        region: &mut Region<F>,
        leb_bytes: &[u8],
        leb_bytes_start_offset: usize,
        is_items_count: bool,
        is_mod_name_len: bool,
        is_import_name_len: bool,
        is_importdesc_val: bool,
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
                is_items_count,
                is_mod_name_len,
                false,
                is_import_name_len,
                false,
                false,
                is_importdesc_val,
                byte_offset,
                last_byte_offset,
                leb_sn,
                leb_sn_recovered_at_pos,
                0,
            );
        }

        (leb_sn, last_byte_offset + 1)
    }

    fn markup_name_section(
        &self,
        region: &mut Region<F>,
        offset: usize,
        is_mod_name: bool,
        is_import_name: bool,
        name_len: usize,
        name_bytes: &[u8],
    ) {
        for (rel_offset, byte_offset) in (offset..offset + name_len).enumerate() {
            self.assign(
                region,
                byte_offset,
                false,
                false,
                is_mod_name,
                false,
                is_import_name,
                false,
                false,
                0,
                0,
                0,
                0,
                name_bytes[rel_offset],
            );
        }
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
            false,
        );
        debug!("offset {} items_count {} items_count_leb_len {}", offset, items_count, items_count_leb_len);
        offset += items_count_leb_len;

        for _item_index in 0..items_count {
            let (mod_name_len, mod_name_leb_len) = self.markup_leb_section(
                region,
                &wasm_bytecode.bytes.as_slice()[offset..],
                offset,
                false,
                true,
                false,
                false,
            );
            debug!("offset {} mod_name_len {} mod_name_leb_len {}", offset, mod_name_len, mod_name_leb_len);
            offset += mod_name_leb_len;

            self.markup_name_section(
                region,
                offset,
                true,
                false,
                mod_name_len as usize,
                &wasm_bytecode.bytes.as_slice()[offset..],
            );
            debug!("markup_name_section offset {}", offset);
            offset += mod_name_len as usize;

            let (import_name_len, import_name_leb_len) = self.markup_leb_section(
                region,
                &wasm_bytecode.bytes.as_slice()[offset..],
                offset,
                false,
                false,
                true,
                false,
            );
            debug!("offset {} import_name_len {} import_name_leb_len {}", offset, import_name_len, import_name_leb_len);
            offset += import_name_leb_len;

            self.markup_name_section(
                region,
                offset,
                false,
                true,
                import_name_len as usize,
                &wasm_bytecode.bytes.as_slice()[offset..],
            );
            debug!("markup_name_section offset {}", offset);
            offset += import_name_len as usize;

            self.assign(
                region,
                offset,
                false,
                false,
                false,
                false,
                false,
                true,
                false,
                0,
                0,
                0,
                0,
                wasm_bytecode.bytes.as_slice()[offset],
            );
            debug!("markup importdesc_type offset {}", offset);
            offset += 1;

            let (importdesc_val, importdesc_val_leb_len) = self.markup_leb_section(
                region,
                &wasm_bytecode.bytes.as_slice()[offset..],
                offset,
                false,
                false,
                false,
                true,
            );
            debug!("offset {} importdesc_val {} importdesc_val_leb_len {}", offset, mod_name_len, mod_name_leb_len);
            offset += importdesc_val_leb_len;
        }

        Ok(offset)
    }
}