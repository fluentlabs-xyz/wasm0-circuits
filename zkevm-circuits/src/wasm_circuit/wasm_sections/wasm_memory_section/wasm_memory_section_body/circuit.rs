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
use crate::wasm_circuit::consts::LimitsType;
use crate::wasm_circuit::error::Error;
use crate::wasm_circuit::leb128_circuit::circuit::LEB128Chip;
use crate::wasm_circuit::leb128_circuit::helpers::{leb128_compute_sn, leb128_compute_sn_recovered_at_position};
use crate::wasm_circuit::wasm_bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::wasm_bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::wasm_sections::helpers::configure_check_for_transition;

#[derive(Debug, Clone)]
pub struct WasmMemorySectionBodyConfig<F: Field> {
    pub q_enable: Column<Fixed>,
    pub is_items_count: Column<Fixed>,
    pub is_limit_type: Column<Fixed>,
    pub is_limit_type_val: Column<Fixed>,

    pub leb128_chip: Rc<LEB128Chip<F>>,

    _marker: PhantomData<F>,
}

impl<'a, F: Field> WasmMemorySectionBodyConfig<F>
{}

#[derive(Debug, Clone)]
pub struct WasmMemorySectionBodyChip<F: Field> {
    pub config: WasmMemorySectionBodyConfig<F>,
    _marker: PhantomData<F>,
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
    ) -> WasmMemorySectionBodyConfig<F> {
        let q_enable = cs.fixed_column();
        let is_items_count = cs.fixed_column();
        let is_limit_type = cs.fixed_column();
        let is_limit_type_val = cs.fixed_column();

        cs.create_gate("WasmMemorySectionBody gate", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
            let is_items_count_expr = vc.query_fixed(is_items_count, Rotation::cur());
            let is_limit_type_expr = vc.query_fixed(is_limit_type, Rotation::cur());
            let is_limit_type_val_expr = vc.query_fixed(is_limit_type_val, Rotation::cur());

            let byte_val_expr = vc.query_advice(bytecode_table.value, Rotation::cur());

            cb.require_boolean("q_enable is boolean", q_enable_expr.clone());
            cb.require_boolean("is_items_count is boolean", is_items_count_expr.clone());
            cb.require_boolean("is_limit_type is boolean", is_limit_type_expr.clone());
            cb.require_boolean("is_limit_type_val is boolean", is_limit_type_val_expr.clone());

            cb.require_equal(
                "exactly one mark flag active at the same time",
                is_items_count_expr.clone() + is_limit_type_expr.clone() + is_limit_type_val_expr.clone(),
                1.expr(),
            );

            cb.condition(
                or::expr([
                    is_items_count_expr.clone(),
                    is_limit_type_val_expr.clone(),
                ]),
                |cbc| {
                    cbc.require_equal(
                        "is_items_count || is_limit_type_val -> leb128",
                        vc.query_fixed(leb128_chip.config.q_enable, Rotation::cur()),
                        1.expr(),
                    )
                }
            );

            // is_items_count+ -> is_limit_type{1} -> is_limit_type_val+
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_items_count+ -> is_limit_type{1}",
                is_items_count_expr.clone(),
                true,
                &[is_items_count, is_limit_type, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_items_count+ -> is_limit_type{1}",
                is_limit_type_expr.clone(),
                false,
                &[is_items_count, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_limit_type{1} -> is_limit_type_val+",
                is_limit_type_expr.clone(),
                true,
                &[is_limit_type_val, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_limit_type{1} -> is_limit_type_val+",
                is_limit_type_val_expr.clone(),
                false,
                &[is_limit_type, is_limit_type_val, ],
            );

            cb.condition(
                is_limit_type_expr.clone(),
                |bcb| {
                    bcb.require_in_set(
                        "is_limit_type -> byte_val has valid value",
                        byte_val_expr.clone(),
                        vec![(LimitsType::MinOnly as i32).expr(), (LimitsType::MinMax as i32).expr()],
                    );
                }
            );

            cb.gate(q_enable_expr.clone())
        });

        let config = WasmMemorySectionBodyConfig::<F> {
            q_enable,
            is_items_count,
            is_limit_type,
            is_limit_type_val,
            leb128_chip,
            _marker: PhantomData,
        };

        config
    }

    // pub fn assign_init(
    //     &self,
    //     region: &mut Region<F>,
    //     offset_max: usize,
    // ) {
    //     for offset in 0..=offset_max {
    //         self.assign(
    //             region,
    //             offset,
    //             false,
    //             false,
    //             false,
    //             0,
    //             0,
    //             0,
    //             0,
    //         );
    //     }
    // }

    pub fn assign(
        &self,
        region: &mut Region<F>,
        offset: usize,
        is_items_count: bool,
        is_limit_type: bool,
        is_limit_type_val: bool,
        leb_byte_rel_offset: usize,
        leb_last_byte_rel_offset: usize,
        leb_sn: u64,
        leb_sn_recovered_at_pos: u64,
    ) {
        let q_enable = is_items_count || is_limit_type || is_limit_type_val;
        debug!("offset {} q_enable {} is_items_count {} is_typeidx {} is_limit_type_val {}", offset, q_enable, is_items_count, is_limit_type, is_limit_type_val);
        if is_items_count || is_limit_type_val {
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
            || format!("assign 'is_limit_type' val {} at {}", is_limit_type, offset),
            self.config.is_limit_type,
            offset,
            || Value::known(F::from(is_limit_type as u64)),
        ).unwrap();
        region.assign_fixed(
            || format!("assign 'is_limit_type_val' val {} at {}", is_limit_type_val, offset),
            self.config.is_limit_type_val,
            offset,
            || Value::known(F::from(is_limit_type_val as u64)),
        ).unwrap();
    }

    /// returns sn and leb len
    fn markup_leb_section(
        &self,
        region: &mut Region<F>,
        leb_bytes: &[u8],
        leb_bytes_start_offset: usize,
        is_items_count: bool,
        is_limit_type_val: bool,
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
                false,
                is_limit_type_val,
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
        );
        debug!("offset {} items_count {} items_count_leb_len {}", offset, items_count, items_count_leb_len);
        offset += items_count_leb_len;

        for _item_index in 0..items_count {
            let limit_type = wasm_bytecode.bytes.as_slice()[offset];
            debug!("offset {} limit_type {}", offset, limit_type);
            self.assign(
                region,
                offset,
                false,
                true,
                false,
                0,
                0,
                0,
                0,
            );
            offset += 1;

            // at least 1 limit exists
            let (min_limit_type_val, min_limit_type_val_leb_len) = self.markup_leb_section(
                region,
                &wasm_bytecode.bytes.as_slice()[offset..],
                offset,
                false,
                true,
            );
            debug!("offset {} min_limit_type_val {} min_limit_type_val_leb_len {}", offset, min_limit_type_val, min_limit_type_val_leb_len);
            offset += min_limit_type_val_leb_len;

            if limit_type == LimitsType::MinMax as u8 {
                let (max_limit_type_val, max_limit_type_val_leb_len) = self.markup_leb_section(
                    region,
                    &wasm_bytecode.bytes.as_slice()[offset..],
                    offset,
                    false,
                    true,
                );
                debug!("offset {} max_limit_type_val {} max_limit_type_val_leb_len {}", offset, max_limit_type_val, max_limit_type_val_leb_len);
                offset += max_limit_type_val_leb_len;
            }
        }

        Ok(offset)
    }
}