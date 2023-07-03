use halo2_proofs::{
    plonk::{Column, ConstraintSystem},
};
use std::{marker::PhantomData};
use std::rc::Rc;
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
use crate::wasm_circuit::wasm_sections::consts::LebParams;
use crate::wasm_circuit::wasm_sections::helpers::configure_check_for_transition;

#[derive(Debug, Clone)]
pub struct WasmFunctionSectionBodyConfig<F: Field> {
    pub q_enable: Column<Fixed>,
    pub is_items_count: Column<Fixed>,
    pub is_typeidx: Column<Fixed>,

    pub leb128_chip: Rc<LEB128Chip<F>>,

    _marker: PhantomData<F>,
}

impl<'a, F: Field> WasmFunctionSectionBodyConfig<F>
{}

#[derive(Debug, Clone)]
pub struct WasmFunctionSectionBodyChip<F: Field> {
    pub config: WasmFunctionSectionBodyConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> WasmFunctionSectionBodyChip<F>
{
    pub fn construct(config: WasmFunctionSectionBodyConfig<F>) -> Self {
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
    ) -> WasmFunctionSectionBodyConfig<F> {
        let q_enable = cs.fixed_column();
        let is_items_count = cs.fixed_column();
        let is_typeidx = cs.fixed_column();

        cs.create_gate("WasmFunctionSectionBody gate", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
            let is_items_count_expr = vc.query_fixed(is_items_count, Rotation::cur());
            let is_typeidx_expr = vc.query_fixed(is_typeidx, Rotation::cur());

            cb.require_boolean("q_enable is boolean", q_enable_expr.clone());
            cb.require_boolean("is_items_count is boolean", is_items_count_expr.clone());
            cb.require_boolean("is_typeidx is boolean", is_typeidx_expr.clone());

            cb.require_equal(
                "exactly one mark flag active at the same time",
                is_items_count_expr.clone() + is_typeidx_expr.clone(),
                1.expr(),
            );

            cb.condition(
                or::expr([
                    is_items_count_expr.clone(),
                    is_typeidx_expr.clone(),
                ]),
                |cbc| {
                    cbc.require_equal(
                        "is_items_count || is_typeidx -> leb128",
                        vc.query_fixed(leb128_chip.config.q_enable, Rotation::cur()),
                        1.expr(),
                    )
                }
            );

            // is_items_count+ -> is_typeidx+
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_items_count+ -> is_typeidx+",
                is_items_count_expr.clone(),
                true,
                &[is_items_count, is_typeidx, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_items_count+ -> is_typeidx+",
                is_typeidx_expr.clone(),
                false,
                &[is_items_count, is_typeidx, ],
            );

            cb.gate(q_enable_expr.clone())
        });

        let config = WasmFunctionSectionBodyConfig::<F> {
            q_enable,
            is_items_count,
            is_typeidx,
            leb128_chip,
            _marker: PhantomData,
        };

        config
    }

    pub fn assign(
        &self,
        region: &mut Region<F>,
        offset: usize,
        is_items_count: bool,
        is_typeidx: bool,
        leb_params: Option<LebParams>,
    ) {
        let q_enable = true;
        debug!("assign at offset {} q_enable {} is_items_count {} is_typeidx {}", offset, q_enable, is_items_count, is_typeidx);
        if is_items_count || is_typeidx {
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
        region.assign_fixed(
            || format!("assign 'is_items_count' val {} at {}", is_items_count, offset),
            self.config.is_items_count,
            offset,
            || Value::known(F::from(is_items_count as u64)),
        ).unwrap();
        region.assign_fixed(
            || format!("assign 'is_typeidx' val {} at {}", is_typeidx, offset),
            self.config.is_typeidx,
            offset,
            || Value::known(F::from(is_typeidx as u64)),
        ).unwrap();
    }

    /// returns sn and leb len
    fn markup_leb_section(
        &self,
        region: &mut Region<F>,
        leb_bytes: &[u8],
        leb_bytes_start_offset: usize,
        is_items_count: bool,
        is_typeidx: bool,
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
                is_items_count,
                is_typeidx,
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
            let (typeidx_val, typeidx_val_leb_len) = self.markup_leb_section(
                region,
                &wasm_bytecode.bytes.as_slice()[offset..],
                offset,
                false,
                true,
            );
            debug!("offset {} typeidx_val {} typeidx_val_leb_len {}", offset, typeidx_val, typeidx_val_leb_len);
            offset += typeidx_val_leb_len;
        }

        Ok(offset)
    }
}