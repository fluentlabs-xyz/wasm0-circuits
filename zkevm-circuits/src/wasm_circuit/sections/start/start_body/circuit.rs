use std::marker::PhantomData;
use std::rc::Rc;
use halo2_proofs::{
    plonk::{Column, ConstraintSystem},
};
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::plonk::Fixed;
use halo2_proofs::poly::Rotation;
use log::debug;
use eth_types::Field;
use gadgets::util::{and, Expr};
use crate::evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon};
use crate::wasm_circuit::bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::error::Error;
use crate::wasm_circuit::leb128_circuit::circuit::LEB128Chip;
use crate::wasm_circuit::leb128_circuit::helpers::{leb128_compute_sn, leb128_compute_sn_recovered_at_position};
use crate::wasm_circuit::sections::consts::LebParams;
use crate::wasm_circuit::sections::start::start_body::types::AssignType;

#[derive(Debug, Clone)]
pub struct WasmStartSectionBodyConfig<F: Field> {
    pub q_enable: Column<Fixed>,
    pub is_func_index: Column<Fixed>,

    pub bytecode_table: Rc<WasmBytecodeTable>,
    pub leb128_chip: Rc<LEB128Chip<F>>,

    _marker: PhantomData<F>,
}

impl<'a, F: Field> WasmStartSectionBodyConfig<F>
{}

#[derive(Debug, Clone)]
pub struct WasmStartSectionBodyChip<F: Field> {
    pub config: WasmStartSectionBodyConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> WasmStartSectionBodyChip<F>
{
    pub fn construct(config: WasmStartSectionBodyConfig<F>) -> Self {
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
    ) -> WasmStartSectionBodyConfig<F> {
        let q_enable = cs.fixed_column();
        let is_func_index = cs.fixed_column();

        let config = WasmStartSectionBodyConfig::<F> {
            q_enable,
            is_func_index,
            bytecode_table,
            leb128_chip,
            _marker: PhantomData,
        };
        cs.create_gate("WasmStartSectionBody gate", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = vc.query_fixed(config.q_enable, Rotation::cur());
            let is_func_index_expr = vc.query_fixed(config.is_func_index, Rotation::cur());
            let is_func_index_prev_expr = vc.query_fixed(config.is_func_index, Rotation::prev());

            let _byte_val_expr = vc.query_advice(config.bytecode_table.value, Rotation::cur());

            let leb128_q_enable_expr = vc.query_fixed(config.leb128_chip.config.q_enable, Rotation::cur());
            let leb128_is_first_leb_byte_expr = vc.query_fixed(config.leb128_chip.config.is_first_leb_byte, Rotation::cur());

            cb.require_boolean("q_enable is boolean", q_enable_expr.clone());
            cb.require_boolean("is_func_index is boolean", is_func_index_expr.clone());

            cb.require_equal(
                "exactly one mark flag active at the same time",
                is_func_index_expr.clone(),
                1.expr(),
            );

            cb.condition(
                is_func_index_expr.clone(),
                |bcb| {
                    bcb.require_equal(
                        "is_func_index => leb128",
                        leb128_q_enable_expr.clone(),
                        1.expr(),
                    )
                }
            );
            cb.condition(
                and::expr([
                    is_func_index_expr.clone(),
                    leb128_is_first_leb_byte_expr.clone(),
                    is_func_index_prev_expr.clone(),
                ]),
                |bcb| {
                    let leb128_q_enable_prev_expr = vc.query_fixed(config.leb128_chip.config.q_enable, Rotation::prev());
                    bcb.require_equal(
                        "exactly one leb arg in a row is allowed",
                        leb128_q_enable_prev_expr,
                        0.expr(),
                    )
                }
            );

            cb.gate(q_enable_expr.clone())
        });

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
            "start_section_body: assign at offset {} q_enable {} assign_type {:?} assign_value {} byte_val {:x?}",
            offset,
            q_enable,
            assign_type,
            assign_value,
            wasm_bytecode.bytes[offset],
        );
        if assign_type == AssignType::IsFuncsIndex {
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
            AssignType::IsFuncsIndex => {
                region.assign_fixed(
                    || format!("assign 'is_func_index' val {} at {}", assign_value, offset),
                    self.config.is_func_index,
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

        let (_funcs_index, funcs_index_leb_len) = self.markup_leb_section(
            region,
            &wasm_bytecode,
            offset,
            AssignType::IsFuncsIndex,
        );
        offset += funcs_index_leb_len;

        Ok(offset)
    }
}