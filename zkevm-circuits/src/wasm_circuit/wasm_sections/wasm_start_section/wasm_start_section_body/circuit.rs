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
use crate::wasm_circuit::consts::NumericInstruction::I32Const;
use crate::wasm_circuit::consts::{MemSegmentType, WASM_BLOCK_END};
use crate::wasm_circuit::error::Error;
use crate::wasm_circuit::leb128_circuit::circuit::LEB128Chip;
use crate::wasm_circuit::leb128_circuit::helpers::{leb128_compute_sn, leb128_compute_sn_recovered_at_position};
use crate::wasm_circuit::wasm_bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::wasm_bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::wasm_sections::consts::LebParams;
use crate::wasm_circuit::wasm_sections::helpers::configure_check_for_transition;
use crate::wasm_circuit::wasm_sections::wasm_start_section::wasm_start_section_body::types::AssignType;

#[derive(Debug, Clone)]
pub struct WasmStartSectionBodyConfig<F: Field> {
    pub q_enable: Column<Fixed>,
    pub is_func_index: Column<Fixed>,

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

        cs.create_gate("WasmStartSectionBody gate", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
            let is_func_index_expr = vc.query_fixed(is_func_index, Rotation::cur());

            let _byte_val_expr = vc.query_advice(bytecode_table.value, Rotation::cur());

            cb.require_boolean("q_enable is boolean", q_enable_expr.clone());
            cb.require_boolean("is_func_index is boolean", is_func_index_expr.clone());

            cb.require_equal(
                "exactly one mark flag active at the same time",
                is_func_index_expr.clone(),
                1.expr(),
            );

            cb.condition(
                is_func_index_expr.clone(),
                |cbc| {
                    cbc.require_equal(
                        "is_func_index => leb128",
                        vc.query_fixed(leb128_chip.config.q_enable, Rotation::cur()),
                        1.expr(),
                    )
                }
            );

            cb.gate(q_enable_expr.clone())
        });

        let config = WasmStartSectionBodyConfig::<F> {
            q_enable,
            is_func_index,
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
        assign_value: bool,
        leb_params: Option<LebParams>,
    ) {
        let q_enable = true;
        debug!(
            "offset {} q_enable {} assign_type {:?}",
            offset,
            q_enable,
            assign_type,
        );
        if assign_type == AssignType::FuncsIndex {
            let leb_params = leb_params.unwrap();
            let is_first_leb_byte = leb_params.byte_rel_offset == 0;
            let is_last_leb_byte = leb_params.byte_rel_offset == leb_params.last_byte_rel_offset;
            let is_leb_byte_has_cb = leb_params.byte_rel_offset < leb_params.last_byte_rel_offset;
            self.config.leb128_chip.assign(
                region,
                offset,
                leb_params.byte_rel_offset,
                q_enable,
                is_first_leb_byte,
                is_last_leb_byte,
                is_leb_byte_has_cb,
                false,
                leb_params.sn,
                leb_params.sn_recovered_at_pos,
            );
        }
        region.assign_fixed(
            || format!("assign 'q_enable' val {} at {}", q_enable, offset),
            self.config.q_enable,
            offset,
            || Value::known(F::from(q_enable as u64)),
        ).unwrap();
        match assign_type {
            AssignType::Unknown => {
                panic!("unknown assign type")
            }
            AssignType::FuncsIndex => {
                region.assign_fixed(
                    || format!("assign 'is_func_index' val {} at {}", assign_value, offset),
                    self.config.is_func_index,
                    offset,
                    || Value::known(F::from(assign_value as u64)),
                ).unwrap();
            }
        }
    }

    /// returns sn and leb len
    fn markup_leb_section(
        &self,
        region: &mut Region<F>,
        bytecode: &WasmBytecode,
        leb_bytes_start_offset: usize,
        assign_type: AssignType,
        assign_value: bool,
    ) -> (u64, usize) {
        const OFFSET: usize = 0;
        let (sn, last_byte_rel_offset) = leb128_compute_sn(&bytecode.bytes[leb_bytes_start_offset..], false, OFFSET).unwrap();
        let mut sn_recovered_at_pos = 0;
        for byte_rel_offset in OFFSET..=last_byte_rel_offset {
            let offset = leb_bytes_start_offset + byte_rel_offset;
            sn_recovered_at_pos = leb128_compute_sn_recovered_at_position(
                sn_recovered_at_pos,
                false,
                byte_rel_offset,
                last_byte_rel_offset,
                bytecode.bytes[offset],
            );
            self.assign(
                region,
                offset,
                assign_type,
                assign_value,
                Some(LebParams {
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
            AssignType::FuncsIndex,
            true,
        );
        offset += funcs_index_leb_len;

        Ok(offset)
    }
}