use halo2_proofs::{
    plonk::{Column, ConstraintSystem},
};
use std::{marker::PhantomData};
use std::rc::Rc;
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::plonk::{Expression, Fixed, VirtualCells};
use halo2_proofs::poly::Rotation;
use eth_types::Field;
use gadgets::util::{Expr, not, or};
use crate::evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon};
use crate::wasm_circuit::consts::NumType;
use crate::wasm_circuit::error::Error;
use crate::wasm_circuit::leb128_circuit::circuit::LEB128Chip;
use crate::wasm_circuit::leb128_circuit::helpers::{leb128_compute_sn, leb128_compute_sn_recovered_at_position};
use crate::wasm_circuit::wasm_bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::wasm_bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::wasm_sections::helpers::configure_check_for_transition;
use crate::wasm_circuit::wasm_sections::wasm_type_section::wasm_type_section_item::consts::Type::FuncType;

#[derive(Debug, Clone)]
pub struct WasmTypeSectionItemConfig<F> {
    pub q_enable: Column<Fixed>,
    pub is_type: Column<Fixed>,
    pub is_input_count: Column<Fixed>,
    pub is_input_type: Column<Fixed>,
    pub is_output_count: Column<Fixed>,
    pub is_output_type: Column<Fixed>,

    pub leb128_chip: Rc<LEB128Chip<F>>,

    _marker: PhantomData<F>,
}

impl<'a, F: Field> WasmTypeSectionItemConfig<F>
{}

#[derive(Debug, Clone)]
pub struct WasmTypeSectionItemChip<F> {
    pub config: WasmTypeSectionItemConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> WasmTypeSectionItemChip<F>
{
    pub fn construct(config: WasmTypeSectionItemConfig<F>) -> Self {
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
    ) -> WasmTypeSectionItemConfig<F> {
        let q_enable = cs.fixed_column();
        let is_type = cs.fixed_column();
        let is_input_count = cs.fixed_column();
        let is_input_type = cs.fixed_column();
        let is_output_count = cs.fixed_column();
        let is_output_type = cs.fixed_column();

        cs.create_gate("WasmTypeSectionItem gate", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
            let is_type_expr = vc.query_fixed(is_type, Rotation::cur());
            let is_input_count_expr = vc.query_fixed(is_input_count, Rotation::cur());
            let is_input_type_expr = vc.query_fixed(is_input_type, Rotation::cur());
            let is_output_count_expr = vc.query_fixed(is_output_count, Rotation::cur());
            let is_output_type_expr = vc.query_fixed(is_output_type, Rotation::cur());

            let byte_value_expr = vc.query_advice(bytecode_table.value, Rotation::cur());

            cb.require_boolean("q_enable is boolean", q_enable_expr.clone());
            cb.require_boolean("is_type is boolean", is_type_expr.clone());
            cb.require_boolean("is_input_count is boolean", is_input_count_expr.clone());
            cb.require_boolean("is_input_type is boolean", is_input_type_expr.clone());
            cb.require_boolean("is_output_count is boolean", is_output_count_expr.clone());
            cb.require_boolean("is_output_type is boolean", is_output_type_expr.clone());

            cb.condition(
                is_type_expr.clone(),
                |bcb| {
                    bcb.require_equal(
                        "type_section_item type has valid value",
                        byte_value_expr.clone(),
                        (FuncType as i32).expr()
                    )
                }
            );

            cb.condition(
                or::expr([
                    is_input_type_expr.clone(),
                    is_output_type_expr.clone(),
                ]),
                |bcb| {
                    bcb.require_zero(
                        "type_section_item input/output type has valid value",
                        // TODO replace with lookup
                        (byte_value_expr.clone() - (NumType::I32 as i32).expr()) * (byte_value_expr.clone() - (NumType::I64 as i32).expr())
                    )
                }
            );

            cb.condition(
                or::expr([
                    is_input_count_expr.clone(),
                    is_output_count_expr.clone(),
                ]),
                |bcb| {
                    bcb.require_zero(
                        "is_input/output_count -> leb128",
                        not::expr(vc.query_fixed(leb128_chip.config.q_enable.clone(), Rotation::cur())),
                    )
                }
            );

            cb.require_equal(
                "exactly one mark flag active at the same time",
                is_type_expr.clone() + is_input_count_expr.clone() + is_input_type_expr.clone() + is_output_count_expr.clone() + is_output_type_expr.clone(),
                1.expr(),
            );

            // is_type{1} -> is_input_count+ -> is_input_type* -> is_output_count+ -> is_output_type*
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_type{1} -> is_input_count+",
                is_type_expr.clone(),
                true,
                &[is_input_count, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_type{1} -> is_input_count+",
                is_input_count_expr.clone(),
                false,
                &[is_type, is_input_count, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_input_count+ -> is_input_type* -> is_output_count+",
                is_input_count_expr.clone(),
                true,
                &[is_input_count, is_input_type, is_output_count, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_input_count+ -> is_input_type*",
                is_input_type_expr.clone(),
                false,
                &[is_input_count, is_input_type, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_input_type* -> is_output_count+",
                is_input_type_expr.clone(),
                true,
                &[is_input_type, is_output_count, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_input_count+ -> is_input_type* -> is_output_count+",
                is_output_count_expr.clone(),
                false,
                &[is_input_count, is_input_type, is_output_count, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_output_count+ -> is_output_type*",
                is_output_type_expr.clone(),
                false,
                &[is_output_count, is_output_type, ],
            );

            // TODO add constraints

            cb.gate(q_enable_expr.clone())
        });

        let config = WasmTypeSectionItemConfig::<F> {
            q_enable,
            is_type,
            is_input_count,
            is_input_type,
            is_output_count,
            is_output_type,
            leb128_chip,
            _marker: PhantomData,
        };

        config
    }

    pub fn assign(
        &self,
        region: &mut Region<F>,
        offset: usize,
        is_type: bool,
        is_input_count: bool,
        is_input_type: bool,
        is_output_count: bool,
        is_output_type: bool,
        leb_byte_rel_offset: usize,
        leb_last_byte_rel_offset: usize,
        leb_sn: u64,
        leb_sn_recovered_at_pos: u64,
    ) {
        if is_input_count || is_output_count {
            self.config.leb128_chip.assign(
                region,
                offset,
                leb_byte_rel_offset,
                true,
                leb_byte_rel_offset == 0,
                leb_byte_rel_offset == leb_last_byte_rel_offset,
                leb_byte_rel_offset < leb_last_byte_rel_offset,
                false,
                leb_sn,
                leb_sn_recovered_at_pos,
            );
        }
        let val = is_type || is_input_count || is_input_type || is_output_count || is_output_type;
        region.assign_fixed(
            || format!("assign 'q_enable' val {} at {}", val, offset),
            self.config.q_enable,
            offset,
            || Value::known(F::from(val as u64)),
        ).unwrap();
        region.assign_fixed(
            || format!("assign 'is_type' val {} at {}", is_type, offset),
            self.config.is_type,
            offset,
            || Value::known(F::from(is_type as u64)),
        ).unwrap();
        region.assign_fixed(
            || format!("assign 'is_input_count' val {} at {}", is_input_count, offset),
            self.config.is_input_count,
            offset,
            || Value::known(F::from(is_input_count as u64)),
        ).unwrap();
        region.assign_fixed(
            || format!("assign 'is_input_type' val {} at {}", is_input_type, offset),
            self.config.is_input_type,
            offset,
            || Value::known(F::from(is_input_type as u64)),
        ).unwrap();
        region.assign_fixed(
            || format!("assign 'is_output_count' val {} at {}", is_output_count, offset),
            self.config.is_output_count,
            offset,
            || Value::known(F::from(is_output_count as u64)),
        ).unwrap();
        region.assign_fixed(
            || format!("assign 'is_output_type' val {} at {}", is_output_type, offset),
            self.config.is_output_type,
            offset,
            || Value::known(F::from(is_output_type as u64)),
        ).unwrap();
    }

    /// returns sn and leb len
    fn markup_leb_section(
        &self,
        region: &mut Region<F>,
        leb_bytes: &[u8],
        leb_bytes_start_offset: usize,
        is_input_count: bool,
        is_output_count: bool,
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
                leb_bytes[OFFSET],
            );
            self.assign(
                region,
                leb_bytes_start_offset + byte_offset,
                false,
                is_input_count,
                false,
                is_output_count,
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
        self.assign(
            region,
            offset,
            true,
            false,
            false,
            false,
            false,
            0,
            0,
            0,
            0,
        );
        offset += 1;

        let (input_count_sn, input_count_leb_len) = self.markup_leb_section(
            region,
            &wasm_bytecode.bytes[offset..],
            offset,
            true,
            false,
        );
        offset += input_count_leb_len;

        for byte_offset in offset..(offset + input_count_sn as usize) {
            self.assign(
                region,
                byte_offset,
                false,
                false,
                true,
                false,
                false,
                0,
                0,
                0,
                0,
            );
        }
        offset += input_count_sn as usize;

        let (output_count_sn, output_count_leb_len) = self.markup_leb_section(
            region,
            &wasm_bytecode.bytes[offset..],
            offset,
            false,
            true,
        );
        offset += output_count_leb_len;

        for byte_offset in offset..(offset + output_count_sn as usize) {
            self.assign(
                region,
                byte_offset,
                false,
                false,
                false,
                false,
                true,
                0,
                0,
                0,
                0,
            );
        }
        offset += output_count_sn as usize;

        Ok(offset)
    }
}