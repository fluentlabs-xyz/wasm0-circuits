use halo2_proofs::{
    plonk::{Column, ConstraintSystem},
};
use std::{marker::PhantomData};
use std::rc::Rc;
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::plonk::{Expression, Fixed, VirtualCells};
use halo2_proofs::poly::Rotation;
use itertools::Itertools;
use log::debug;
use eth_types::Field;
use gadgets::util::{Expr, not, or};
use crate::evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon};
use crate::wasm_circuit::consts::NumType;
use crate::wasm_circuit::error::Error;
use crate::wasm_circuit::leb128_circuit::circuit::LEB128Chip;
use crate::wasm_circuit::leb128_circuit::helpers::{leb128_compute_sn, leb128_compute_sn_recovered_at_position};
use crate::wasm_circuit::bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::sections::consts::LebParams;
use crate::wasm_circuit::sections::helpers::configure_check_for_transition;
use crate::wasm_circuit::sections::r#type::type_item::consts::Type::FuncType;
use crate::wasm_circuit::sections::r#type::type_item::types::AssignType;

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
                    bcb.require_in_set(
                        "type_section_item input/output type has valid value",
                        byte_value_expr.clone(),
                        vec![
                            (NumType::I32 as i32).expr(),
                            (NumType::I64 as i32).expr(),
                        ]
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
        wasm_bytecode: &WasmBytecode,
        offset: usize,
        assign_type: AssignType,
        assign_value: u64,
        leb_params: Option<LebParams>,
    ) {
        let q_enable = true;
        debug!(
            "type_section_item: assign at offset {} q_enable {} assign_type {:?} assign_value {} byte_val {:x?}",
            offset,
            q_enable,
            assign_type,
            assign_value,
            wasm_bytecode.bytes[offset],
        );
        if [
            AssignType::IsInputCount,
            AssignType::IsOutputCount,
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
            AssignType::IsType => {
                region.assign_fixed(
                    || format!("assign 'is_type' val {} at {}", assign_value, offset),
                    self.config.is_type,
                    offset,
                    || Value::known(F::from(assign_value)),
                ).unwrap();
            }
            AssignType::IsInputCount => {
                region.assign_fixed(
                    || format!("assign 'is_input_count' val {} at {}", assign_value, offset),
                    self.config.is_input_count,
                    offset,
                    || Value::known(F::from(assign_value)),
                ).unwrap();
            }
            AssignType::IsInputType => {
                region.assign_fixed(
                    || format!("assign 'is_input_type' val {} at {}", assign_value, offset),
                    self.config.is_input_type,
                    offset,
                    || Value::known(F::from(assign_value)),
                ).unwrap();
            }
            AssignType::IsOutputCount => {
                region.assign_fixed(
                    || format!("assign 'is_output_count' val {} at {}", assign_value, offset),
                    self.config.is_output_count,
                    offset,
                    || Value::known(F::from(assign_value)),
                ).unwrap();
            }
            AssignType::IsOutputType => {
                region.assign_fixed(
                    || format!("assign 'is_output_type' val {} at {}", assign_value, offset),
                    self.config.is_output_type,
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
        // is_type{1}
        self.assign(
            region,
            wasm_bytecode,
            offset,
            AssignType::IsType,
            1,
            None,
        );
        offset += 1;

        // is_input_count+
        let (input_count, input_count_leb_len) = self.markup_leb_section(
            region,
            wasm_bytecode,
            offset,
            AssignType::IsInputCount,
        );
        offset += input_count_leb_len;

        // is_input_type*
        for byte_offset in offset..(offset + input_count as usize) {
            self.assign(
                region,
                wasm_bytecode,
                byte_offset,
                AssignType::IsInputType,
                1,
                None,
            );
        }
        offset += input_count as usize;

        // is_output_count+
        let (output_count, output_count_leb_len) = self.markup_leb_section(
            region,
            wasm_bytecode,
            offset,
            AssignType::IsOutputCount,
        );
        offset += output_count_leb_len;

        // is_output_type*
        for byte_offset in offset..(offset + output_count as usize) {
            self.assign(
                region,
                wasm_bytecode,
                byte_offset,
                AssignType::IsOutputType,
                1,
                None,
            );
        }
        offset += output_count as usize;

        Ok(offset)
    }
}