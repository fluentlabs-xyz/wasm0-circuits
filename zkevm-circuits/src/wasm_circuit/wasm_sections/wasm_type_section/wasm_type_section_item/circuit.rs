use halo2_proofs::{
    plonk::{Column, ConstraintSystem},
};
use std::{marker::PhantomData};
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::plonk::{Expression, Fixed, VirtualCells};
use halo2_proofs::poly::Rotation;
use eth_types::Field;
use gadgets::util::{Expr, not, or};
use crate::evm_circuit::util::constraint_builder::BaseConstraintBuilder;
use crate::wasm_circuit::leb128_circuit::circuit::LEB128Chip;
use crate::wasm_circuit::wasm_bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::wasm_sections::wasm_type_section::wasm_type_section_item::consts::Type::FuncType;

///
#[derive(Debug, Clone)]
pub struct WasmTypeSectionItemConfig<F> {
    pub q_enable: Column<Fixed>,
    pub is_type: Column<Fixed>,
    pub is_input_count: Column<Fixed>,
    pub is_input_type: Column<Fixed>,
    pub is_output_count: Column<Fixed>,
    pub is_output_type: Column<Fixed>,
    _marker: PhantomData<F>,
}

///
impl<F: Field> WasmTypeSectionItemConfig<F>
{}

///
#[derive(Debug, Clone)]
pub struct WasmTypeSectionItemChip<F> {
    ///
    pub config: WasmTypeSectionItemConfig<F>,
    ///
    _marker: PhantomData<F>,
}

impl<F: Field> WasmTypeSectionItemChip<F>
{
    ///
    pub fn construct(config: WasmTypeSectionItemConfig<F>) -> Self {
        let instance = Self {
            config,
            _marker: PhantomData,
        };
        instance
    }

    ///
    pub fn configure(
        cs: &mut ConstraintSystem<F>,
        bytecode_table: &WasmBytecodeTable,
        is_leb_byte: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
    ) -> WasmTypeSectionItemConfig<F> {
        let q_enable = cs.fixed_column();
        let is_item_type = cs.fixed_column();
        let is_input_count = cs.fixed_column();
        let is_input_type = cs.fixed_column();
        let is_output_count = cs.fixed_column();
        let is_output_type = cs.fixed_column();

        cs.create_gate("WasmTypeSectionItem gate", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let is_leb_byte_expr = is_leb_byte(vc);

            let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
            let is_item_type_expr = vc.query_fixed(is_item_type, Rotation::cur());
            let is_input_count_expr = vc.query_fixed(is_input_count, Rotation::cur());
            let is_input_type_expr = vc.query_fixed(is_input_type, Rotation::cur());
            let is_output_count_expr = vc.query_fixed(is_output_count, Rotation::cur());
            let is_output_type_expr = vc.query_fixed(is_output_type, Rotation::cur());

            let byte_value_expr = vc.query_advice(bytecode_table.value, Rotation::cur());

            cb.condition(
                is_item_type_expr.clone(),
                |bcb| {
                    byte_value_expr.clone() - (FuncType as i32).expr()
                }
            );

            cb.condition(
                or::expr([
                    is_input_count_expr.clone(),
                    is_output_count_expr.clone(),
                ]),
                |bcb| {
                    not::expr(is_leb_byte_expr.clone())
                }
            );

            // TODO item_type -(1)> input_count -(0..N)> input_type -(1)> output_count -(0..N)> output_type

            cb.gate(q_enable_expr.clone())
        });

        let config = WasmTypeSectionItemConfig {
            q_enable,
            is_type: is_item_type,
            is_input_count,
            is_input_type,
            is_output_count,
            is_output_type,
            _marker: PhantomData,
        };

        config
    }

    ///
    pub fn assign_init(
        &self,
        region: &mut Region<F>,
        offset_max: usize,
        leb128_chip: Option<&LEB128Chip<F>>,
    ) {
        if let Some(leb128_chip) = leb128_chip {
            leb128_chip.assign_init(region, offset_max);
        }
        for offset in 0..=offset_max {
            self.assign(
                region,
                offset,
                0,
                None,
                false,
                false,
                false,
                false,
                false,
                false,
                false,
                0,
                0,
            );
        }
    }

    ///
    pub fn assign(
        &self,
        region: &mut Region<F>,
        offset: usize,
        leb_byte_offset: usize,
        leb128_chip: Option<&LEB128Chip<F>>,
        is_type: bool,
        is_count_first_byte: bool,
        is_count_last_byte: bool,
        is_input_count: bool,
        is_input_type: bool,
        is_output_count: bool,
        is_output_type: bool,
        leb_sn: u64,
        leb_sn_recovered_at_pos: u64,
    ) {
        if is_input_count || is_output_count {
            if let Some(leb128_chip) = leb128_chip {
                leb128_chip.assign(
                    region,
                    offset,
                    leb_byte_offset,
                    true,
                    true,
                    is_count_first_byte,
                    is_count_last_byte,
                    !is_count_last_byte,
                    false,
                    leb_sn,
                    leb_sn_recovered_at_pos,
                );
            }
        }
        let val = is_type || is_input_count || is_input_type || is_output_count || is_output_type;
        region.assign_fixed(
            || format!("assign 'q_enable' val {} at {}", val, offset),
            self.config.q_enable,
            offset,
            || Value::known(F::from(val as u64)),
        ).unwrap();
        region.assign_fixed(
            || format!("assign 'is_item_type' val {} at {}", is_type, offset),
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
}