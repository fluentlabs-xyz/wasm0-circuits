use std::marker::PhantomData;
use std::rc::Rc;

use halo2_proofs::{
    plonk::{Column, ConstraintSystem},
};
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::plonk::{Advice, Fixed};
use halo2_proofs::poly::Rotation;
use log::debug;

use eth_types::Field;
use gadgets::binary_number::BinaryNumberChip;
use gadgets::util::{Expr, not};

use crate::evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon};
use crate::wasm_circuit::bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::consts::{LimitType, ReferenceType};
use crate::wasm_circuit::error::Error;
use crate::wasm_circuit::leb128_circuit::circuit::LEB128Chip;
use crate::wasm_circuit::leb128_circuit::helpers::{leb128_compute_sn, leb128_compute_sn_recovered_at_position};
use crate::wasm_circuit::sections::consts::LebParams;
use crate::wasm_circuit::sections::helpers::{configure_constraints_for_q_first_and_q_last, configure_transition_check};
use crate::wasm_circuit::sections::table::table_body::types::AssignType;
use crate::wasm_circuit::tables::dynamic_indexes::circuit::DynamicIndexesChip;
use crate::wasm_circuit::tables::dynamic_indexes::types::Tag;
use crate::wasm_circuit::types::SharedState;

#[derive(Debug, Clone)]
pub struct WasmTableSectionBodyConfig<F: Field> {
    pub q_enable: Column<Fixed>,
    pub q_first: Column<Fixed>,
    pub q_last: Column<Fixed>,
    pub is_reference_type_count: Column<Fixed>,
    pub is_reference_type: Column<Fixed>,
    pub is_limit_type: Column<Fixed>,
    pub is_limit_type_ctx: Column<Fixed>,
    pub is_limit_min: Column<Fixed>,
    pub is_limit_max: Column<Fixed>,

    pub leb128_chip: Rc<LEB128Chip<F>>,
    pub limit_type: Column<Advice>,
    pub limit_type_chip: Rc<BinaryNumberChip<F, LimitType, 8>>,
    pub dynamic_indexes_chip: Rc<DynamicIndexesChip<F>>,

    _marker: PhantomData<F>,
}

impl<'a, F: Field> WasmTableSectionBodyConfig<F>
{}

#[derive(Debug, Clone)]
pub struct WasmTableSectionBodyChip<F: Field> {
    pub config: WasmTableSectionBodyConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> WasmTableSectionBodyChip<F>
{
    pub fn construct(config: WasmTableSectionBodyConfig<F>) -> Self {
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
        dynamic_indexes_chip: Rc<DynamicIndexesChip<F>>,
    ) -> WasmTableSectionBodyConfig<F> {
        let q_enable = cs.fixed_column();
        let q_first = cs.fixed_column();
        let q_last = cs.fixed_column();
        let is_reference_type_count = cs.fixed_column();
        let is_reference_type = cs.fixed_column();
        let is_limit_type = cs.fixed_column();
        let is_limit_type_ctx = cs.fixed_column();
        let is_limit_min = cs.fixed_column();
        let is_limit_max = cs.fixed_column();

        let limit_type = cs.advice_column();

        let config = BinaryNumberChip::configure(
            cs,
            is_limit_type_ctx,
            Some(limit_type.into()),
        );
        let limit_type_chip = Rc::new(BinaryNumberChip::construct(config));

        cs.create_gate("WasmTableSectionBody gate", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
            let q_first_expr = vc.query_fixed(q_first, Rotation::cur());
            let q_last_expr = vc.query_fixed(q_last, Rotation::cur());
            let not_q_last_expr = not::expr(q_last_expr.clone());
            let is_reference_type_count_expr = vc.query_fixed(is_reference_type_count, Rotation::cur());
            let is_reference_type_expr = vc.query_fixed(is_reference_type, Rotation::cur());
            let is_limit_type_expr = vc.query_fixed(is_limit_type, Rotation::cur());
            let is_limit_min_expr = vc.query_fixed(is_limit_min, Rotation::cur());
            let is_limit_max_expr = vc.query_fixed(is_limit_max, Rotation::cur());

            let byte_val_expr = vc.query_advice(bytecode_table.value, Rotation::cur());

            let limit_type_is_min_only_expr = limit_type_chip.config.value_equals(LimitType::MinOnly, Rotation::cur())(vc);
            let limit_type_is_min_max_expr = limit_type_chip.config.value_equals(LimitType::MinMax, Rotation::cur())(vc);

            cb.require_boolean("q_enable is boolean", q_enable_expr.clone());
            cb.require_boolean("is_reference_type_count is boolean", is_reference_type_count_expr.clone());
            cb.require_boolean("is_reference_type is boolean", is_reference_type_expr.clone());
            cb.require_boolean("is_limit_type is boolean", is_limit_type_expr.clone());
            cb.require_boolean("is_limit_min is boolean", is_limit_min_expr.clone());
            cb.require_boolean("is_limit_max is boolean", is_limit_max_expr.clone());

            configure_constraints_for_q_first_and_q_last(
                &mut cb,
                vc,
                &q_enable,
                &q_first,
                &[is_reference_type_count],
                &q_last,
                &[is_limit_min, is_limit_max],
            );

            cb.require_equal(
                "exactly one mark flag active at the same time",
                is_reference_type_count_expr.clone()
                    + is_reference_type_expr.clone()
                    + is_limit_type_expr.clone()
                    + is_limit_min_expr.clone()
                    + is_limit_max_expr.clone(),
                1.expr(),
            );

            cb.condition(
                is_reference_type_count_expr.clone()
                    + is_limit_min_expr.clone()
                    + is_limit_max_expr.clone(),
                |bcb| {
                    bcb.require_equal(
                        "reference_type_count || limit_min || limit_max => leb128",
                        vc.query_fixed(leb128_chip.config.q_enable, Rotation::cur()),
                        1.expr(),
                    )
                }
            );

            cb.condition(
                is_reference_type_expr.clone(),
                |bcb| {
                    bcb.require_in_set(
                        "reference_type => byte value is correct",
                        byte_val_expr.clone(),
                        vec![
                            ReferenceType::FuncRef.expr(),
                            ReferenceType::ExternRef.expr(),
                        ],
                    )
                }
            );

            cb.condition(
                is_limit_type_expr.clone(),
                |bcb| {
                    bcb.require_in_set(
                        "limit_type => byte value is correct",
                        byte_val_expr.clone(),
                        vec![
                            LimitType::MinOnly.expr(),
                            LimitType::MinMax.expr(),
                        ],
                    )
                }
            );

            // reference_type_count+ -> reference_type{1} -> limit_type{1} -> limit_min+ -> limit_max*
            configure_transition_check(
                &mut cb,
                vc,
                "check next: reference_type_count+ -> reference_type(1)",
                is_reference_type_count_expr.clone() * not_q_last_expr.clone(),
                true,
                &[is_reference_type_count, is_reference_type, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: reference_type(1) -> limit_type(1)",
                is_reference_type_expr.clone() * not_q_last_expr.clone(),
                true,
                &[is_limit_type, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: limit_type(1) -> limit_min+",
                is_limit_type_expr.clone() * not_q_last_expr.clone(),
                true,
                &[is_limit_min, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: limit_min+",
                is_limit_min_expr.clone() * limit_type_is_min_only_expr.clone() * not_q_last_expr.clone(),
                true,
                &[is_limit_min, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: limit_min+ -> limit_max*",
                is_limit_min_expr.clone() * limit_type_is_min_max_expr.clone() * not_q_last_expr.clone(),
                true,
                &[is_limit_min, is_limit_max ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: limit_max*",
                is_limit_max_expr.clone() * not_q_last_expr.clone(),
                true,
                &[is_limit_max, ],
            );

            cb.gate(q_enable_expr.clone())
        });

        let config = WasmTableSectionBodyConfig::<F> {
            q_enable,
            q_first,
            q_last,
            is_reference_type_count,
            is_reference_type,
            is_limit_type,
            is_limit_type_ctx,
            is_limit_min,
            is_limit_max,
            leb128_chip,
            limit_type,
            limit_type_chip,
            dynamic_indexes_chip,
            _marker: PhantomData,
        };

        config
    }

    pub fn assign(
        &self,
        region: &mut Region<F>,
        wasm_bytecode: &WasmBytecode,
        offset: usize,
        assign_types: &[AssignType],
        assign_value: u64,
        leb_params: Option<LebParams>,
    ) {
        let q_enable = true;
        debug!(
            "table_section_body: assign at offset {} q_enable {} assign_types {:?} assign_value {} byte_val {:x?}",
            offset,
            q_enable,
            assign_types,
            assign_value,
            wasm_bytecode.bytes[offset],
        );
        region.assign_fixed(
            || format!("assign 'q_enable' val {} at {}", q_enable, offset),
            self.config.q_enable,
            offset,
            || Value::known(F::from(q_enable as u64)),
        ).unwrap();
        assign_types.iter().for_each(|assign_type| {
            if [
                AssignType::IsReferenceTypeCount,
                AssignType::IsLimitMin,
                AssignType::IsLimitMax
            ].contains(assign_type) {
                let p = leb_params.unwrap();
                self.config.leb128_chip.assign(
                    region,
                    offset,
                    q_enable,
                    p,
                );
            }
            match assign_type {
                AssignType::QFirst => {
                    region.assign_fixed(
                        || format!("assign 'q_first' val {} at {}", assign_value, offset),
                        self.config.q_first,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::QLast => {
                    region.assign_fixed(
                        || format!("assign 'q_last' val {} at {}", assign_value, offset),
                        self.config.q_last,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsReferenceTypeCount => {
                    region.assign_fixed(
                        || format!("assign 'is_reference_type_count' val {} at {}", assign_value, offset),
                        self.config.is_reference_type_count,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsReferenceType => {
                    region.assign_fixed(
                        || format!("assign 'is_reference_type' val {} at {}", assign_value, offset),
                        self.config.is_reference_type,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsLimitType => {
                    region.assign_fixed(
                        || format!("assign 'is_limit_type' val {} at {}", assign_value, offset),
                        self.config.is_limit_type,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsLimitMin => {
                    region.assign_fixed(
                        || format!("assign 'is_limit_min' val {} at {}", assign_value, offset),
                        self.config.is_limit_min,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsLimitMax => {
                    region.assign_fixed(
                        || format!("assign 'is_limit_max' val {} at {}", assign_value, offset),
                        self.config.is_limit_max,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsLimitTypeCtx => {
                    region.assign_fixed(
                        || format!("assign 'is_limit_type_ctx' val {} at {}", assign_value, offset),
                        self.config.is_limit_type_ctx,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::LimitType => {
                    region.assign_advice(
                        || format!("assign 'limit_type' val {} at {}", assign_value, offset),
                        self.config.limit_type,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                    let limit_type_val = wasm_bytecode.bytes[offset];
                    let limit_type: LimitType = limit_type_val.try_into().unwrap();
                    self.config.limit_type_chip.assign(
                        region,
                        offset,
                        &limit_type,
                    ).unwrap();
                }
            }
        });
    }

    /// returns sn and leb len
    fn markup_leb_section(
        &self,
        region: &mut Region<F>,
        wasm_bytecode: &WasmBytecode,
        leb_bytes_offset: usize,
        assign_type: &[AssignType],
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
        shared_state: &mut SharedState,
    ) -> Result<usize, Error> {
        let mut offset = offset_start;

        // reference_type_count+
        let (_reference_type_count, reference_type_count_leb_len) = self.markup_leb_section(
            region,
            wasm_bytecode,
            offset,
            &[AssignType::IsReferenceTypeCount],
        );
        self.assign(region, &wasm_bytecode, offset, &[AssignType::QFirst], 1, None);
        offset += reference_type_count_leb_len;

        // reference_type{1}
        self.assign(
            region,
            wasm_bytecode,
            offset,
            &[AssignType::IsReferenceType],
            1,
            None,
        );
        shared_state.dynamic_indexes_offset = self.config.dynamic_indexes_chip.assign_auto(
            region,
            shared_state.dynamic_indexes_offset,
            1,
            Tag::TableSectionTableIndex,
        ).unwrap();
        offset += 1;

        // limit_type{1}
        let limit_type_val = wasm_bytecode.bytes[offset];
        let limit_type = limit_type_val.try_into().unwrap();
        self.assign(
            region,
            wasm_bytecode,
            offset,
            &[AssignType::IsLimitType, AssignType::IsLimitTypeCtx],
            1,
            None,
        );
        self.config.limit_type_chip.assign(region, offset, &limit_type).unwrap();
        offset += 1;

        // limit_min+
        let (_limit_min, limit_min_leb_len) = self.markup_leb_section(
            region,
            wasm_bytecode,
            offset,
            &[AssignType::IsLimitMin, AssignType::IsLimitTypeCtx],
        );
        for offset in offset..offset + limit_min_leb_len {
            self.config.limit_type_chip.assign(region, offset, &limit_type).unwrap();
        }
        offset += limit_min_leb_len;

        // limit_max*
        if limit_type_val == LimitType::MinMax as u8 {
            let (_limit_max, limit_max_leb_len) = self.markup_leb_section(
                region,
                wasm_bytecode,
                offset,
                &[AssignType::IsLimitMax, AssignType::IsLimitTypeCtx],
            );
            for offset in offset..offset + limit_max_leb_len {
                self.config.limit_type_chip.assign(region, offset, &limit_type).unwrap();
            }
            offset += limit_max_leb_len;
        }

        if offset != offset_start {
            self.assign(region, &wasm_bytecode, offset - 1, &[AssignType::QLast], 1, None);
        }

        Ok(offset)
    }
}