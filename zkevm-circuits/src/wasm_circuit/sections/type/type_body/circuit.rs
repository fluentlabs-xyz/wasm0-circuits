use std::cell::RefCell;
use std::marker::PhantomData;
use std::rc::Rc;

use halo2_proofs::{
    plonk::{Column, ConstraintSystem},
};
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::plonk::{Advice, Fixed};
use halo2_proofs::poly::Rotation;
use itertools::Itertools;
use log::debug;

use eth_types::Field;
use gadgets::util::not;

use crate::evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon};
use crate::wasm_circuit::bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::common::{WasmAssignAwareChipV1, WasmFuncCountAwareChip, WasmLeb128AwareChipV1, WasmSharedStateAwareChip};
use crate::wasm_circuit::error::Error;
use crate::wasm_circuit::leb128_circuit::circuit::LEB128Chip;
use crate::wasm_circuit::sections::consts::LebParams;
use crate::wasm_circuit::sections::helpers::{configure_constraints_for_q_first_and_q_last, configure_transition_check};
use crate::wasm_circuit::sections::r#type::type_body::types::AssignType;
use crate::wasm_circuit::sections::r#type::type_item::circuit::WasmTypeSectionItemChip;
use crate::wasm_circuit::tables::dynamic_indexes::circuit::DynamicIndexesChip;
use crate::wasm_circuit::tables::dynamic_indexes::types::Tag;
use crate::wasm_circuit::types::SharedState;

#[derive(Debug, Clone)]
pub struct WasmTypeSectionBodyConfig<F> {
    pub q_enable: Column<Fixed>,
    pub q_first: Column<Fixed>,
    pub q_last: Column<Fixed>,
    pub is_items_count: Column<Fixed>,
    pub is_body: Column<Fixed>,

    pub func_count: Column<Advice>,

    pub wasm_type_section_item_chip: Rc<WasmTypeSectionItemChip<F>>,
    pub leb128_chip: Rc<LEB128Chip<F>>,
    pub dynamic_indexes_chip: Rc<DynamicIndexesChip<F>>,

    shared_state: Rc<RefCell<SharedState>>,

    _marker: PhantomData<F>,
}

impl<'a, F: Field> WasmTypeSectionBodyConfig<F>
{}

#[derive(Debug, Clone)]
pub struct WasmTypeSectionBodyChip<F> {
    pub config: WasmTypeSectionBodyConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> WasmAssignAwareChipV1<F> for WasmTypeSectionBodyChip<F> {
    type AssignType = AssignType;

    fn assign(
        &self,
        region: &mut Region<F>,
        wasm_bytecode: &WasmBytecode,
        offset: usize,
        assign_types: &[Self::AssignType],
        assign_value: u64,
        leb_params: Option<LebParams>,
    ) {
        let q_enable = true;
        debug!(
            "assign at offset {} q_enable {} assign_types {:?} assign_value {} byte_val {:x?}",
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
        self.assign_func_count(region, offset);

        assign_types.iter().for_each(|assign_type| {
            if [
                AssignType::IsBodyItemsCount,
            ].contains(&assign_type) {
                let p = leb_params.unwrap();
                self.config.leb128_chip.assign(
                    region,
                    offset,
                    true,
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
                AssignType::IsBodyItemsCount => {
                    region.assign_fixed(
                        || format!("assign 'is_items_count' val {} at {}", assign_value, offset),
                        self.config.is_items_count,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsBody => {
                    region.assign_fixed(
                        || format!("assign 'is_body' val {} at {}", assign_value, offset),
                        self.config.is_body,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
            }
        })
    }
}

impl<F: Field> WasmLeb128AwareChipV1<F> for WasmTypeSectionBodyChip<F> {}

impl<F: Field> WasmSharedStateAwareChip<F> for WasmTypeSectionBodyChip<F> {
    fn shared_state(&self) -> Rc<RefCell<SharedState>> { self.config.shared_state.clone() }
}

impl<F: Field> WasmFuncCountAwareChip<F> for WasmTypeSectionBodyChip<F> {
    fn func_count_col(&self) -> Column<Advice> { self.config.func_count }
}

impl<F: Field> WasmTypeSectionBodyChip<F>
{
    pub fn construct(config: WasmTypeSectionBodyConfig<F>) -> Self {
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
        wasm_type_section_item_chip: Rc<WasmTypeSectionItemChip<F>>,
        dynamic_indexes_chip: Rc<DynamicIndexesChip<F>>,
        func_count: Column<Advice>,
        shared_state: Rc<RefCell<SharedState>>,
    ) -> WasmTypeSectionBodyConfig<F> {
        let q_enable = cs.fixed_column();
        let q_first = cs.fixed_column();
        let q_last = cs.fixed_column();
        let is_items_count = cs.fixed_column();
        let is_body = cs.fixed_column();

        cs.create_gate("WasmTypeSectionBody gate", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
            let q_first_expr = vc.query_fixed(q_first, Rotation::cur());
            let q_last_expr = vc.query_fixed(q_last, Rotation::cur());
            let not_q_last_expr = not::expr(q_last_expr.clone());
            let is_items_count_expr = vc.query_fixed(is_items_count, Rotation::cur());
            let is_body_expr = vc.query_fixed(is_body, Rotation::cur());

            let byte_value_expr = vc.query_advice(bytecode_table.value, Rotation::cur());

            cb.require_boolean("q_enable is boolean", q_enable_expr.clone());
            cb.require_boolean("is_items_count is boolean", is_items_count_expr.clone());
            cb.require_boolean("is_body is boolean", is_body_expr.clone());

            configure_constraints_for_q_first_and_q_last(
                &mut cb,
                vc,
                &q_enable,
                &q_first,
                &[is_items_count],
                &q_last,
                &[is_body],
            );

            cb.condition(
                is_items_count_expr.clone(),
                |bcb| {
                    bcb.require_zero(
                        "is_items_count -> leb128",
                        not::expr(vc.query_fixed(leb128_chip.config.q_enable, Rotation::cur()))
                    );
                }
            );
            cb.require_equal(
                "is_body_expr <-> wasm_type_section_item",
                is_body_expr.clone(),
                vc.query_fixed(wasm_type_section_item_chip.config.q_enable, Rotation::cur()),
            );

            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_items_count+ -> is_body+",
                is_items_count_expr.clone() * not_q_last_expr.clone(),
                true,
                &[is_items_count, is_body],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_body+",
                is_body_expr.clone() * not_q_last_expr.clone(),
                true,
                &[is_body, ],
            );

            cb.gate(q_enable_expr.clone())
        });

        let config = WasmTypeSectionBodyConfig::<F> {
            q_enable,
            q_first,
            q_last,
            is_items_count,
            is_body,
            leb128_chip,
            wasm_type_section_item_chip,
            dynamic_indexes_chip,
            func_count,
            shared_state,

            _marker: PhantomData,
        };

        config
    }

    /// updates `shared_state.dynamic_indexes_offset` to a new offset
    ///
    /// returns new offset
    pub fn assign_auto(
        &self,
        region: &mut Region<F>,
        wasm_bytecode: &WasmBytecode,
        offset_start: usize,
    ) -> Result<usize, Error> {
        let mut offset = offset_start;
        let (body_items_count, body_items_count_leb_len) = self.markup_leb_section(
            region,
            wasm_bytecode,
            offset,
            &[AssignType::IsBodyItemsCount],
        );
        self.assign(region, &wasm_bytecode, offset, &[AssignType::QFirst], 1, None);
        offset += body_items_count_leb_len;

        let dynamic_indexes_offset = self.config.dynamic_indexes_chip.assign_auto(
            region,
            self.config.shared_state.borrow().dynamic_indexes_offset,
            body_items_count as usize,
            Tag::TypeIndex,
        ).unwrap();
        self.config.shared_state.borrow_mut().dynamic_indexes_offset = dynamic_indexes_offset;

        for _body_item_index in 0..body_items_count {
            let next_body_item_offset = self.config.wasm_type_section_item_chip.assign_auto(
                region,
                wasm_bytecode,
                offset,
            )?;
            for offset in offset..next_body_item_offset {
                self.assign(
                    region,
                    wasm_bytecode,
                    offset,
                    &[AssignType::IsBody],
                    1,
                    None,
                );
            }
            offset = next_body_item_offset;
        }

        if offset != offset_start {
            self.assign(region, &wasm_bytecode, offset - 1, &[AssignType::QLast], 1, None);
        }

        Ok(offset)
    }
}