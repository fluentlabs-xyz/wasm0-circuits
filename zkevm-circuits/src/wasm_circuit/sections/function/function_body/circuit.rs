use std::cell::RefCell;
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
use gadgets::util::{Expr, not, or};

use crate::evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon};
use crate::wasm_circuit::bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::error::Error;
use crate::wasm_circuit::leb128_circuit::circuit::LEB128Chip;
use crate::wasm_circuit::leb128_circuit::helpers::{leb128_compute_sn, leb128_compute_sn_recovered_at_position};
use crate::wasm_circuit::sections::consts::LebParams;
use crate::wasm_circuit::sections::function::function_body::types::AssignType;
use crate::wasm_circuit::sections::helpers::{configure_constraints_for_q_first_and_q_last, configure_transition_check};
use crate::wasm_circuit::types::SharedState;

#[derive(Debug, Clone)]
pub struct WasmFunctionSectionBodyConfig<F: Field> {
    pub q_enable: Column<Fixed>,
    pub q_first: Column<Fixed>,
    pub q_last: Column<Fixed>,
    pub is_items_count: Column<Fixed>,
    pub is_typeidx: Column<Fixed>,

    pub leb128_chip: Rc<LEB128Chip<F>>,

    pub func_count: Column<Advice>,

    shared_state: Rc<RefCell<SharedState>>,

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
        func_count: Column<Advice>,
        shared_state: Rc<RefCell<SharedState>>,
    ) -> WasmFunctionSectionBodyConfig<F> {
        let q_enable = cs.fixed_column();
        let q_first = cs.fixed_column();
        let q_last = cs.fixed_column();
        let is_items_count = cs.fixed_column();
        let is_typeidx = cs.fixed_column();

        cs.create_gate("WasmFunctionSectionBody gate", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
            let q_first_expr = vc.query_fixed(q_first, Rotation::cur());
            let q_last_expr = vc.query_fixed(q_last, Rotation::cur());
            let not_q_last_expr = not::expr(q_last_expr.clone());
            let is_items_count_expr = vc.query_fixed(is_items_count, Rotation::cur());
            let is_typeidx_expr = vc.query_fixed(is_typeidx, Rotation::cur());

            cb.require_boolean("q_enable is boolean", q_enable_expr.clone());
            cb.require_boolean("is_items_count is boolean", is_items_count_expr.clone());
            cb.require_boolean("is_typeidx is boolean", is_typeidx_expr.clone());

            configure_constraints_for_q_first_and_q_last(
                &mut cb,
                vc,
                &q_enable,
                &q_first,
                &[is_items_count],
                &q_last,
                &[is_typeidx],
            );

            cb.require_equal(
                "exactly one mark flag active at the same time",
                is_items_count_expr.clone()
                    + is_typeidx_expr.clone(),
                1.expr(),
            );

            cb.condition(
                or::expr([
                    is_items_count_expr.clone(),
                    is_typeidx_expr.clone(),
                ]),
                |bcb| {
                    bcb.require_equal(
                        "is_items_count || is_typeidx -> leb128",
                        vc.query_fixed(leb128_chip.config.q_enable, Rotation::cur()),
                        1.expr(),
                    )
                }
            );

            // is_items_count+ -> is_typeidx+
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_items_count+ -> is_typeidx+",
                is_items_count_expr.clone() * not_q_last_expr.clone(),
                true,
                &[is_items_count, is_typeidx, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_typeidx+",
                is_typeidx_expr.clone() * not_q_last_expr.clone(),
                true,
                &[is_typeidx, ],
            );

            cb.gate(q_enable_expr.clone())
        });

        let config = WasmFunctionSectionBodyConfig::<F> {
            q_enable,
            q_first,
            q_last,
            is_items_count,
            is_typeidx,
            leb128_chip,
            func_count,
            shared_state,
            _marker: PhantomData,
        };

        config
    }

    pub fn assign_func_count(&self, region: &mut Region<F>, offset: usize) {
        let func_count = self.config.shared_state.borrow().func_count;
        debug!("assign at offset {} func_count val {}", offset, func_count);
        region.assign_advice(
            || format!("assign 'func_count' val {} at {}", func_count, offset),
            self.config.func_count,
            offset,
            || Value::known(F::from(func_count as u64)),
        ).unwrap();
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
            "function_section_body: assign at offset {} q_enable {} assign_type {:?} assign_value {} byte_val {:x?}",
            offset,
            q_enable,
            assign_type,
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

        if [
            AssignType::IsItemsCount,
            AssignType::IsTypeidx,
        ].contains(&assign_type) {
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
            AssignType::IsItemsCount => {
                region.assign_fixed(
                    || format!("assign 'is_items_count' val {} at {}", assign_value, offset),
                    self.config.is_items_count,
                    offset,
                    || Value::known(F::from(assign_value)),
                ).unwrap();
            }
            AssignType::IsTypeidx => {
                region.assign_fixed(
                    || format!("assign 'is_typeidx' val {} at {}", assign_value, offset),
                    self.config.is_typeidx,
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

        let (items_count, items_count_leb_len) = self.markup_leb_section(
            region,
            wasm_bytecode,
            offset,
            AssignType::IsItemsCount,
        );
        self.assign(region, &wasm_bytecode, offset, AssignType::QFirst, 1, None);
        offset += items_count_leb_len;

        for _item_index in 0..items_count {
            let (_typeidx_val, typeidx_val_leb_len) = self.markup_leb_section(
                region,
                wasm_bytecode,
                offset,
                AssignType::IsTypeidx,
            );
            offset += typeidx_val_leb_len;
        }

        if offset != offset_start {
            self.assign(region, &wasm_bytecode, offset - 1, AssignType::QLast, 1, None);
        }

        Ok(offset)
    }
}