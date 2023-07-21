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
use gadgets::binary_number::BinaryNumberChip;
use gadgets::util::{Expr, not, or};

use crate::evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon};
use crate::wasm_circuit::bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::common::WasmChipTrait;
use crate::wasm_circuit::consts::{NUM_TYPE_VALUES, NumType, WASM_BLOCK_END};
use crate::wasm_circuit::consts::NumericInstruction::{I32Const, I64Const};
use crate::wasm_circuit::error::Error;
use crate::wasm_circuit::leb128_circuit::circuit::LEB128Chip;
use crate::wasm_circuit::leb128_circuit::helpers::{leb128_compute_sn, leb128_compute_sn_recovered_at_position};
use crate::wasm_circuit::sections::consts::LebParams;
use crate::wasm_circuit::sections::global::global_body::types::AssignType;
use crate::wasm_circuit::sections::helpers::{configure_constraints_for_q_first_and_q_last, configure_transition_check};
use crate::wasm_circuit::tables::dynamic_indexes::circuit::DynamicIndexesChip;
use crate::wasm_circuit::tables::dynamic_indexes::types::{LookupArgsParams, Tag};
use crate::wasm_circuit::types::SharedState;

#[derive(Debug, Clone)]
pub struct WasmGlobalSectionBodyConfig<F: Field> {
    pub q_enable: Column<Fixed>,
    pub q_first: Column<Fixed>,
    pub q_last: Column<Fixed>,
    pub is_items_count: Column<Fixed>,
    pub is_global_type: Column<Fixed>,
    pub is_global_type_ctx: Column<Fixed>,
    pub is_mut_prop: Column<Fixed>,
    pub is_init_opcode: Column<Fixed>,
    pub is_init_val: Column<Fixed>,
    pub is_expr_delimiter: Column<Fixed>,

    pub global_type: Column<Advice>,

    pub leb128_chip: Rc<LEB128Chip<F>>,
    pub dynamic_indexes_chip: Rc<DynamicIndexesChip<F>>,
    pub global_type_chip: Rc<BinaryNumberChip<F, NumType, 8>>,

    pub func_count: Column<Advice>,

    shared_state: Rc<RefCell<SharedState>>,

    _marker: PhantomData<F>,
}

impl<'a, F: Field> WasmGlobalSectionBodyConfig<F>
{}

#[derive(Debug, Clone)]
pub struct WasmGlobalSectionBodyChip<F: Field> {
    pub config: WasmGlobalSectionBodyConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> WasmChipTrait<F> for WasmGlobalSectionBodyChip<F> {
    fn shared_state(&self) -> Rc<RefCell<SharedState>> {
        self.config.shared_state.clone()
    }

    fn func_count_col(&self) -> Column<Advice> {
        self.config.func_count
    }
}

impl<F: Field> WasmGlobalSectionBodyChip<F>
{
    pub fn construct(config: WasmGlobalSectionBodyConfig<F>) -> Self {
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
        func_count: Column<Advice>,
        shared_state: Rc<RefCell<SharedState>>,
    ) -> WasmGlobalSectionBodyConfig<F> {
        let q_enable = cs.fixed_column();
        let q_first = cs.fixed_column();
        let q_last = cs.fixed_column();
        let is_items_count = cs.fixed_column();
        let is_global_type = cs.fixed_column();
        let is_global_type_ctx = cs.fixed_column();
        let is_mut_prop = cs.fixed_column();
        let is_init_opcode = cs.fixed_column();
        let is_init_val = cs.fixed_column();
        let is_expr_delimiter = cs.fixed_column();

        let global_type = cs.advice_column();
        let config = BinaryNumberChip::configure(cs, is_global_type_ctx, Some(global_type.into()));
        let global_type_chip = Rc::new(BinaryNumberChip::construct(config));

        dynamic_indexes_chip.lookup_args(
            "global section has valid setup for mem indexes",
            cs,
            |vc| {
                LookupArgsParams {
                    cond: vc.query_fixed(is_items_count, Rotation::cur()),
                    index: vc.query_advice(leb128_chip.config.sn, Rotation::cur()),
                    tag: Tag::GlobalIndex.expr(),
                    is_terminator: true.expr(),
                }
            }
        );

        cs.create_gate("WasmGlobalSectionBody gate", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
            let q_first_expr = vc.query_fixed(q_first, Rotation::cur());
            let q_last_expr = vc.query_fixed(q_last, Rotation::cur());
            let not_q_last_expr = not::expr(q_last_expr.clone());
            let is_items_count_expr = vc.query_fixed(is_items_count, Rotation::cur());
            let is_global_type_expr = vc.query_fixed(is_global_type, Rotation::cur());
            let is_global_type_ctx_expr = vc.query_fixed(is_global_type_ctx, Rotation::cur());
            let is_mut_prop_expr = vc.query_fixed(is_mut_prop, Rotation::cur());
            let is_init_opcode_expr = vc.query_fixed(is_init_opcode, Rotation::cur());
            let is_init_val_expr = vc.query_fixed(is_init_val, Rotation::cur());
            let is_expr_delimiter_expr = vc.query_fixed(is_expr_delimiter, Rotation::cur());

            let byte_val_expr = vc.query_advice(bytecode_table.value, Rotation::cur());

            let global_type_expr = vc.query_advice(global_type, Rotation::cur());

            cb.require_boolean("q_enable is boolean", q_enable_expr.clone());
            cb.require_boolean("is_items_count is boolean", is_items_count_expr.clone());
            cb.require_boolean("is_global_type is boolean", is_global_type_expr.clone());
            cb.require_boolean("is_mut_prop is boolean", is_mut_prop_expr.clone());
            cb.require_boolean("is_init_opcode is boolean", is_init_opcode_expr.clone());
            cb.require_boolean("is_init_val is boolean", is_init_val_expr.clone());
            cb.require_boolean("is_expr_delimiter is boolean", is_expr_delimiter_expr.clone());

            configure_constraints_for_q_first_and_q_last(
                &mut cb,
                vc,
                &q_enable,
                &q_first,
                &[is_items_count],
                &q_last,
                &[is_expr_delimiter],
            );

            cb.require_equal(
                "exactly one mark flag active at the same time",
                is_items_count_expr.clone()
                    + is_global_type_expr.clone()
                    + is_mut_prop_expr.clone()
                    + is_init_opcode_expr.clone()
                    + is_init_val_expr.clone()
                    + is_expr_delimiter_expr.clone()
                ,
                1.expr(),
            );

            cb.condition(
                is_global_type_expr.clone(),
                |bcb| {
                    let global_type_expr = vc.query_advice(global_type, Rotation::cur());
                    bcb.require_equal(
                        "is_global_type => global_type=byte_val",
                        global_type_expr,
                        byte_val_expr.clone(),
                    );
                }
            );
            cb.require_equal(
                "is_global_type_ctx active on a specific flags only",
                    is_global_type_expr.clone()
                    + is_mut_prop_expr.clone()
                    + is_init_opcode_expr.clone()
                    + is_init_val_expr.clone()
                ,
                is_global_type_ctx_expr.clone(),
            );
            cb.condition(
                is_global_type_ctx_expr.clone(),
                |bcb| {
                    let is_global_type_ctx_prev_expr = vc.query_fixed(is_global_type_ctx, Rotation::prev());
                    let global_type_prev_expr = vc.query_advice(global_type, Rotation::prev());
                    bcb.require_zero(
                        "is_global_type_ctx && prev.is_global_type_ctx => ",
                        is_global_type_ctx_prev_expr.clone() * (global_type_prev_expr.clone() - global_type_expr.clone()),
                    );
                }
            );

            cb.condition(
                or::expr([
                    is_items_count_expr.clone(),
                    is_init_val_expr.clone(),
                ]),
                |bcb| {
                    bcb.require_equal(
                        "is_items_count || is_init_val -> leb128",
                        vc.query_fixed(leb128_chip.config.q_enable, Rotation::cur()),
                        1.expr(),
                    )
                }
            );

            // is_items_count+ -> item+(is_global_type{1} -> is_mut_prop{1} -> is_init_opcode{1} -> is_init_val+ -> is_expr_delimiter{1})
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_items_count+ -> item+(is_global_type{1} ...",
                is_items_count_expr.clone() * not_q_last_expr.clone(),
                true,
                &[is_items_count, is_global_type, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_global_type{1} -> is_mut_prop{1}",
                is_global_type_expr.clone() * not_q_last_expr.clone(),
                true,
                &[is_mut_prop, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_mut_prop{1} -> is_init_opcode{1}",
                is_mut_prop_expr.clone() * not_q_last_expr.clone(),
                true,
                &[is_init_opcode, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_init_opcode{1} -> is_init_val+",
                is_init_opcode_expr.clone() * not_q_last_expr.clone(),
                true,
                &[is_init_val, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_init_val+ -> is_expr_delimiter{1}",
                is_init_val_expr.clone() * not_q_last_expr.clone(),
                true,
                &[is_init_val, is_expr_delimiter],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_expr_delimiter{1}",
                is_expr_delimiter_expr.clone() * not_q_last_expr.clone(),
                true,
                &[is_global_type],
            );

            cb.condition(
                is_global_type_expr.clone(),
                |bcb| {
                    bcb.require_in_set(
                        "is_global_type has eligible byte value",
                        byte_val_expr.clone(),
                        NUM_TYPE_VALUES.iter().map(|&v| v.expr()).collect_vec(),
                    )
                }
            );

            cb.condition(
                is_mut_prop_expr.clone(),
                |bcb| {
                    bcb.require_boolean(
                        "is_mut_prop -> bool",
                        byte_val_expr.clone(),
                    )
                }
            );

            cb.condition(
                is_init_opcode_expr.clone(),
                |bcb| {
                    bcb.require_in_set(
                        "is_init_opcode has eligible byte value",
                        byte_val_expr.clone(),
                        vec![
                            I32Const.expr(),
                            I64Const.expr(),
                            // add support for float types?
                            // F32Const,
                            // F64Const,
                        ],
                    );
                    let global_type_is_i32_expr = global_type_chip.config.value_equals(NumType::I32, Rotation::cur())(vc);
                    bcb.require_zero(
                        "is_init_opcode && global_type_is_i32 => global type corresponds to init opcode",
                        global_type_is_i32_expr * (NumType::I32.expr() - byte_val_expr.clone() - (NumType::I32 as i32 - I32Const as i32).expr()),
                    );
                    let global_type_is_i64_expr = global_type_chip.config.value_equals(NumType::I64, Rotation::cur())(vc);
                    bcb.require_zero(
                        "is_init_opcode && global_type_is_i64 => global type corresponds to init opcode",
                        global_type_is_i64_expr * (NumType::I64.expr() - byte_val_expr.clone() - (NumType::I64 as i32 - I64Const as i32).expr()),
                    );
                }
            );

            cb.condition(
                is_expr_delimiter_expr.clone(),
                |bcb| {
                    bcb.require_equal(
                        "is_expr_delimiter -> byte value = WASM_BLOCK_END",
                        byte_val_expr.clone(),
                        WASM_BLOCK_END.expr(),
                    )
                }
            );

            cb.gate(q_enable_expr.clone())
        });

        let config = WasmGlobalSectionBodyConfig::<F> {
            q_enable,
            q_first,
            q_last,
            is_items_count,
            is_global_type,
            is_global_type_ctx,
            is_mut_prop,
            is_init_opcode,
            is_init_val,
            is_expr_delimiter,
            global_type,
            leb128_chip,
            dynamic_indexes_chip,
            global_type_chip,
            func_count,
            shared_state,

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
            "global_section_body: assign at offset {} q_enable {} assign_types {:?} assign_values {} byte_val {:x?}",
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
                AssignType::IsItemsCount,
                AssignType::IsInitVal,
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
                AssignType::IsGlobalType => {
                    region.assign_fixed(
                        || format!("assign 'is_global_type' val {} at {}", assign_value, offset),
                        self.config.is_global_type,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsMutProp => {
                    region.assign_fixed(
                        || format!("assign 'is_mut_prop' val {} at {}", assign_value, offset),
                        self.config.is_mut_prop,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsInitOpcode => {
                    region.assign_fixed(
                        || format!("assign 'is_init_opcode' val {} at {}", assign_value, offset),
                        self.config.is_init_opcode,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsInitVal => {
                    region.assign_fixed(
                        || format!("assign 'is_init_val' val {} at {}", assign_value, offset),
                        self.config.is_init_val,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsExprDelimiter => {
                    region.assign_fixed(
                        || format!("assign 'is_expr_delimiter' val {} at {}", assign_value, offset),
                        self.config.is_expr_delimiter,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::GlobalType => {
                    region.assign_advice(
                        || format!("assign 'global_type' val {} at {}", assign_value, offset),
                        self.config.global_type,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                    let global_type: NumType = (assign_value as u8).try_into().unwrap();
                    self.config.global_type_chip.assign(
                        region,
                        offset,
                        &global_type,
                    ).unwrap();
                }
                AssignType::IsGlobalTypeCtx => {
                    region.assign_fixed(
                        || format!("assign 'is_global_type_ctx' val {} at {}", assign_value, offset),
                        self.config.is_global_type_ctx,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
            }
        })
    }

    /// returns sn and leb len
    fn markup_leb_section(
        &self,
        region: &mut Region<F>,
        wasm_bytecode: &WasmBytecode,
        leb_bytes_offset: usize,
        assign_types: &[AssignType],
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
                assign_types,
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
            &[AssignType::IsItemsCount],
        );
        let dynamic_indexes_offset = self.config.dynamic_indexes_chip.assign_auto(
            region,
            self.config.shared_state.borrow().dynamic_indexes_offset,
            items_count as usize,
            Tag::GlobalIndex,
        ).unwrap();
        self.config.shared_state.borrow_mut().dynamic_indexes_offset = dynamic_indexes_offset;
        self.assign(region, &wasm_bytecode, offset, &[AssignType::QFirst], 1, None);
        offset += items_count_leb_len;

        for _item_index in 0..items_count {
            // is_global_type{1}
            let global_type_val = wasm_bytecode.bytes[offset];
            let global_type: NumType = global_type_val.try_into().unwrap();
            let global_type_val = global_type_val as u64;
            self.assign(
                region,
                wasm_bytecode,
                offset,
                &[AssignType::IsGlobalType, AssignType::IsGlobalTypeCtx],
                1,
                None,
            );
            self.assign(region, wasm_bytecode, offset, &[AssignType::GlobalType], global_type_val, None);
            offset += 1;

            // is_mut_prop{1}
            self.assign(
                region,
                wasm_bytecode,
                offset,
                &[AssignType::IsMutProp, AssignType::IsGlobalTypeCtx],
                1,
                None,
            );
            self.assign(region, wasm_bytecode, offset, &[AssignType::GlobalType], global_type_val, None);
            offset += 1;

            // is_init_opcode{1}
            self.assign(
                region,
                wasm_bytecode,
                offset,
                &[AssignType::IsInitOpcode, AssignType::IsGlobalTypeCtx],
                1,
                None,
            );
            self.assign(region, wasm_bytecode, offset, &[AssignType::GlobalType], global_type_val, None);
            offset += 1;

            // is_init_val+
            let (_init_val, init_val_leb_len) = self.markup_leb_section(
                region,
                wasm_bytecode,
                offset,
                &[AssignType::IsInitVal, AssignType::IsGlobalTypeCtx],
            );
            for offset in offset..offset+init_val_leb_len {
                self.assign(region, wasm_bytecode, offset, &[AssignType::GlobalType], global_type_val, None);
            }
            offset += init_val_leb_len;

            // is_expr_delimiter{1}
            self.assign(
                region,
                wasm_bytecode,
                offset,
                &[AssignType::IsExprDelimiter],
                1,
                None,
            );
            offset += 1;
        }

        if offset != offset_start {
            self.assign(region, &wasm_bytecode, offset - 1, &[AssignType::QLast], 1, None);
        }

        Ok(offset)
    }
}