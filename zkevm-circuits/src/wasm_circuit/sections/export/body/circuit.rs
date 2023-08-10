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
use gadgets::binary_number::BinaryNumberChip;
use gadgets::util::{and, Expr, not, or};

use crate::evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon};
use crate::wasm_circuit::bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::common::{configure_constraints_for_q_first_and_q_last, configure_transition_check, WasmAssignAwareChip, WasmCountPrefixedItemsAwareChip, WasmFuncCountAwareChip, WasmLenPrefixedBytesSpanAwareChip, WasmMarkupLeb128SectionAwareChip, WasmNameAwareChip, WasmSharedStateAwareChip};
use crate::wasm_circuit::consts::ExportDescType;
use crate::wasm_circuit::error::Error;
use crate::wasm_circuit::leb128_circuit::circuit::LEB128Chip;
use crate::wasm_circuit::sections::consts::LebParams;
use crate::wasm_circuit::sections::export::body::types::AssignType;
use crate::wasm_circuit::types::SharedState;

#[derive(Debug, Clone)]
pub struct WasmExportSectionBodyConfig<F: Field> {
    pub q_enable: Column<Fixed>,
    pub q_first: Column<Fixed>,
    pub q_last: Column<Fixed>,
    pub is_items_count: Column<Fixed>,
    pub is_export_name_len: Column<Fixed>,
    pub is_export_name: Column<Fixed>,
    pub is_exportdesc_type: Column<Fixed>,
    pub is_exportdesc_type_ctx: Column<Fixed>,
    pub is_exportdesc_val: Column<Fixed>,

    pub leb128_chip: Rc<LEB128Chip<F>>,
    pub exportdesc_type: Column<Advice>,
    pub exportdesc_type_chip: Rc<BinaryNumberChip<F, ExportDescType, 8>>,

    pub func_count: Column<Advice>,
    body_byte_rev_index: Column<Advice>,
    body_item_rev_count: Column<Advice>,

    shared_state: Rc<RefCell<SharedState>>,

    _marker: PhantomData<F>,
}

impl<'a, F: Field> WasmExportSectionBodyConfig<F> {}

#[derive(Debug, Clone)]
pub struct WasmExportSectionBodyChip<F: Field> {
    pub config: WasmExportSectionBodyConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> WasmAssignAwareChip<F> for WasmExportSectionBodyChip<F> {
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

        for assign_type in assign_types {
            if [
                AssignType::IsItemsCount,
                AssignType::IsExportNameLen,
                AssignType::IsExportdescVal,
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
                AssignType::IsExportNameLen => {
                    region.assign_fixed(
                        || format!("assign 'is_export_name_len' val {} at {}", assign_value, offset),
                        self.config.is_export_name_len,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsExportName => {
                    region.assign_fixed(
                        || format!("assign 'is_export_name' val {} at {}", assign_value, offset),
                        self.config.is_export_name,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsExportdescType => {
                    region.assign_fixed(
                        || format!("assign 'is_exportdesc_type' val {} at {}", assign_value, offset),
                        self.config.is_exportdesc_type,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsExportdescVal => {
                    region.assign_fixed(
                        || format!("assign 'is_exportdesc_val' val {} at {}", assign_value, offset),
                        self.config.is_exportdesc_val,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsExportdescTypeCtx => {
                    region.assign_fixed(
                        || format!("assign 'is_exportdesc_type_ctx' val {} at {}", assign_value, offset),
                        self.config.is_exportdesc_type_ctx,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::ExportdescType => {
                    region.assign_advice(
                        || format!("assign 'exportdesc_type' val {} at {}", assign_value, offset),
                        self.config.exportdesc_type,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::BodyByteRevIndex => {
                    region.assign_advice(
                        || format!("assign 'body_byte_rev_index' val {} at {}", assign_value, offset),
                        self.config.body_byte_rev_index,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::BodyItemRevCount => {
                    region.assign_advice(
                        || format!("assign 'body_item_rev_count' val {} at {}", assign_value, offset),
                        self.config.body_item_rev_count,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
            }
        }
    }
}

impl<F: Field> WasmMarkupLeb128SectionAwareChip<F> for WasmExportSectionBodyChip<F> {}

impl<F: Field> WasmCountPrefixedItemsAwareChip<F> for WasmExportSectionBodyChip<F> {}

impl<F: Field> WasmLenPrefixedBytesSpanAwareChip<F> for WasmExportSectionBodyChip<F> {}

impl<F: Field> WasmNameAwareChip<F> for WasmExportSectionBodyChip<F> {}

impl<F: Field> WasmSharedStateAwareChip<F> for WasmExportSectionBodyChip<F> {
    fn shared_state(&self) -> Rc<RefCell<SharedState>> { self.config.shared_state.clone() }
}

impl<F: Field> WasmFuncCountAwareChip<F> for WasmExportSectionBodyChip<F> {
    fn func_count_col(&self) -> Column<Advice> { self.config.func_count }
}

impl<F: Field> WasmExportSectionBodyChip<F>
{
    pub fn construct(config: WasmExportSectionBodyConfig<F>) -> Self {
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
        body_byte_rev_index: Column<Advice>,
        body_item_rev_count: Column<Advice>,
    ) -> WasmExportSectionBodyConfig<F> {
        let q_enable = cs.fixed_column();
        let q_first = cs.fixed_column();
        let q_last = cs.fixed_column();
        let is_items_count = cs.fixed_column();
        let is_export_name_len = cs.fixed_column();
        let is_export_name = cs.fixed_column();
        let is_exportdesc_type = cs.fixed_column();
        let is_exportdesc_val = cs.fixed_column();

        let is_exportdesc_type_ctx = cs.fixed_column();

        let exportdesc_type = cs.advice_column();

        let config = BinaryNumberChip::configure(
            cs,
            is_exportdesc_type_ctx,
            Some(exportdesc_type.into()),
        );
        let exportdesc_type_chip = Rc::new(BinaryNumberChip::construct(config));

        Self::configure_len_prefixed_bytes_span_checks(
            cs,
            leb128_chip.as_ref(),
            |vc| vc.query_fixed(is_export_name, Rotation::cur()),
            body_byte_rev_index,
            |vc| {
                let not_q_last_expr = not::expr(vc.query_fixed(q_last, Rotation::cur()));
                let is_export_name_len_expr = vc.query_fixed(is_export_name_len, Rotation::cur());
                let is_export_name_next_expr = vc.query_fixed(is_export_name, Rotation::next());

                and::expr([not_q_last_expr, is_export_name_len_expr, is_export_name_next_expr])
            },
            |vc| {
                let is_export_name_expr = vc.query_fixed(is_export_name, Rotation::cur());
                let is_exportdesc_type_next_expr = vc.query_fixed(is_exportdesc_type, Rotation::next());

                and::expr([
                    is_export_name_expr,
                    is_exportdesc_type_next_expr,
                ])
            },
        );

        Self::configure_count_prefixed_items_checks(
            cs,
            leb128_chip.as_ref(),
            body_item_rev_count,
            |vc| vc.query_fixed(is_items_count, Rotation::cur()),
            |vc| {
                let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
                let is_items_count_expr = vc.query_fixed(is_items_count, Rotation::cur());

                and::expr([
                    q_enable_expr,
                    not::expr(is_items_count_expr),
                ])
            },
            |vc| {
                let q_first_expr = vc.query_fixed(q_first, Rotation::cur());
                let is_export_name_len_expr = vc.query_fixed(is_export_name_len, Rotation::cur());
                let is_items_count_prev_expr = vc.query_fixed(is_items_count, Rotation::prev());
                let is_exportdesc_val_prev_expr = vc.query_fixed(is_exportdesc_val, Rotation::prev());

                and::expr([
                    not::expr(q_first_expr),
                    is_export_name_len_expr,
                    or::expr([
                        is_items_count_prev_expr,
                        is_exportdesc_val_prev_expr,
                    ]),
                ])
            },
            |vc| vc.query_fixed(q_last, Rotation::cur()),
        );

        cs.create_gate("WasmExportSectionBody gate", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
            let q_first_expr = vc.query_fixed(q_first, Rotation::cur());
            let q_last_expr = vc.query_fixed(q_last, Rotation::cur());
            let not_q_last_expr = not::expr(q_last_expr.clone());
            let is_items_count_expr = vc.query_fixed(is_items_count, Rotation::cur());
            let is_export_name_len_expr = vc.query_fixed(is_export_name_len, Rotation::cur());
            let is_export_name_expr = vc.query_fixed(is_export_name, Rotation::cur());
            let is_exportdesc_type_expr = vc.query_fixed(is_exportdesc_type, Rotation::cur());
            let is_exportdesc_val_expr = vc.query_fixed(is_exportdesc_val, Rotation::cur());

            let is_exportdesc_type_ctx_prev_expr = vc.query_fixed(is_exportdesc_type_ctx, Rotation::prev());
            let is_exportdesc_type_ctx_expr = vc.query_fixed(is_exportdesc_type_ctx, Rotation::cur());

            let byte_val_expr = vc.query_advice(bytecode_table.value, Rotation::cur());

            let exportdesc_type_prev_expr = vc.query_advice(exportdesc_type, Rotation::prev());
            let exportdesc_type_expr = vc.query_advice(exportdesc_type, Rotation::cur());

            let leb128_is_last_byte_expr = vc.query_fixed(leb128_chip.config.is_last_byte, Rotation::cur());

            cb.require_boolean("q_enable is boolean", q_enable_expr.clone());
            cb.require_boolean("is_items_count is boolean", is_items_count_expr.clone());
            cb.require_boolean("is_export_name_len is boolean", is_export_name_len_expr.clone());
            cb.require_boolean("is_export_name is boolean", is_export_name_expr.clone());
            cb.require_boolean("is_exportdesc_type is boolean", is_exportdesc_type_expr.clone());
            cb.require_boolean("is_exportdesc_val is boolean", is_exportdesc_val_expr.clone());

            configure_constraints_for_q_first_and_q_last(
                &mut cb,
                vc,
                &q_enable,
                &q_first,
                &[is_items_count],
                &q_last,
                &[is_exportdesc_val],
            );

            cb.require_equal(
                "exactly one mark flag active at the same time",
                is_items_count_expr.clone()
                    + is_export_name_len_expr.clone()
                    + is_export_name_expr.clone()
                    + is_exportdesc_type_expr.clone()
                    + is_exportdesc_val_expr.clone(),
                1.expr(),
            );

            cb.condition(
                or::expr([
                    is_items_count_expr.clone(),
                    is_export_name_len_expr.clone(),
                    is_exportdesc_val_expr.clone(),
                ]),
                |bcb| {
                    bcb.require_equal(
                        "is_items_count || is_export_name_len || is_exportdesc_val -> leb128",
                        vc.query_fixed(leb128_chip.config.q_enable, Rotation::cur()),
                        1.expr(),
                    )
                }
            );

            cb.condition(
                or::expr([
                    is_exportdesc_type_expr.clone(),
                    is_exportdesc_val_expr.clone(),
                ]),
                |bcb| {
                    bcb.require_equal(
                        "is_exportdesc_type || is_exportdesc_val => is_exportdesc_type_ctx",
                        is_exportdesc_type_ctx_expr.clone(),
                        1.expr(),
                    )
                }
            );
            cb.condition(
                and::expr([
                    is_exportdesc_type_ctx_prev_expr.clone(),
                    is_exportdesc_type_ctx_expr.clone(),
                ]),
                |bcb| {
                    bcb.require_equal(
                        "is_exportdesc_type_ctx && prev.is_exportdesc_type_ctx => exportdesc_type=prev.exportdesc_type",
                        exportdesc_type_expr.clone(),
                        exportdesc_type_prev_expr.clone(),
                    )
                }
            );

            // is_items_count+ -> item+(is_export_name_len+ -> is_export_name+ -> is_exportdesc_type{1} -> is_exportdesc_val+)
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_items_count+ -> item+(is_export_name_len+ ...",
                and::expr([
                    not_q_last_expr.clone(),
                    is_items_count_expr.clone(),
                ]),
                true,
                &[is_items_count, is_export_name_len],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next (last leb byte): is_items_count+ -> item+(is_export_name_len+ ...",
                and::expr([
                    not_q_last_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                    is_items_count_expr.clone(),
                ]),
                true,
                &[is_export_name_len],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_export_name_len+ -> is_export_name+",
                and::expr([
                    not_q_last_expr.clone(),
                    is_export_name_len_expr.clone(),
                ]),
                true,
                &[is_export_name_len, is_export_name],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next (last leb byte): is_export_name_len+ -> is_export_name+",
                and::expr([
                    not_q_last_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                    is_export_name_len_expr.clone(),
                ]),
                true,
                &[is_export_name],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_export_name+ -> is_exportdesc_type{1}",
                and::expr([
                    not_q_last_expr.clone(),
                    is_export_name_expr.clone(),
                ]),
                true,
                &[is_export_name, is_exportdesc_type],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_exportdesc_type{1} -> is_exportdesc_val+",
                and::expr([
                    not_q_last_expr.clone(),
                    is_exportdesc_type_expr.clone(),
                ]),
                true,
                &[is_exportdesc_val],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_exportdesc_val+",
                and::expr([
                    not_q_last_expr.clone(),
                    is_exportdesc_val_expr.clone(),
                ]),
                true,
                &[is_exportdesc_val, is_export_name_len],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next (last leb byte): is_exportdesc_val+",
                and::expr([
                    not_q_last_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                    is_exportdesc_val_expr.clone(),
                ]),
                true,
                &[is_export_name_len],
            );

            cb.condition(
                is_exportdesc_type_expr.clone(),
                |bcb| {
                    bcb.require_in_set(
                        "is_exportdesc_type -> byte_val has valid value",
                        byte_val_expr.clone(),
                        vec![
                            ExportDescType::Funcidx.expr(),
                            ExportDescType::Tableidx.expr(),
                            ExportDescType::Memidx.expr(),
                            ExportDescType::Globalidx.expr(),
                        ],
                    );
                }
            );

            cb.gate(q_enable_expr.clone())
        });

        let config = WasmExportSectionBodyConfig::<F> {
            _marker: PhantomData,

            q_enable,
            q_first,
            q_last,
            is_items_count,
            is_export_name_len,
            is_export_name,
            is_exportdesc_type,
            is_exportdesc_type_ctx,
            is_exportdesc_val,
            leb128_chip,
            exportdesc_type,
            exportdesc_type_chip,
            func_count,
            body_byte_rev_index,
            body_item_rev_count,
            shared_state,
        };

        config
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
        let mut body_item_rev_count = items_count;
        for offset in offset..offset + items_count_leb_len {
            self.assign(
                region,
                &wasm_bytecode,
                offset,
                &[AssignType::BodyItemRevCount],
                body_item_rev_count,
                None,
            );
        }
        self.assign(region, &wasm_bytecode, offset, &[AssignType::QFirst], 1, None);
        offset += items_count_leb_len;

        for _item_index in 0..items_count {
            body_item_rev_count -= 1;
            let item_start_offset = offset;

            let (export_name_len, export_name_len_leb_len) = self.markup_leb_section(
                region,
                wasm_bytecode,
                offset,
                &[AssignType::IsExportNameLen],
            );
            let export_name_len_last_byte_offset = offset + export_name_len_leb_len - 1;
            let export_name_last_byte_offset = export_name_len_last_byte_offset + export_name_len as usize;
            for offset in export_name_len_last_byte_offset..=export_name_last_byte_offset {
                self.assign(
                    region,
                    &wasm_bytecode,
                    offset,
                    &[AssignType::BodyByteRevIndex],
                    (export_name_last_byte_offset - offset) as u64,
                    None,
                );
            }
            offset += export_name_len_leb_len;

            let export_name_new_offset = self.markup_name_section(
                region,
                wasm_bytecode,
                offset,
                &[AssignType::IsExportName],
                export_name_len as usize,
                1,
            );
            offset = export_name_new_offset;

            let exportdesc_type_val = wasm_bytecode.bytes.as_slice()[offset];
            let exportdesc_type: ExportDescType = wasm_bytecode.bytes.as_slice()[offset].try_into().unwrap();
            self.assign(
                region,
                wasm_bytecode,
                offset,
                &[AssignType::IsExportdescType, AssignType::IsExportdescTypeCtx],
                1,
                None,
            );
            self.assign(
                region,
                &wasm_bytecode,
                offset,
                &[AssignType::ExportdescType],
                exportdesc_type_val as u64,
                None,
            );
            self.config.exportdesc_type_chip.assign(region, offset, &exportdesc_type).unwrap();
            offset += 1;

            match exportdesc_type {
                ExportDescType::Funcidx | ExportDescType::Tableidx | ExportDescType::Memidx | ExportDescType::Globalidx => {
                    let (exportdesc_val, exportdesc_val_leb_len) = self.markup_leb_section(
                        region,
                        wasm_bytecode,
                        offset,
                        &[AssignType::IsExportdescVal, AssignType::IsExportdescTypeCtx],
                    );
                    for offset in offset..offset + exportdesc_val_leb_len {
                        self.assign(
                            region,
                            &wasm_bytecode,
                            offset,
                            &[AssignType::ExportdescType],
                            exportdesc_type_val as u64,
                            None,
                        );
                        self.config.exportdesc_type_chip.assign(region, offset, &exportdesc_type).unwrap();
                    }
                    offset += exportdesc_val_leb_len;
                }
            }

            for offset in item_start_offset..offset {
                self.assign(
                    region,
                    &wasm_bytecode,
                    offset,
                    &[AssignType::BodyItemRevCount],
                    body_item_rev_count,
                    None,
                );
            }
        }

        if offset != offset_start {
            self.assign(region, &wasm_bytecode, offset - 1, &[AssignType::QLast], 1, None);
        }

        Ok(offset)
    }
}