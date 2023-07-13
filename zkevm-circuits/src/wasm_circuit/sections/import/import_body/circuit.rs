use halo2_proofs::{
    plonk::{Column, ConstraintSystem},
};
use std::{marker::PhantomData};
use std::rc::Rc;
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::plonk::{Advice, Fixed};
use halo2_proofs::poly::Rotation;
use itertools::Itertools;
use log::debug;
use eth_types::Field;
use gadgets::binary_number::BinaryNumberChip;
use gadgets::util::{and, Expr, not, or};
use crate::evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon};
use crate::wasm_circuit::consts::{IMPORT_DESC_TYPE_VALUES, ImportDescType, MUTABILITY_VALUES};
use crate::wasm_circuit::error::Error;
use crate::wasm_circuit::leb128_circuit::circuit::LEB128Chip;
use crate::wasm_circuit::leb128_circuit::helpers::{leb128_compute_sn, leb128_compute_sn_recovered_at_position};
use crate::wasm_circuit::utf8_circuit::circuit::UTF8Chip;
use crate::wasm_circuit::bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::sections::consts::LebParams;
use crate::wasm_circuit::sections::helpers::configure_check_for_transition;
use crate::wasm_circuit::sections::import::import_body::types::AssignType;
use crate::wasm_circuit::tables::dynamic_indexes::circuit::DynamicIndexesChip;

#[derive(Debug, Clone)]
pub struct WasmImportSectionBodyConfig<F: Field> {
    pub q_enable: Column<Fixed>,
    pub is_items_count: Column<Fixed>,
    pub is_mod_name_len: Column<Fixed>,
    pub is_mod_name: Column<Fixed>,
    pub is_import_name_len: Column<Fixed>,
    pub is_import_name: Column<Fixed>,
    pub is_importdesc_type: Column<Fixed>,
    pub is_importdesc_type_ctx: Column<Fixed>,
    pub is_importdesc_val: Column<Fixed>,
    pub is_mut: Column<Fixed>,

    pub leb128_chip: Rc<LEB128Chip<F>>,
    pub utf8_chip: Rc<UTF8Chip<F>>,
    pub dynamic_indexes_chip: Rc<DynamicIndexesChip<F>>,
    pub importdesc_type: Column<Advice>,
    pub importdesc_type_chip: Rc<BinaryNumberChip<F, ImportDescType, 8>>,

    _marker: PhantomData<F>,
}

impl<'a, F: Field> WasmImportSectionBodyConfig<F>
{}

#[derive(Debug, Clone)]
pub struct WasmImportSectionBodyChip<F: Field> {
    pub config: WasmImportSectionBodyConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> WasmImportSectionBodyChip<F>
{
    pub fn construct(config: WasmImportSectionBodyConfig<F>) -> Self {
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
        utf8_chip: Rc<UTF8Chip<F>>,
        dynamic_indexes_chip: Rc<DynamicIndexesChip<F>>,
    ) -> WasmImportSectionBodyConfig<F> {
        let q_enable = cs.fixed_column();
        let is_items_count = cs.fixed_column();
        let is_mod_name_len = cs.fixed_column();
        let is_mod_name = cs.fixed_column();
        let is_import_name_len = cs.fixed_column();
        let is_import_name = cs.fixed_column();
        let is_importdesc_type = cs.fixed_column();
        let is_importdesc_val = cs.fixed_column();
        let is_mut = cs.fixed_column();

        let is_importdesc_type_ctx = cs.fixed_column();

        let importdesc_type = cs.advice_column();

        let config = BinaryNumberChip::configure(
            cs,
            is_importdesc_type_ctx,
            Some(importdesc_type.into()),
        );
        let importdesc_type_chip = Rc::new(BinaryNumberChip::construct(config));

        cs.create_gate("WasmImportSectionBody gate", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
            let is_items_count_expr = vc.query_fixed(is_items_count, Rotation::cur());
            let is_mod_name_len_expr = vc.query_fixed(is_mod_name_len, Rotation::cur());
            let is_mod_name_expr = vc.query_fixed(is_mod_name, Rotation::cur());
            let is_import_name_len_expr = vc.query_fixed(is_import_name_len, Rotation::cur());
            let is_import_name_expr = vc.query_fixed(is_import_name, Rotation::cur());
            let is_importdesc_type_expr = vc.query_fixed(is_importdesc_type, Rotation::cur());
            let is_importdesc_type_ctx_prev_expr = vc.query_fixed(is_importdesc_type_ctx, Rotation::prev());
            let is_importdesc_type_ctx_expr = vc.query_fixed(is_importdesc_type_ctx, Rotation::cur());
            let is_importdesc_val_expr = vc.query_fixed(is_importdesc_val, Rotation::cur());
            let is_mut_expr = vc.query_fixed(is_mut, Rotation::cur());

            let byte_value_expr = vc.query_advice(bytecode_table.value, Rotation::cur());
            let importdesc_type_prev_expr = vc.query_advice(importdesc_type, Rotation::prev());
            let importdesc_type_expr = vc.query_advice(importdesc_type, Rotation::cur());

            let utf8_chip_q_enabled_expr = vc.query_fixed(utf8_chip.config.q_enable, Rotation::cur());

            cb.require_boolean("q_enable is boolean", q_enable_expr.clone());
            cb.require_boolean("is_items_count is boolean", is_items_count_expr.clone());
            cb.require_boolean("is_mod_name_len is boolean", is_mod_name_len_expr.clone());
            cb.require_boolean("is_mod_name is boolean", is_mod_name_expr.clone());
            cb.require_boolean("is_import_name_len is boolean", is_import_name_len_expr.clone());
            cb.require_boolean("is_import_name is boolean", is_import_name_expr.clone());
            cb.require_boolean("is_importdesc_type is boolean", is_importdesc_type_expr.clone());
            cb.require_boolean("is_importdesc_val is boolean", is_importdesc_val_expr.clone());
            cb.require_boolean("is_mut is boolean", is_mut_expr.clone());

            cb.condition(
                or::expr([
                    is_importdesc_type_expr.clone(),
                    is_importdesc_val_expr.clone(),
                    is_mut_expr.clone(),
                ]),
                |bcb| {
                    bcb.require_equal(
                        "is_importdesc_type || is_importdesc_val || is_mut => is_importdesc_type_ctx",
                        is_importdesc_type_ctx_expr.clone(),
                        1.expr(),
                    )
                }
            );
            cb.condition(
                and::expr([
                    is_importdesc_type_ctx_prev_expr.clone(),
                    is_importdesc_type_ctx_expr.clone(),
                ]),
                |bcb| {
                    bcb.require_equal(
                        "is_importdesc_type_ctx && prev.is_importdesc_type_ctx => importdesc_type=prev.importdesc_type",
                        importdesc_type_expr.clone(),
                        importdesc_type_prev_expr.clone(),
                    )
                }
            );

            cb.require_equal(
                "exactly one mark flag active at the same time",
                is_items_count_expr.clone()
                    + is_mod_name_len_expr.clone()
                    + is_mod_name_expr.clone()
                    + is_import_name_len_expr.clone()
                    + is_import_name_expr.clone()
                    + is_importdesc_type_expr.clone()
                    + is_importdesc_val_expr.clone()
                    + is_mut_expr.clone()
                ,
                1.expr(),
            );

            // TODO
            // cb.req(
            //     "is_items_count=1 -> first byte val is not 0",
            //     ,
            //     1.expr(),
            // );

            cb.condition(
                or::expr([
                    is_items_count_expr.clone(),
                    is_mod_name_len_expr.clone(),
                    is_import_name_len_expr.clone(),
                    is_importdesc_val_expr.clone()
                ]),
                |bcb| {
                    bcb.require_equal(
                        "is_items_count || is_mod_name_len || is_import_name_len || is_importdesc_val => leb128",
                        vc.query_fixed(leb128_chip.config.q_enable, Rotation::cur()),
                        1.expr(),
                    )
                }
            );

            cb.condition(
                is_mut_expr.clone(),
                |bcb| {
                    bcb.require_in_set(
                        "is_mut => byte_val is valid",
                        byte_value_expr.clone(),
                        MUTABILITY_VALUES.iter().map(|&v| v.expr()).collect_vec(),
                    )
                }
            );

            // is_items_count+ -> is_item+ (is_mod_name_len+ -> is_mod_name* -> is_import_name_len+ -> is_import_name* -> import_desc+)
            let importdesc_type_is_typeidx_prev_expr = importdesc_type_chip.config.value_equals(ImportDescType::Typeidx, Rotation::prev())(vc);
            let importdesc_type_is_mem_type_prev_expr = importdesc_type_chip.config.value_equals(ImportDescType::MemType, Rotation::prev())(vc);
            let importdesc_type_is_table_type_prev_expr = importdesc_type_chip.config.value_equals(ImportDescType::TableType, Rotation::prev())(vc);
            let importdesc_type_is_global_type_prev_expr = importdesc_type_chip.config.value_equals(ImportDescType::GlobalType, Rotation::prev())(vc);
            let importdesc_type_is_typeidx_expr = importdesc_type_chip.config.value_equals(ImportDescType::Typeidx, Rotation::cur())(vc);
            let importdesc_type_is_mem_type_expr = importdesc_type_chip.config.value_equals(ImportDescType::MemType, Rotation::cur())(vc);
            let importdesc_type_is_table_type_expr = importdesc_type_chip.config.value_equals(ImportDescType::TableType, Rotation::cur())(vc);
            let importdesc_type_is_global_type_expr = importdesc_type_chip.config.value_equals(ImportDescType::GlobalType, Rotation::cur())(vc);
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_items_count+ -> is_item+ (is_mod_name_len+ ...",
                and::expr([
                    is_items_count_expr.clone(),
                    importdesc_type_is_typeidx_expr.clone(),
                ]),
                true,
                &[is_items_count, is_mod_name_len, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_items_count+ -> is_item+ (is_mod_name_len+ ...",
                and::expr([
                    is_mod_name_len_expr.clone(),
                    importdesc_type_is_typeidx_expr.clone(),
                    importdesc_type_is_global_type_prev_expr.clone(),
                ]),
                false,
                &[is_items_count, is_mod_name_len, is_importdesc_val, is_mut, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_items_count+ -> is_item+ (is_mod_name_len+ ...",
                and::expr([
                    is_mod_name_len_expr.clone(),
                    importdesc_type_is_typeidx_expr.clone(),
                    not::expr(importdesc_type_is_global_type_prev_expr.clone()),
                ]),
                false,
                &[is_items_count, is_mod_name_len, is_importdesc_val, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_mod_name_len+ -> is_mod_name* -> is_import_name_len+",
                and::expr([
                    is_mod_name_len_expr.clone(),
                    importdesc_type_is_typeidx_expr.clone(),
                ]),
                true,
                &[is_mod_name_len, is_mod_name, is_import_name_len, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_mod_name_len+ -> is_mod_name*",
                and::expr([
                    is_mod_name_expr.clone(),
                    importdesc_type_is_typeidx_expr.clone(),
                ]),
                false,
                &[is_mod_name, is_mod_name_len, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_mod_name* -> is_import_name_len+",
                and::expr([
                    is_mod_name_expr.clone(),
                    importdesc_type_is_typeidx_expr.clone(),
                ]),
                true,
                &[is_mod_name, is_import_name_len, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_mod_name_len+ -> is_mod_name* -> is_import_name_len+",
                and::expr([
                    is_import_name_len_expr.clone(),
                    importdesc_type_is_typeidx_expr.clone(),
                ]),
                false,
                &[is_mod_name_len, is_mod_name, is_import_name_len, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_import_name_len+ -> is_import_name* -> is_importdesc_type{1}",
                and::expr([
                    is_import_name_len_expr.clone(),
                    importdesc_type_is_typeidx_expr.clone(),
                ]),
                true,
                &[is_import_name_len, is_import_name, is_importdesc_type, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_import_name_len+ -> is_import_name*",
                and::expr([
                    is_import_name_expr.clone(),
                    importdesc_type_is_typeidx_expr.clone(),
                ]),
                false,
                &[is_import_name_len, is_import_name, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_import_name* -> is_importdesc_type{1}",
                and::expr([
                    is_import_name_expr.clone(),
                    importdesc_type_is_typeidx_expr.clone(),
                ]),
                true,
                &[is_import_name, is_importdesc_type, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_import_name_len+ -> is_import_name* -> is_importdesc_type{1}",
                and::expr([
                    is_importdesc_type_expr.clone(),
                    importdesc_type_is_typeidx_expr.clone(),
                ]),
                false,
                &[is_import_name_len, is_import_name, is_importdesc_type, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_importdesc_type{1} -> is_importdesc_val+",
                and::expr([
                    is_importdesc_type_expr.clone(),
                    importdesc_type_is_typeidx_expr.clone(),
                ]),
                true,
                &[is_importdesc_val, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_importdesc_type{1} -> is_importdesc_val+",
                and::expr([
                    is_importdesc_val_expr.clone(),
                    importdesc_type_is_typeidx_expr.clone(),
                ]),
                false,
                &[is_importdesc_type, is_importdesc_val, ],
            );
            // TODO importdesc_type{1}=3(ImportDescType::Globaltype): import_desc+(is_importdesc_type{1} -> is_importdesc_val+ -> is_mut{1})
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_items_count+ -> is_item+ (is_mod_name_len+ ...",
                and::expr([
                    is_items_count_expr.clone(),
                    importdesc_type_is_global_type_expr.clone(),
                ]),
                true,
                &[is_items_count, is_mod_name_len, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_items_count+ -> is_item+ (is_mod_name_len+ ...",
                and::expr([
                    is_mod_name_len_expr.clone(),
                    importdesc_type_is_global_type_expr.clone(),
                    importdesc_type_is_global_type_prev_expr.clone(),
                ]),
                false,
                &[is_items_count, is_mod_name_len, is_importdesc_val, is_mut, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_items_count+ -> is_item+ (is_mod_name_len+ ...",
                and::expr([
                    is_mod_name_len_expr.clone(),
                    importdesc_type_is_global_type_expr.clone(),
                    not::expr(importdesc_type_is_global_type_prev_expr.clone()),
                ]),
                false,
                &[is_items_count, is_mod_name_len, is_importdesc_val, is_mut, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_mod_name_len+ -> is_mod_name* -> is_import_name_len+",
                and::expr([
                    is_mod_name_len_expr.clone(),
                    importdesc_type_is_global_type_expr.clone(),
                ]),
                true,
                &[is_mod_name_len, is_mod_name, is_import_name_len, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_mod_name_len+ -> is_mod_name*",
                and::expr([
                    is_mod_name_expr.clone(),
                    importdesc_type_is_global_type_expr.clone(),
                ]),
                false,
                &[is_mod_name, is_mod_name_len, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_mod_name* -> is_import_name_len+",
                and::expr([
                    is_mod_name_expr.clone(),
                    importdesc_type_is_global_type_expr.clone(),
                ]),
                true,
                &[is_mod_name, is_import_name_len, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_mod_name_len+ -> is_mod_name* -> is_import_name_len+",
                and::expr([
                    is_import_name_len_expr.clone(),
                    importdesc_type_is_global_type_expr.clone(),
                ]),
                false,
                &[is_mod_name_len, is_mod_name, is_import_name_len, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_import_name_len+ -> is_import_name* -> is_importdesc_type{1}",
                and::expr([
                    is_import_name_len_expr.clone(),
                    importdesc_type_is_global_type_expr.clone(),
                ]),
                true,
                &[is_import_name_len, is_import_name, is_importdesc_type, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_import_name_len+ -> is_import_name*",
                and::expr([
                    is_import_name_expr.clone(),
                    importdesc_type_is_global_type_expr.clone(),
                ]),
                false,
                &[is_import_name_len, is_import_name, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_import_name* -> is_importdesc_type{1}",
                and::expr([
                    is_import_name_expr.clone(),
                    importdesc_type_is_global_type_expr.clone(),
                ]),
                true,
                &[is_import_name, is_importdesc_type, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_import_name_len+ -> is_import_name* -> is_importdesc_type{1}",
                and::expr([
                    is_importdesc_type_expr.clone(),
                    importdesc_type_is_global_type_expr.clone(),
                ]),
                false,
                &[is_import_name_len, is_import_name, is_importdesc_type, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_importdesc_type{1} -> is_importdesc_val+",
                and::expr([
                    is_importdesc_type_expr.clone(),
                    importdesc_type_is_global_type_expr.clone(),
                ]),
                true,
                &[is_importdesc_val, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_importdesc_type{1} -> is_importdesc_val+",
                and::expr([
                    is_importdesc_val_expr.clone(),
                    importdesc_type_is_global_type_expr.clone(),
                ]),
                false,
                &[is_importdesc_type, is_importdesc_val, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_importdesc_val+ -> is_mut{1}",
                and::expr([
                    is_importdesc_val_expr.clone(),
                    importdesc_type_is_global_type_expr.clone(),
                ]),
                true,
                &[is_importdesc_val, is_mut, ],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_importdesc_val+ -> is_mut{1}",
                and::expr([
                    is_mut_expr.clone(),
                    importdesc_type_is_global_type_expr.clone(),
                ]),
                false,
                &[is_importdesc_val, ],
            );
            // TODO importdesc_type{1}=ImportDescType::Memtype: TODO
            cb.condition(
                importdesc_type_is_mem_type_expr.expr(),
                |bcb| {
                    bcb.require_equal(
                        "unsupported ImportDescType::Memtype",
                        0.expr(),
                        1.expr(),
                    )
                }
            );
            // TODO importdesc_type{1}=ImportDescType::Tabletype: TODO
            cb.condition(
                importdesc_type_is_table_type_expr.expr(),
                |bcb| {
                    bcb.require_equal(
                        "unsupported ImportDescType::Tabletype",
                        0.expr(),
                        1.expr(),
                    )
                }
            );

            cb.condition(
                is_importdesc_type_expr.clone(),
                |bcb| {
                    bcb.require_in_set(
                        "is_importdesc_type => value is valid",
                        byte_value_expr.clone(),
                        IMPORT_DESC_TYPE_VALUES.iter().map(|v| (*v).expr()).collect_vec()
                    );
                    bcb.require_equal(
                        "is_importdesc_type => importdesc_type has valid value",
                        importdesc_type_expr.clone(),
                        byte_value_expr.clone(),
                    );
                }
            );

            cb.require_equal(
                "is_mod_name || is_import_name -> utf8",
                or::expr([
                    is_mod_name_expr.clone(),
                    is_import_name_expr.clone(),
                ]),
                utf8_chip_q_enabled_expr.clone(),
            );

            cb.gate(q_enable_expr.clone())
        });

        let config = WasmImportSectionBodyConfig::<F> {
            q_enable,
            is_items_count,
            is_mod_name_len,
            is_mod_name,
            is_import_name_len,
            is_import_name,
            is_importdesc_type,
            is_importdesc_type_ctx,
            is_importdesc_val,
            is_mut,
            leb128_chip,
            utf8_chip,
            dynamic_indexes_chip,
            importdesc_type,
            importdesc_type_chip,
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
            "import_section_body: assign at offset {} q_enable {} assign_type {:?} assign_value {} byte_val {:x?}",
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
                AssignType::IsItemsCount,
                AssignType::IsModNameLen,
                AssignType::IsImportNameLen,
                AssignType::IsImportdescVal,
            ].contains(assign_type) {
                let p = leb_params.unwrap();
                self.config.leb128_chip.assign(
                    region,
                    offset,
                    true,
                    p,
                );
            }
            if [
                AssignType::IsModName,
                AssignType::IsImportName,
            ].contains(assign_type) {
                let byte_val = wasm_bytecode.bytes[offset];
                self.config.utf8_chip.assign(
                    region,
                    offset,
                    true,
                    byte_val,
                );
            }
            match assign_type {
                AssignType::IsItemsCount => {
                    region.assign_fixed(
                        || format!("assign 'is_items_count' val {} at {}", assign_value, offset),
                        self.config.is_items_count,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsModNameLen => {
                    region.assign_fixed(
                        || format!("assign 'is_mod_name_len' val {} at {}", assign_value, offset),
                        self.config.is_mod_name_len,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsModName => {
                    region.assign_fixed(
                        || format!("assign 'is_mod_name' val {} at {}", assign_value, offset),
                        self.config.is_mod_name,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsImportNameLen => {
                    region.assign_fixed(
                        || format!("assign 'is_import_name_len' val {} at {}", assign_value, offset),
                        self.config.is_import_name_len,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsImportName => {
                    region.assign_fixed(
                        || format!("assign 'is_import_name' val {} at {}", assign_value, offset),
                        self.config.is_import_name,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsImportdescType => {
                    region.assign_fixed(
                        || format!("assign 'is_importdesc_type' val {} at {}", assign_value, offset),
                        self.config.is_importdesc_type,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsImportdescVal => {
                    region.assign_fixed(
                        || format!("assign 'is_importdesc_val' val {} at {}", assign_value, offset),
                        self.config.is_importdesc_val,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsMut => {
                    region.assign_fixed(
                        || format!("assign 'is_mut' val {} at {}", assign_value, offset),
                        self.config.is_mut,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsImportdescTypeCtx => {
                    region.assign_fixed(
                        || format!("assign 'is_importdesc_type_ctx' val {} at {}", assign_value, offset),
                        self.config.is_importdesc_type_ctx,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::ImportdescType => {
                    region.assign_advice(
                        || format!("assign 'importdesc_type' val {} at {}", assign_value, offset),
                        self.config.importdesc_type,
                        offset,
                        || Value::known(F::from(assign_value)),
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

    fn markup_name_section(
        &self,
        region: &mut Region<F>,
        wasm_bytecode: &WasmBytecode,
        assign_type: AssignType,
        offset: usize,
        name_len: usize,
    ) {
        if ![
            AssignType::IsModName,
            AssignType::IsImportName,
        ].contains(&assign_type) {
            panic!("unsupported assign type {:?}", assign_type)
        }
        for byte_offset in 0..name_len {
            self.assign(
                region,
                wasm_bytecode,
                offset + byte_offset,
                &[assign_type],
                1,
                None,
            );
        }
    }

    /// returns new offset
    pub fn assign_auto(
        &self,
        region: &mut Region<F>,
        wasm_bytecode: &WasmBytecode,
        offset_start: usize,
    ) -> Result<usize, Error> {
        let mut offset = offset_start;

        // is_items_count+
        let (items_count, items_count_leb_len) = self.markup_leb_section(
            region,
            wasm_bytecode,
            offset,
            &[AssignType::IsItemsCount],
        );
        offset += items_count_leb_len;

        for _item_index in 0..items_count {
            // is_mod_name_len+
            let (mod_name_len, mod_name_leb_len) = self.markup_leb_section(
                region,
                wasm_bytecode,
                offset,
                &[AssignType::IsModNameLen],
            );
            offset += mod_name_leb_len;

            // is_mod_name*
            self.markup_name_section(
                region,
                wasm_bytecode,
                AssignType::IsModName,
                offset,
                mod_name_len as usize,
            );
            offset += mod_name_len as usize;

            // is_import_name_len+
            let (import_name_len, import_name_leb_len) = self.markup_leb_section(
                region,
                wasm_bytecode,
                offset,
                &[AssignType::IsImportNameLen],
            );
            offset += import_name_leb_len;

            // is_import_name*
            self.markup_name_section(
                region,
                wasm_bytecode,
                AssignType::IsImportName,
                offset,
                import_name_len as usize,
            );
            offset += import_name_len as usize;

            // is_importdesc_type{1}
            let import_desc_type_val = wasm_bytecode.bytes[offset];
            let import_desc_type: ImportDescType = import_desc_type_val.try_into().unwrap();
            self.assign(
                region,
                wasm_bytecode,
                offset,
                &[AssignType::IsImportdescType, AssignType::IsImportdescTypeCtx],
                1,
                None,
            );
            self.assign(
                region,
                &wasm_bytecode,
                offset,
                &[AssignType::ImportdescType],
                import_desc_type_val as u64,
                None,
            );
            self.config.importdesc_type_chip.assign(region, offset, &import_desc_type).unwrap();
            offset += 1;

            // is_importdesc_val+
            match import_desc_type {
                ImportDescType::Typeidx => {
                    let (_importdesc_val, importdesc_val_leb_len) = self.markup_leb_section(
                        region,
                        wasm_bytecode,
                        offset,
                        &[AssignType::IsImportdescVal, AssignType::IsImportdescTypeCtx],
                    );
                    for offset in offset..offset + importdesc_val_leb_len {
                        self.assign(
                            region,
                            &wasm_bytecode,
                            offset,
                            &[AssignType::ImportdescType],
                            import_desc_type_val as u64,
                            None,
                        );
                        self.config.importdesc_type_chip.assign(region, offset, &import_desc_type).unwrap();
                    }
                    offset += importdesc_val_leb_len;
                }
                ImportDescType::GlobalType => {
                    let (_importdesc_val, importdesc_val_leb_len) = self.markup_leb_section(
                        region,
                        wasm_bytecode,
                        offset,
                        &[AssignType::IsImportdescVal, AssignType::IsImportdescTypeCtx],
                    );
                    for offset in offset..offset + importdesc_val_leb_len {
                        self.assign(
                            region,
                            &wasm_bytecode,
                            offset,
                            &[AssignType::ImportdescType],
                            import_desc_type_val as u64,
                            None,
                        );
                        self.config.importdesc_type_chip.assign(region, offset, &import_desc_type).unwrap();
                    }
                    offset += importdesc_val_leb_len;

                    self.assign(
                        region,
                        wasm_bytecode,
                        offset,
                        &[AssignType::IsMut, AssignType::IsImportdescTypeCtx],
                        1,
                        None,
                    );
                    for offset in offset..offset + importdesc_val_leb_len {
                        self.assign(
                            region,
                            &wasm_bytecode,
                            offset,
                            &[AssignType::ImportdescType],
                            import_desc_type_val as u64,
                            None,
                        );
                        self.config.importdesc_type_chip.assign(region, offset, &import_desc_type).unwrap();
                    }
                    offset += 1;
                }
                _ => { panic!("unsupported import_desc_type {:?}", import_desc_type) }
            }
        }

        Ok(offset)
    }
}