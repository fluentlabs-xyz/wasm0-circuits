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
use gadgets::less_than::{LtChip, LtInstruction};
use gadgets::util::{and, Expr, not, or};

use crate::evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon};
use crate::wasm_circuit::bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::common::{LimitTypeFields, WasmFuncCountAwareChip, WasmLimitTypeAwareChip, WasmSharedStateAwareChip};
use crate::wasm_circuit::consts::{IMPORT_DESC_TYPE_VALUES, ImportDescType, LimitType, MUTABILITY_VALUES, REF_TYPE_VALUES, RefType};
use crate::wasm_circuit::error::Error;
use crate::wasm_circuit::leb128_circuit::circuit::LEB128Chip;
use crate::wasm_circuit::leb128_circuit::helpers::{leb128_compute_sn, leb128_compute_sn_recovered_at_position};
use crate::wasm_circuit::sections::consts::LebParams;
use crate::wasm_circuit::sections::helpers::{configure_constraints_for_q_first_and_q_last, configure_transition_check};
use crate::wasm_circuit::sections::import::import_body::types::AssignType;
use crate::wasm_circuit::tables::dynamic_indexes::circuit::DynamicIndexesChip;
use crate::wasm_circuit::types::SharedState;
use crate::wasm_circuit::utf8_circuit::circuit::UTF8Chip;

#[derive(Debug, Clone)]
pub struct WasmImportSectionBodyConfig<F: Field> {
    pub q_enable: Column<Fixed>,
    pub q_first: Column<Fixed>,
    pub q_last: Column<Fixed>,
    pub is_items_count: Column<Fixed>,
    pub is_mod_name_len: Column<Fixed>,
    pub is_mod_name: Column<Fixed>,
    pub is_import_name_len: Column<Fixed>,
    pub is_import_name: Column<Fixed>,
    pub is_importdesc_type: Column<Fixed>,
    pub is_importdesc_type_ctx: Column<Fixed>,
    pub is_importdesc_val: Column<Fixed>,
    pub is_mut_prop: Column<Fixed>,

    pub limit_type_fields: LimitTypeFields<F>,

    pub is_ref_type: Column<Fixed>,

    pub leb128_chip: Rc<LEB128Chip<F>>,
    pub utf8_chip: Rc<UTF8Chip<F>>,
    pub dynamic_indexes_chip: Rc<DynamicIndexesChip<F>>,
    pub importdesc_type: Column<Advice>,
    pub importdesc_type_chip: Rc<BinaryNumberChip<F, ImportDescType, 8>>,

    pub func_count: Column<Advice>,

    shared_state: Rc<RefCell<SharedState>>,

    _marker: PhantomData<F>,
}

impl<'a, F: Field> WasmImportSectionBodyConfig<F>
{}

#[derive(Debug, Clone)]
pub struct WasmImportSectionBodyChip<F: Field> {
    pub config: WasmImportSectionBodyConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> WasmSharedStateAwareChip<F> for WasmImportSectionBodyChip<F> {
    fn shared_state(&self) -> Rc<RefCell<SharedState>> { self.config.shared_state.clone() }
}

impl<F: Field> WasmFuncCountAwareChip<F> for WasmImportSectionBodyChip<F> {
    fn func_count_col(&self) -> Column<Advice> { self.config.func_count }
}

impl<F: Field> WasmLimitTypeAwareChip<F> for WasmImportSectionBodyChip<F> {}

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
        func_count: Column<Advice>,
        shared_state: Rc<RefCell<SharedState>>,
    ) -> WasmImportSectionBodyConfig<F> {
        let q_enable = cs.fixed_column();
        let q_first = cs.fixed_column();
        let q_last = cs.fixed_column();
        let is_items_count = cs.fixed_column();
        let is_mod_name_len = cs.fixed_column();
        let is_mod_name = cs.fixed_column();
        let is_import_name_len = cs.fixed_column();
        let is_import_name = cs.fixed_column();
        let is_importdesc_type = cs.fixed_column();
        let is_importdesc_val = cs.fixed_column();
        let is_mut_prop = cs.fixed_column();
        let is_ref_type = cs.fixed_column();

        let is_importdesc_type_ctx = cs.fixed_column();

        let importdesc_type = cs.advice_column();

        let config = BinaryNumberChip::configure(
            cs,
            is_importdesc_type_ctx,
            Some(importdesc_type.into()),
        );
        let importdesc_type_chip = Rc::new(BinaryNumberChip::construct(config));

        let limit_type_fields = Self::construct_limit_type_fields(
            cs,
            q_enable,
            leb128_chip.as_ref(),
        );
        Self::configure_limit_type_constraints(
            cs,
            bytecode_table.as_ref(),
            q_enable,
            leb128_chip.as_ref(),
            &limit_type_fields,
        );

        let LimitTypeFields {
            is_limit_type,
            is_limit_min,
            is_limit_max,
            limit_type_chip,
            ..
        } = limit_type_fields.clone();

        cs.create_gate("WasmImportSectionBody gate", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
            let q_last_expr = vc.query_fixed(q_last, Rotation::cur());
            let not_q_last_expr = not::expr(q_last_expr.clone());
            let is_items_count_expr = vc.query_fixed(is_items_count, Rotation::cur());
            let is_mod_name_len_expr = vc.query_fixed(is_mod_name_len, Rotation::cur());
            let is_mod_name_expr = vc.query_fixed(is_mod_name, Rotation::cur());
            let is_import_name_len_expr = vc.query_fixed(is_import_name_len, Rotation::cur());
            let is_import_name_expr = vc.query_fixed(is_import_name, Rotation::cur());
            let is_importdesc_type_expr = vc.query_fixed(is_importdesc_type, Rotation::cur());
            let is_importdesc_val_expr = vc.query_fixed(is_importdesc_val, Rotation::cur());
            let is_mut_prop_expr = vc.query_fixed(is_mut_prop, Rotation::cur());
            let is_limit_type_expr = vc.query_fixed(is_limit_type, Rotation::cur());
            let is_limit_min_expr = vc.query_fixed(is_limit_min, Rotation::cur());
            let is_limit_max_expr = vc.query_fixed(is_limit_max, Rotation::cur());
            let is_ref_type_expr = vc.query_fixed(is_ref_type, Rotation::cur());

            let is_importdesc_type_ctx_prev_expr = vc.query_fixed(is_importdesc_type_ctx, Rotation::prev());
            let is_importdesc_type_ctx_expr = vc.query_fixed(is_importdesc_type_ctx, Rotation::cur());

            let byte_val_expr = vc.query_advice(bytecode_table.value, Rotation::cur());
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
            cb.require_boolean("is_mut_prop is boolean", is_mut_prop_expr.clone());
            cb.require_boolean("is_limit_type is boolean", is_limit_type_expr.clone());
            cb.require_boolean("is_limit_min is boolean", is_limit_min_expr.clone());
            cb.require_boolean("is_limit_max is boolean", is_limit_max_expr.clone());
            cb.require_boolean("is_ref_type is boolean", is_ref_type_expr.clone());

            configure_constraints_for_q_first_and_q_last(
                &mut cb,
                vc,
                &q_enable,
                &q_first,
                &[is_items_count],
                &q_last,
                &[is_importdesc_val, is_mut_prop, is_limit_min, is_limit_max],
            );

            cb.condition(
                or::expr([
                    is_importdesc_type_expr.clone(),
                    is_importdesc_val_expr.clone(),
                    is_mut_prop_expr.clone(),
                ]),
                |bcb| {
                    bcb.require_equal(
                        "is_importdesc_type || is_importdesc_val || is_mut_prop => is_importdesc_type_ctx",
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
                    + is_mut_prop_expr.clone()
                    + is_limit_type_expr.clone()
                    + is_limit_min_expr.clone()
                    + is_limit_max_expr.clone()
                    + is_ref_type_expr.clone()
                ,
                1.expr(),
            );

            cb.condition(
                is_ref_type_expr.clone(),
                |bcb| {
                    bcb.require_in_set(
                        "reference_type => byte value is valid",
                        byte_val_expr.clone(),
                        REF_TYPE_VALUES.iter().map(|&v| v.expr()).collect_vec(),
                    )
                }
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
                    is_importdesc_val_expr.clone(),
                    is_limit_min_expr.clone(),
                    is_limit_max_expr.clone(),
                ]),
                |bcb| {
                    bcb.require_equal(
                        "is_items_count || is_mod_name_len || is_import_name_len || is_importdesc_val || is_limit_min || is_limit_max => leb128",
                        vc.query_fixed(leb128_chip.config.q_enable, Rotation::cur()),
                        1.expr(),
                    )
                }
            );

            cb.condition(
                is_mut_prop_expr.clone(),
                |bcb| {
                    bcb.require_in_set(
                        "is_mut_prop => byte_val is valid",
                        byte_val_expr.clone(),
                        MUTABILITY_VALUES.iter().map(|&v| v.expr()).collect_vec(),
                    )
                }
            );

            // is_items_count+ -> is_item+ (is_mod_name_len+ -> is_mod_name* -> is_import_name_len+ -> is_import_name* -> import_desc+)
            let importdesc_type_is_global_type_prev_expr = importdesc_type_chip.config.value_equals(ImportDescType::GlobalType, Rotation::prev())(vc);
            let importdesc_type_is_typeidx_expr = importdesc_type_chip.config.value_equals(ImportDescType::Typeidx, Rotation::cur())(vc);
            let importdesc_type_is_typeidx_next_expr = importdesc_type_chip.config.value_equals(ImportDescType::Typeidx, Rotation::next())(vc);
            let importdesc_type_is_mem_type_expr = importdesc_type_chip.config.value_equals(ImportDescType::MemType, Rotation::cur())(vc);
            let importdesc_type_is_mem_type_next_expr = importdesc_type_chip.config.value_equals(ImportDescType::MemType, Rotation::next())(vc);
            let importdesc_type_is_table_type_expr = importdesc_type_chip.config.value_equals(ImportDescType::TableType, Rotation::cur())(vc);
            let importdesc_type_is_table_type_next_expr = importdesc_type_chip.config.value_equals(ImportDescType::TableType, Rotation::next())(vc);
            let importdesc_type_is_global_type_expr = importdesc_type_chip.config.value_equals(ImportDescType::GlobalType, Rotation::cur())(vc);
            let importdesc_type_is_global_type_next_expr = importdesc_type_chip.config.value_equals(ImportDescType::GlobalType, Rotation::next())(vc);

            let limit_type_is_min_only_expr = limit_type_chip.config.value_equals(LimitType::MinOnly, Rotation::cur())(vc);
            let limit_type_is_min_max_expr = limit_type_chip.config.value_equals(LimitType::MinMax, Rotation::cur())(vc);

            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_items_count+ -> is_item+ (is_mod_name_len+ ...",
                and::expr([
                    is_items_count_expr.clone(),
                    importdesc_type_is_typeidx_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_items_count, is_mod_name_len, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_mod_name_len+ -> is_mod_name* -> is_import_name_len+",
                and::expr([
                    is_mod_name_len_expr.clone(),
                    importdesc_type_is_typeidx_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_mod_name_len, is_mod_name, is_import_name_len, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_mod_name* -> is_import_name_len+",
                and::expr([
                    is_mod_name_expr.clone(),
                    importdesc_type_is_typeidx_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_mod_name, is_import_name_len, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_import_name_len+ -> is_import_name* -> is_importdesc_type{1}",
                and::expr([
                    is_import_name_len_expr.clone(),
                    importdesc_type_is_typeidx_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_import_name_len, is_import_name, is_importdesc_type, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_import_name* -> is_importdesc_type{1}",
                and::expr([
                    is_import_name_expr.clone(),
                    importdesc_type_is_typeidx_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_import_name, is_importdesc_type, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_importdesc_type{1} -> is_importdesc_val+",
                and::expr([
                    is_importdesc_type_expr.clone(),
                    importdesc_type_is_typeidx_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_importdesc_val, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_importdesc_val+",
                and::expr([
                    is_importdesc_val_expr.clone(),
                    importdesc_type_is_typeidx_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_importdesc_val, is_mod_name_len ],
            );
            // importdesc_type{1}=3(ImportDescType::Globaltype): import_desc+(is_importdesc_type{1} -> is_importdesc_val+ -> is_mut_prop{1})
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_items_count+ -> is_item+ (is_mod_name_len+ ...",
                and::expr([
                    is_items_count_expr.clone(),
                    importdesc_type_is_global_type_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_items_count, is_mod_name_len, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_mod_name_len+ -> is_mod_name* -> is_import_name_len+",
                and::expr([
                    is_mod_name_len_expr.clone(),
                    importdesc_type_is_global_type_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_mod_name_len, is_mod_name, is_import_name_len, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_mod_name* -> is_import_name_len+",
                and::expr([
                    is_mod_name_expr.clone(),
                    importdesc_type_is_global_type_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_mod_name, is_import_name_len, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_import_name_len+ -> is_import_name* -> is_importdesc_type{1}",
                and::expr([
                    is_import_name_len_expr.clone(),
                    importdesc_type_is_global_type_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_import_name_len, is_import_name, is_importdesc_type, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_import_name* -> is_importdesc_type{1}",
                and::expr([
                    is_import_name_expr.clone(),
                    importdesc_type_is_global_type_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_import_name, is_importdesc_type, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_importdesc_type{1} -> is_importdesc_val+",
                and::expr([
                    is_importdesc_type_expr.clone(),
                    importdesc_type_is_global_type_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_importdesc_val, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_importdesc_val+ -> is_mut_prop{1}",
                and::expr([
                    is_importdesc_val_expr.clone(),
                    importdesc_type_is_global_type_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_importdesc_val, is_mut_prop, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_mut_prop{1}",
                and::expr([
                    is_mut_prop_expr.clone(),
                    importdesc_type_is_global_type_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_mod_name_len, ],
            );
            // importdesc_type{1}=ImportDescType::Memtype: import_desc+(is_importdesc_type{1} -> limit_type{1} -> limit_min+ -> limit_max*)
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_items_count+ -> is_item+ (is_mod_name_len+ ...",
                and::expr([
                    is_items_count_expr.clone(),
                    importdesc_type_is_mem_type_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_items_count, is_mod_name_len, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_mod_name_len+ -> is_mod_name* -> is_import_name_len+",
                and::expr([
                    is_mod_name_len_expr.clone(),
                    importdesc_type_is_mem_type_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_mod_name_len, is_mod_name, is_import_name_len, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_mod_name* -> is_import_name_len+",
                and::expr([
                    is_mod_name_expr.clone(),
                    importdesc_type_is_mem_type_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_mod_name, is_import_name_len, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_import_name_len+ -> is_import_name* -> is_importdesc_type{1}",
                and::expr([
                    is_import_name_len_expr.clone(),
                    importdesc_type_is_mem_type_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_import_name_len, is_import_name, is_importdesc_type, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_import_name* -> is_importdesc_type{1}",
                and::expr([
                    is_import_name_expr.clone(),
                    importdesc_type_is_mem_type_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_import_name, is_importdesc_type, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_importdesc_type{1} -> limit_type{1}",
                and::expr([
                    is_importdesc_type_expr.clone(),
                    importdesc_type_is_mem_type_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_limit_type, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: limit_type{1} -> limit_min+",
                and::expr([
                    is_limit_type_expr.clone(),
                    importdesc_type_is_mem_type_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_limit_min, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: limit_min+",
                and::expr([
                    is_limit_min_expr.clone(),
                    limit_type_is_min_only_expr.clone(),
                    importdesc_type_is_mem_type_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_limit_min, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: limit_min+ -> limit_max*",
                and::expr([
                    is_limit_min_expr.clone(),
                    limit_type_is_min_max_expr.clone(),
                    importdesc_type_is_mem_type_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_limit_min, is_limit_max ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: limit_max*",
                is_limit_max_expr.clone() * not_q_last_expr.clone(),
                true,
                &[is_limit_max, is_mod_name_len, ],
            );
            // importdesc_type{1}=ImportDescType::Tabletype: import_desc+(is_importdesc_type{1} -> ref_type{1} -> limit_type{1} -> limit_min+ -> limit_max*)
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_items_count+ -> is_item+ (is_mod_name_len+ ...",
                and::expr([
                    is_items_count_expr.clone(),
                    importdesc_type_is_table_type_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_items_count, is_mod_name_len, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_mod_name_len+ -> is_mod_name* -> is_import_name_len+",
                and::expr([
                    is_mod_name_len_expr.clone(),
                    importdesc_type_is_table_type_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_mod_name_len, is_mod_name, is_import_name_len, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_mod_name* -> is_import_name_len+",
                and::expr([
                    is_mod_name_expr.clone(),
                    importdesc_type_is_table_type_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_mod_name, is_import_name_len, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_import_name_len+ -> is_import_name* -> is_importdesc_type{1}",
                and::expr([
                    is_import_name_len_expr.clone(),
                    importdesc_type_is_table_type_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_import_name_len, is_import_name, is_importdesc_type, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_import_name* -> is_importdesc_type{1}",
                and::expr([
                    is_import_name_expr.clone(),
                    importdesc_type_is_table_type_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_import_name, is_importdesc_type, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_importdesc_type{1} -> ref_type{1}",
                and::expr([
                    is_importdesc_type_expr.clone(),
                    importdesc_type_is_table_type_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_ref_type, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: ref_type{1} -> limit_type{1}",
                and::expr([
                    is_ref_type_expr.clone(),
                    importdesc_type_is_table_type_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_limit_type, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: limit_type{1} -> limit_min+",
                and::expr([
                    is_limit_type_expr.clone(),
                    importdesc_type_is_table_type_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_limit_min, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: limit_min+",
                and::expr([
                    is_limit_min_expr.clone(),
                    limit_type_is_min_only_expr.clone(),
                    importdesc_type_is_table_type_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_limit_min, ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: limit_min+ -> limit_max*",
                and::expr([
                    is_limit_min_expr.clone(),
                    limit_type_is_min_max_expr.clone(),
                    importdesc_type_is_table_type_expr.clone(),
                    not_q_last_expr.clone(),
                ]),
                true,
                &[is_limit_min, is_limit_max ],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: limit_max*",
                is_limit_max_expr.clone() * not_q_last_expr.clone(),
                true,
                &[is_limit_max, is_mod_name_len, ],
            );

            cb.condition(
                is_importdesc_type_expr.clone(),
                |bcb| {
                    bcb.require_in_set(
                        "is_importdesc_type => value is valid",
                        byte_val_expr.clone(),
                        IMPORT_DESC_TYPE_VALUES.iter().map(|&v| v.expr()).collect_vec()
                    );
                    bcb.require_equal(
                        "is_importdesc_type => importdesc_type has valid value",
                        importdesc_type_expr.clone(),
                        byte_val_expr.clone(),
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
            q_first,
            q_last,
            is_items_count,
            is_mod_name_len,
            is_mod_name,
            is_import_name_len,
            is_import_name,
            is_importdesc_type,
            is_importdesc_type_ctx,
            is_importdesc_val,
            is_mut_prop,
            limit_type_fields,
            is_ref_type,
            leb128_chip,
            utf8_chip,
            dynamic_indexes_chip,
            importdesc_type,
            importdesc_type_chip,
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
            "import_section_body: assign at offset {} q_enable {} assign_types {:?} assign_value {} byte_val {:x?}",
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
                AssignType::IsModNameLen,
                AssignType::IsImportNameLen,
                AssignType::IsImportdescVal,
                AssignType::IsLimitMin,
                AssignType::IsLimitMax,
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
                        || format!("assign 'is_mut_prop' val {} at {}", assign_value, offset),
                        self.config.is_mut_prop,
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
                AssignType::IsLimitType => {
                    region.assign_fixed(
                        || format!("assign 'is_limit_type' val {} at {}", assign_value, offset),
                        self.config.limit_type_fields.is_limit_type,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsLimitMin => {
                    region.assign_fixed(
                        || format!("assign 'is_limit_min' val {} at {}", assign_value, offset),
                        self.config.limit_type_fields.is_limit_min,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsLimitMax => {
                    region.assign_fixed(
                        || format!("assign 'is_limit_max' val {} at {}", assign_value, offset),
                        self.config.limit_type_fields.is_limit_max,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::IsLimitTypeCtx => {
                    region.assign_fixed(
                        || format!("assign 'is_limit_type_ctx' val {} at {}", assign_value, offset),
                        self.config.limit_type_fields.is_limit_type_ctx,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                }
                AssignType::LimitType => {
                    region.assign_advice(
                        || format!("assign 'limit_type' val {} at {}", assign_value, offset),
                        self.config.limit_type_fields.limit_type,
                        offset,
                        || Value::known(F::from(assign_value)),
                    ).unwrap();
                    let limit_type: LimitType = (assign_value as u8).try_into().unwrap();
                    self.config.limit_type_fields.limit_type_chip.assign(
                        region,
                        offset,
                        &limit_type,
                    ).unwrap();
                }
                AssignType::IsRefType => {
                    region.assign_fixed(
                        || format!("assign 'is_ref_type' val {} at {}", assign_value, offset),
                        self.config.is_ref_type,
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
        self.assign(region, &wasm_bytecode, offset, &[AssignType::QFirst], 1, None);
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
            let importdesc_type_val = wasm_bytecode.bytes[offset];
            let importdesc_type: ImportDescType = importdesc_type_val.try_into().unwrap();
            let importdesc_type_val = importdesc_type_val as u64;
            if importdesc_type == ImportDescType::Typeidx { self.config.shared_state.borrow_mut().func_count += 1; }
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
                importdesc_type_val,
                None,
            );
            self.config.importdesc_type_chip.assign(region, offset, &importdesc_type).unwrap();
            offset += 1;

            // is_importdesc_val+
            match importdesc_type {
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
                            importdesc_type_val,
                            None,
                        );
                        self.config.importdesc_type_chip.assign(region, offset, &importdesc_type).unwrap();
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
                            importdesc_type_val,
                            None,
                        );
                        self.config.importdesc_type_chip.assign(region, offset, &importdesc_type).unwrap();
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
                            importdesc_type_val,
                            None,
                        );
                        self.config.importdesc_type_chip.assign(region, offset, &importdesc_type).unwrap();
                    }
                    offset += 1;
                }
                ImportDescType::MemType => {
                    // limit_type{1}
                    let limit_type_val = wasm_bytecode.bytes[offset];
                    let limit_type: LimitType = limit_type_val.try_into().unwrap();
                    let limit_type_val = limit_type_val as u64;
                    self.assign(
                        region,
                        wasm_bytecode,
                        offset,
                        &[AssignType::IsLimitType, AssignType::IsLimitTypeCtx],
                        1,
                        None,
                    );
                    self.assign(region, wasm_bytecode, offset, &[AssignType::LimitType], limit_type_val, None);
                    offset += 1;

                    // limit_min+
                    let (_limit_min, limit_min_leb_len) = self.markup_leb_section(
                        region,
                        wasm_bytecode,
                        offset,
                        &[AssignType::IsLimitMin, AssignType::IsLimitTypeCtx],
                    );
                    for offset in offset..offset + limit_min_leb_len {
                        self.assign(region, wasm_bytecode, offset, &[AssignType::LimitType], limit_type_val, None);
                    }
                    offset += limit_min_leb_len;

                    // limit_max*
                    if limit_type == LimitType::MinMax {
                        let (_limit_max, limit_max_leb_len) = self.markup_leb_section(
                            region,
                            wasm_bytecode,
                            offset,
                            &[AssignType::IsLimitMax, AssignType::IsLimitTypeCtx],
                        );
                        for offset in offset..offset + limit_max_leb_len {
                            self.assign(region, wasm_bytecode, offset, &[AssignType::LimitType], limit_type_val, None);
                        }
                        offset += limit_max_leb_len;
                    }
                }
                ImportDescType::TableType => {
                    // ref_type{1}
                    let ref_type_val = wasm_bytecode.bytes[offset];
                    let ref_type: RefType = ref_type_val.try_into().unwrap();
                    let ref_type_val = ref_type_val as u64;
                    self.assign(
                        region,
                        wasm_bytecode,
                        offset,
                        &[AssignType::IsRefType],
                        1,
                        None,
                    );
                    offset += 1;

                    // limit_type{1}
                    let limit_type_val = wasm_bytecode.bytes[offset];
                    let limit_type: LimitType = limit_type_val.try_into().unwrap();
                    let limit_type_val = limit_type_val as u64;
                    self.assign(
                        region,
                        wasm_bytecode,
                        offset,
                        &[AssignType::IsLimitType, AssignType::IsLimitTypeCtx],
                        1,
                        None,
                    );
                    self.assign(region, wasm_bytecode, offset, &[AssignType::LimitType], limit_type_val, None);
                    offset += 1;

                    // limit_min+
                    let (limit_min, limit_min_leb_len) = self.markup_leb_section(
                        region,
                        wasm_bytecode,
                        offset,
                        &[AssignType::IsLimitMin, AssignType::IsLimitTypeCtx],
                    );
                    for offset in offset..offset + limit_min_leb_len {
                        self.assign(region, wasm_bytecode, offset, &[AssignType::LimitType], limit_type_val, None);
                    }
                    offset += limit_min_leb_len;

                    // limit_max*
                    if limit_type == LimitType::MinMax {
                        let (limit_max, limit_max_leb_len) = self.markup_leb_section(
                            region,
                            wasm_bytecode,
                            offset,
                            &[AssignType::IsLimitMax, AssignType::IsLimitTypeCtx],
                        );
                        for offset in offset..offset + limit_max_leb_len {
                            self.assign(region, wasm_bytecode, offset, &[AssignType::LimitType], limit_type_val, None);
                        }
                        self.config.limit_type_fields.limit_type_params_lt_chip.assign(region, offset, F::from(limit_min), F::from(limit_max)).unwrap();
                        offset += limit_max_leb_len;
                    }
                }
            }
        }

        if offset != offset_start {
            self.assign(region, &wasm_bytecode, offset - 1, &[AssignType::QLast], 1, None);
        }

        Ok(offset)
    }
}