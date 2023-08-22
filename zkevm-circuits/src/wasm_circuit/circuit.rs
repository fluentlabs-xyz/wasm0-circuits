use std::{cell::RefCell, marker::PhantomData, rc::Rc};

use halo2_proofs::{
    circuit::{Chip, Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Fixed},
    poly::Rotation,
};
use log::debug;

use eth_types::Field;
use gadgets::{
    is_zero::{IsZeroChip, IsZeroInstruction},
    less_than::{LtChip, LtInstruction},
    util::{and, not, or, Expr},
};

use crate::{
    evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon},
    table::PoseidonTable,
    wasm_circuit::{
        bytecode::{bytecode::WasmBytecode, bytecode_table::WasmBytecodeTable},
        common::{
            configure_constraints_for_q_first_and_q_last, configure_transition_check,
            digit_char_to_number, wasm_compute_section_len, WasmAssignAwareChip,
            WasmBytecodeNumberAwareChip, WasmErrorAwareChip, WasmFuncCountAwareChip,
            WasmLenPrefixedBytesSpanAwareChip, WasmMarkupLeb128SectionAwareChip,
            WasmSharedStateAwareChip,
        },
        consts::{
            SECTION_ID_DEFAULT, WASM_MAGIC_PREFIX, WASM_MAGIC_PREFIX_LEN,
            WASM_MAGIC_PREFIX_START_INDEX, WASM_SECTIONS_START_INDEX, WASM_SECTION_ID_MAX,
            WASM_VERSION_PREFIX, WASM_VERSION_PREFIX_END_INDEX, WASM_VERSION_PREFIX_LEN,
            WASM_VERSION_PREFIX_START_INDEX,
        },
        error::{
            error_index_out_of_bounds, is_recoverable_error, remap_error_to_assign_at,
            remap_error_to_compute_value_at, remap_error_to_invalid_enum_value_at, Error,
        },
        leb128::{circuit::LEB128Chip, helpers::leb128_compute_last_byte_offset},
        sections::{
            code::body::circuit::WasmCodeSectionBodyChip,
            consts::LebParams,
            data::body::circuit::WasmDataSectionBodyChip,
            element::body::circuit::WasmElementSectionBodyChip,
            export::body::circuit::WasmExportSectionBodyChip,
            function::body::circuit::WasmFunctionSectionBodyChip,
            global::body::circuit::WasmGlobalSectionBodyChip,
            import::body::circuit::WasmImportSectionBodyChip,
            memory::body::circuit::WasmMemorySectionBodyChip,
            r#type::{
                body::circuit::WasmTypeSectionBodyChip, item::circuit::WasmTypeSectionItemChip,
            },
            start::body::circuit::WasmStartSectionBodyChip,
            table::body::circuit::WasmTableSectionBodyChip,
        },
        tables::{
            dynamic_indexes::{
                circuit::DynamicIndexesChip,
                types::{LookupArgsParams, Tag},
            },
            fixed_range::config::RangeTableConfig,
        },
        types::{
            AssignType, ControlInstruction, ErrorCode, ExportDescType, ImportDescType,
            NewOffsetType, NewWbOffsetType, OffsetType, SharedState, WasmSection,
        },
        utf8::circuit::UTF8Chip,
    },
};

pub struct WasmSectionConfig<F: Field> {
    _marker: PhantomData<F>,
}

#[derive(Debug, Clone)]
pub struct WasmConfig<F: Field> {
    pub wb_table: Rc<WasmBytecodeTable>,

    pub shared_state: Rc<RefCell<SharedState>>,

    bytecode_number: Column<Advice>,

    q_enable: Column<Fixed>,
    q_first: Column<Fixed>,
    q_last: Column<Fixed>,
    is_section_id: Column<Fixed>,
    is_section_len: Column<Fixed>,
    is_section_body: Column<Fixed>,

    section_id: Column<Advice>,

    leb128_chip: Rc<LEB128Chip<F>>,
    utf8_chip: Rc<UTF8Chip<F>>,
    wasm_type_section_item_chip: Rc<WasmTypeSectionItemChip<F>>,
    wasm_type_section_body_chip: Rc<WasmTypeSectionBodyChip<F>>,
    wasm_import_section_body_chip: Rc<WasmImportSectionBodyChip<F>>,
    wasm_function_section_body_chip: Rc<WasmFunctionSectionBodyChip<F>>,
    wasm_memory_section_body_chip: Rc<WasmMemorySectionBodyChip<F>>,
    wasm_export_section_body_chip: Rc<WasmExportSectionBodyChip<F>>,
    wasm_data_section_body_chip: Rc<WasmDataSectionBodyChip<F>>,
    wasm_global_section_body_chip: Rc<WasmGlobalSectionBodyChip<F>>,
    wasm_code_section_body_chip: Rc<WasmCodeSectionBodyChip<F>>,
    wasm_start_section_body_chip: Rc<WasmStartSectionBodyChip<F>>,
    wasm_table_section_body_chip: Rc<WasmTableSectionBodyChip<F>>,
    wasm_element_section_body_chip: Rc<WasmElementSectionBodyChip<F>>,
    section_id_lt_chip: LtChip<F, 1>,
    dynamic_indexes_chip: Rc<DynamicIndexesChip<F>>,
    magic_prefix_count: usize,
    index_at_magic_prefix: Vec<IsZeroChip<F>>,
    poseidon_table: PoseidonTable,
    range_table_config_0_256: RangeTableConfig<F, 0, 256>,
    section_id_range_table_config: RangeTableConfig<F, 0, { WASM_SECTION_ID_MAX + 1 }>,
    range_table_config_0_128: Rc<RangeTableConfig<F, 0, 128>>,

    func_count: Column<Advice>,
    block_depth_level: Column<Advice>,
    body_byte_rev_index_l1: Column<Advice>,
    body_byte_rev_index_l2: Column<Advice>,
    body_item_rev_count_l1: Column<Advice>,
    body_item_rev_count_l2: Column<Advice>,

    error_code: Column<Advice>,

    _marker: PhantomData<F>,
}

impl<F: Field> WasmConfig<F> {}

#[derive(Debug, Clone)]
pub struct WasmChip<F: Field> {
    pub config: WasmConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> WasmLenPrefixedBytesSpanAwareChip<F> for WasmChip<F> {}

impl<F: Field> WasmMarkupLeb128SectionAwareChip<F> for WasmChip<F> {}

impl<F: Field> WasmBytecodeNumberAwareChip<F> for WasmChip<F> {
    fn bytecode_number_col(&self) -> Column<Advice> {
        self.config.bytecode_number
    }
}

impl<F: Field> WasmErrorAwareChip<F> for WasmChip<F> {
    fn error_code_col(&self) -> Column<Advice> {
        self.config.error_code
    }
}

impl<F: Field> WasmSharedStateAwareChip<F> for WasmChip<F> {
    fn shared_state(&self) -> Rc<RefCell<SharedState>> {
        self.config.shared_state.clone()
    }
}

impl<F: Field> WasmFuncCountAwareChip<F> for WasmChip<F> {
    fn func_count_col(&self) -> Column<Advice> {
        self.config.func_count
    }
}

impl<F: Field> WasmAssignAwareChip<F> for WasmChip<F> {
    type AssignType = AssignType;

    fn assign_internal(
        &self,
        region: &mut Region<F>,
        wb: &WasmBytecode,
        wb_offset: usize,
        assign_delta: usize,
        assign_types: &[AssignType],
        assign_value: u64,
        leb_params: Option<LebParams>,
    ) -> Result<(), Error> {
        let q_enable = true;
        let assign_offset = wb_offset + assign_delta;
        debug!(
            "assign at {} q_enable {} assign_types {:?} assign_value {} byte_val {:x?}",
            assign_offset, q_enable, assign_types, assign_value, wb.bytes[wb_offset],
        );
        region
            .assign_fixed(
                || format!("assign 'q_enable' val {} at {}", q_enable, assign_offset),
                self.config.q_enable,
                assign_offset,
                || Value::known(F::from(q_enable as u64)),
            )
            .map_err(|v| Error::AssignAt(assign_offset))?;
        self.assign_bytecode_number(region, assign_offset, None)
            .map_err(|v| Error::AssignAt(assign_offset))?;

        for assign_type in assign_types {
            match assign_type {
                AssignType::Unknown => {
                    return Err(Error::FatalUnknownAssignTypeUsed(
                        "unknown assign type is an impossible situation".to_string(),
                    ))
                }
                AssignType::QFirst => {
                    region
                        .assign_fixed(
                            || {
                                format!(
                                    "assign 'q_first' val {} at {}",
                                    assign_value, assign_offset
                                )
                            },
                            self.config.q_first,
                            assign_offset,
                            || Value::known(F::from(assign_value)),
                        )
                        .map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::QLast => {
                    region
                        .assign_fixed(
                            || format!("assign 'q_last' val {} at {}", assign_value, assign_offset),
                            self.config.q_last,
                            assign_offset,
                            || Value::known(F::from(assign_value)),
                        )
                        .map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::IsSectionId => {
                    region
                        .assign_fixed(
                            || {
                                format!(
                                    "assign 'is_section_id' val {} at {}",
                                    assign_value, assign_offset
                                )
                            },
                            self.config.is_section_id,
                            assign_offset,
                            || Value::known(F::from(assign_value)),
                        )
                        .map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::IsSectionLen => {
                    region
                        .assign_fixed(
                            || {
                                format!(
                                    "assign 'is_section_len' val {} at {}",
                                    assign_value, assign_offset
                                )
                            },
                            self.config.is_section_len,
                            assign_offset,
                            || Value::known(F::from(assign_value)),
                        )
                        .map_err(remap_error_to_assign_at(assign_offset))?;
                    let p = leb_params.unwrap();
                    self.config
                        .leb128_chip
                        .assign(region, assign_offset, q_enable, p)?;
                }
                AssignType::IsSectionBody => {
                    region
                        .assign_fixed(
                            || {
                                format!(
                                    "assign 'is_section_body' val {} at {}",
                                    assign_value, assign_offset
                                )
                            },
                            self.config.is_section_body,
                            assign_offset,
                            || Value::known(F::from(assign_value)),
                        )
                        .map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::BodyByteRevIndexL1 => {
                    region
                        .assign_advice(
                            || {
                                format!(
                                    "assign 'body_byte_rev_index_l1' val {} at {}",
                                    assign_value, assign_offset
                                )
                            },
                            self.config.body_byte_rev_index_l1,
                            assign_offset,
                            || Value::known(F::from(assign_value)),
                        )
                        .map_err(remap_error_to_assign_at(assign_offset))?;
                }
                AssignType::ErrorCode => {
                    self.assign_error_code(region, assign_offset, None)?;
                }
            }
        }

        for (index, index_at_magic_prefix) in self.config.index_at_magic_prefix.iter().enumerate() {
            index_at_magic_prefix
                .assign(
                    region,
                    assign_offset,
                    Value::known(F::from(wb_offset as u64) - F::from(index as u64)),
                )
                .map_err(remap_error_to_assign_at(assign_offset))?;
        }

        Ok(())
    }
}

impl<F: Field> WasmChip<F> {
    pub fn load(
        &self,
        layouter: &mut impl Layouter<F>,
        wb: &WasmBytecode,
        assign_delta: usize,
    ) -> Result<NewOffsetType, Error> {
        let mut new_assign_offset = 0;
        // layouter
        //     .assign_region(
        //         || format!("wasm bytecode table at {}", assign_delta),
        //         |mut region| {
        new_assign_offset = self
            .config
            .wb_table
            .load(layouter, wb, assign_delta)
            .unwrap();
        // Ok(())
        // },
        // )
        // .unwrap();

        let assign_delta = assign_delta
            + if self.config.wb_table.zero_row_enabled {
                1
            } else {
                0
            };
        self.config
            .poseidon_table
            .dev_load(layouter, &[wb.bytes.clone()], assign_delta)
            .unwrap();

        Ok(new_assign_offset)
    }
    pub fn load_once(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        self.config.range_table_config_0_256.load(layouter).unwrap();
        self.config
            .section_id_range_table_config
            .load(layouter)
            .unwrap();
        self.config.range_table_config_0_128.load(layouter).unwrap();

        Ok(())
    }

    pub fn configure(
        cs: &mut ConstraintSystem<F>,
        wb_table: Rc<WasmBytecodeTable>,
        shared_state: Rc<RefCell<SharedState>>,
    ) -> WasmConfig<F> {
        let magic_prefix_count = WASM_MAGIC_PREFIX_LEN + WASM_VERSION_PREFIX_LEN;

        let bytecode_number = cs.advice_column();

        let q_enable = cs.fixed_column();
        let q_first = cs.fixed_column();
        let q_last = cs.fixed_column();
        let is_section_id = cs.fixed_column();
        let is_section_len = cs.fixed_column();
        let is_section_body = cs.fixed_column();

        let section_id = cs.advice_column();
        let func_count = cs.advice_column();
        let block_depth_level = cs.advice_column();
        let body_byte_rev_index_l1 = cs.advice_column();
        let body_byte_rev_index_l2 = cs.advice_column();
        let body_item_rev_count_l1 = cs.advice_column();
        let body_item_rev_count_l2 = cs.advice_column();

        let error_code = cs.advice_column();

        let range_table_config_0_256 = RangeTableConfig::configure(cs);
        let section_id_range_table_config = RangeTableConfig::configure(cs);
        let range_table_config_0_128 = Rc::new(RangeTableConfig::configure(cs));
        let poseidon_table = PoseidonTable::dev_construct(cs);

        let leb128_config = LEB128Chip::configure(cs, &wb_table.value);
        let mut leb128_chip = Rc::new(LEB128Chip::construct(leb128_config));

        let utf8_config =
            UTF8Chip::configure(cs, range_table_config_0_128.clone(), &wb_table.value);
        let mut utf8_chip = Rc::new(UTF8Chip::construct(utf8_config));

        let config = DynamicIndexesChip::configure(cs);
        let dynamic_indexes_chip = Rc::new(DynamicIndexesChip::construct(config));

        let config = WasmTypeSectionItemChip::configure(
            cs,
            wb_table.clone(),
            leb128_chip.clone(),
            func_count,
            shared_state.clone(),
            body_item_rev_count_l2,
            error_code,
        );
        let wasm_type_section_item_chip = Rc::new(WasmTypeSectionItemChip::construct(config));
        let config = WasmTypeSectionBodyChip::configure(
            cs,
            wb_table.clone(),
            leb128_chip.clone(),
            wasm_type_section_item_chip.clone(),
            dynamic_indexes_chip.clone(),
            func_count,
            shared_state.clone(),
            body_item_rev_count_l1,
            error_code,
        );
        let wasm_type_section_body_chip = Rc::new(WasmTypeSectionBodyChip::construct(config));

        let config = WasmImportSectionBodyChip::configure(
            cs,
            wb_table.clone(),
            leb128_chip.clone(),
            utf8_chip.clone(),
            dynamic_indexes_chip.clone(),
            func_count,
            shared_state.clone(),
            body_byte_rev_index_l2,
            body_item_rev_count_l1,
            error_code,
        );
        let wasm_import_section_body_chip = Rc::new(WasmImportSectionBodyChip::construct(config));

        let config = WasmFunctionSectionBodyChip::configure(
            cs,
            wb_table.clone(),
            leb128_chip.clone(),
            func_count,
            shared_state.clone(),
            body_item_rev_count_l1,
            error_code,
        );
        let wasm_function_section_body_chip =
            Rc::new(WasmFunctionSectionBodyChip::construct(config));

        let config = WasmMemorySectionBodyChip::configure(
            cs,
            wb_table.clone(),
            leb128_chip.clone(),
            dynamic_indexes_chip.clone(),
            func_count,
            shared_state.clone(),
            body_item_rev_count_l1,
            error_code,
            bytecode_number,
        );
        let wasm_memory_section_body_chip = Rc::new(WasmMemorySectionBodyChip::construct(config));

        let config = WasmExportSectionBodyChip::configure(
            cs,
            wb_table.clone(),
            leb128_chip.clone(),
            func_count,
            shared_state.clone(),
            body_byte_rev_index_l2,
            body_item_rev_count_l1,
            error_code,
        );
        let wasm_export_section_body_chip = Rc::new(WasmExportSectionBodyChip::construct(config));

        let config = WasmDataSectionBodyChip::configure(
            cs,
            wb_table.clone(),
            leb128_chip.clone(),
            dynamic_indexes_chip.clone(),
            func_count,
            shared_state.clone(),
            body_byte_rev_index_l2,
            body_item_rev_count_l1,
            error_code,
            bytecode_number,
        );
        let wasm_data_section_body_chip = Rc::new(WasmDataSectionBodyChip::construct(config));

        let config = WasmGlobalSectionBodyChip::configure(
            cs,
            wb_table.clone(),
            leb128_chip.clone(),
            dynamic_indexes_chip.clone(),
            func_count,
            shared_state.clone(),
            body_item_rev_count_l1,
            error_code,
            bytecode_number,
        );
        let wasm_global_section_body_chip = Rc::new(WasmGlobalSectionBodyChip::construct(config));

        let config = WasmCodeSectionBodyChip::configure(
            cs,
            wb_table.clone(),
            leb128_chip.clone(),
            dynamic_indexes_chip.clone(),
            func_count,
            shared_state.clone(),
            body_byte_rev_index_l2,
            body_item_rev_count_l1,
            error_code,
        );
        let wasm_code_section_body_chip = Rc::new(WasmCodeSectionBodyChip::construct(config));

        let config = WasmStartSectionBodyChip::configure(
            cs,
            wb_table.clone(),
            leb128_chip.clone(),
            func_count,
            shared_state.clone(),
            error_code,
        );
        let wasm_start_section_body_chip = Rc::new(WasmStartSectionBodyChip::construct(config));

        let config = WasmElementSectionBodyChip::configure(
            cs,
            wb_table.clone(),
            leb128_chip.clone(),
            func_count,
            shared_state.clone(),
            body_item_rev_count_l1,
            error_code,
        );
        let wasm_element_section_body_chip = Rc::new(WasmElementSectionBodyChip::construct(config));

        let config = WasmTableSectionBodyChip::configure(
            cs,
            wb_table.clone(),
            leb128_chip.clone(),
            dynamic_indexes_chip.clone(),
            func_count,
            error_code,
            shared_state.clone(),
        );
        let wasm_table_section_body_chip = Rc::new(WasmTableSectionBodyChip::construct(config));

        let mut index_at_magic_prefix: Vec<IsZeroChip<F>> = Vec::new();
        for index in 0..magic_prefix_count {
            let value_inv = cs.advice_column();
            let index_at_magic_prefix_config = IsZeroChip::configure(
                cs,
                |vc| {
                    and::expr([
                        vc.query_fixed(q_enable, Rotation::cur()),
                        not::expr(vc.query_fixed(q_first, Rotation::cur())),
                    ])
                },
                |vc| vc.query_advice(wb_table.index, Rotation::cur()) - index.expr(),
                value_inv,
            );
            let chip = IsZeroChip::construct(index_at_magic_prefix_config);
            index_at_magic_prefix.push(chip);
        }

        Self::configure_len_prefixed_bytes_span_checks(
            cs,
            leb128_chip.as_ref(),
            |vc| vc.query_fixed(is_section_body, Rotation::cur()),
            body_byte_rev_index_l1,
            |vc| {
                let not_q_last_expr = not::expr(vc.query_fixed(q_last, Rotation::cur()));
                let is_section_len_expr = vc.query_fixed(is_section_len, Rotation::cur());
                let is_section_body_next_expr = vc.query_fixed(is_section_body, Rotation::next());

                and::expr([
                    not_q_last_expr,
                    is_section_len_expr,
                    is_section_body_next_expr,
                ])
            },
            |vc| {
                let q_last_expr = vc.query_fixed(q_last, Rotation::cur());
                let is_section_body_expr = vc.query_fixed(is_section_body, Rotation::cur());
                let is_section_id_next_expr = vc.query_fixed(is_section_id, Rotation::next());

                or::expr([
                    q_last_expr,
                    and::expr([is_section_body_expr, is_section_id_next_expr]),
                ])
            },
        );

        Self::configure_error_code(cs, q_enable, q_first, q_last, error_code);

        Self::configure_bytecode_number(cs, q_enable, q_first, q_last, bytecode_number);

        cs.lookup("all bytecode values are byte values", |vc| {
            let q_enable_expr = Self::get_selector_expr_enriched_with_error_processing(
                vc,
                q_enable,
                &shared_state.borrow(),
                error_code,
            );

            let byte_value_expr = vc.query_advice(wb_table.value, Rotation::cur());

            vec![(
                q_enable_expr * byte_value_expr,
                range_table_config_0_256.value,
            )]
        });

        for (index, char) in WASM_MAGIC_PREFIX.chars().enumerate() {
            cs.lookup_any("byte_val=ord(specific_char) at index", |vc| {
                let q_enable_expr = Self::get_selector_expr_enriched_with_error_processing(
                    vc,
                    q_enable,
                    &shared_state.borrow(),
                    error_code,
                );
                let q_enable_expr =
                    q_enable_expr * not::expr(vc.query_fixed(q_first, Rotation::cur()));

                let bytecode_number_expr = vc.query_advice(bytecode_number, Rotation::cur());
                let byte_index_expr = vc.query_advice(wb_table.index, Rotation::cur());
                let byte_val_expr = vc.query_advice(wb_table.value, Rotation::cur());
                vec![
                    (
                        q_enable_expr.clone() * bytecode_number_expr.clone(),
                        bytecode_number_expr,
                    ),
                    (q_enable_expr.clone() * index.expr(), byte_index_expr),
                    (q_enable_expr.clone() * (char as i32).expr(), byte_val_expr),
                ]
            });
        }
        for index in WASM_VERSION_PREFIX_START_INDEX
            ..WASM_VERSION_PREFIX_START_INDEX + WASM_VERSION_PREFIX_LEN
        {
            let version_val = if index == WASM_VERSION_PREFIX_START_INDEX {
                1
            } else {
                0
            };
            cs.lookup_any("byte_val[index]=version_val[index]", |vc| {
                let q_enable_expr = Self::get_selector_expr_enriched_with_error_processing(
                    vc,
                    q_enable,
                    &shared_state.borrow(),
                    error_code,
                );
                let q_first_expr = vc.query_fixed(q_first, Rotation::cur());
                let not_q_first_expr = not::expr(q_first_expr.clone());
                let q_enable_expr = q_enable_expr * not_q_first_expr;

                let bytecode_number_expr = vc.query_advice(bytecode_number, Rotation::cur());
                let byte_index_expr = vc.query_advice(wb_table.index, Rotation::cur());
                let byte_val_expr = vc.query_advice(wb_table.value, Rotation::cur());
                vec![
                    (
                        q_enable_expr.clone() * bytecode_number_expr.clone(),
                        bytecode_number_expr,
                    ),
                    (q_enable_expr.clone() * index.expr(), byte_index_expr),
                    (q_enable_expr.clone() * version_val.expr(), byte_val_expr),
                ]
            });
        }

        let section_id_lt_chip_config = LtChip::configure(
            cs,
            |vc| {
                let q_enable_expr = Self::get_selector_expr_enriched_with_error_processing(
                    vc,
                    q_enable,
                    &shared_state.borrow(),
                    error_code,
                );
                let q_first_expr = vc.query_fixed(q_first, Rotation::cur());
                let not_q_first_expr = not::expr(q_first_expr.clone());

                and::expr([not_q_first_expr.clone(), q_enable_expr.clone()])
            },
            |vc| vc.query_advice(section_id, Rotation::prev()),
            |vc| vc.query_advice(section_id, Rotation::cur()),
        );
        let section_id_lt_chip = LtChip::construct(section_id_lt_chip_config);

        cs.create_gate("WasmCircuit gate", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = Self::get_selector_expr_enriched_with_error_processing(
                vc,
                q_enable,
                &shared_state.borrow(),
                error_code,
            );
            let q_first_expr = vc.query_fixed(q_first, Rotation::cur());
            let q_first_prev_expr = vc.query_fixed(q_first, Rotation::prev());
            let not_q_first_expr = not::expr(q_first_expr.clone());
            let not_q_first_prev_expr = not::expr(q_first_prev_expr.clone());
            let q_last_expr = vc.query_fixed(q_last, Rotation::cur());
            let not_q_last_expr = not::expr(q_last_expr.clone());

            let is_section_id_expr = vc.query_fixed(is_section_id, Rotation::cur());
            let is_section_len_expr = vc.query_fixed(is_section_len, Rotation::cur());
            let is_section_body_expr = vc.query_fixed(is_section_body, Rotation::cur());

            let index_val_expr = vc.query_advice(wb_table.index, Rotation::cur());
            let byte_val_expr = vc.query_advice(wb_table.value, Rotation::cur());

            let func_count_expr = vc.query_advice(func_count, Rotation::cur());

            let byte_index_expr = vc.query_advice(wb_table.index, Rotation::cur());
            let byte_index_next_expr = vc.query_advice(wb_table.index, Rotation::next());

            let section_id_expr = vc.query_advice(section_id, Rotation::cur());
            let section_id_prev_expr = vc.query_advice(section_id, Rotation::prev());

            let leb128_is_last_byte_expr =
                vc.query_fixed(leb128_chip.config.is_last_byte, Rotation::cur());

            let wb_table_code_hash = vc.query_advice(wb_table.code_hash, Rotation::cur());
            let poseidon_table_hash_id = vc.query_advice(poseidon_table.hash_id, Rotation::cur());

            cb.require_boolean("q_enable is boolean", q_enable_expr.clone());
            cb.require_boolean("is_section_id is boolean", is_section_id_expr.clone());
            cb.require_boolean("is_section_len is boolean", is_section_len_expr.clone());
            cb.require_boolean("is_section_body is boolean", is_section_body_expr.clone());

            cb.condition(
                q_first_expr.clone(),
                |cb| {
                    cb.require_zero("q_first => index=0", vc.query_advice(wb_table.index, Rotation::cur()));
                    cb.require_zero("q_first => value=0", vc.query_advice(wb_table.value, Rotation::cur()));
                    cb.require_zero("q_first => code_hash=0", vc.query_advice(wb_table.code_hash, Rotation::cur()));
                }
            );

            configure_constraints_for_q_first_and_q_last(
                &mut cb,
                vc,
                &q_enable,
                &q_first,
                &[],
                &q_last,
                &[],
            );

            cb.require_zero(
                "index=0 => q_first=1",
                and::expr([q_first_expr.clone(), index_val_expr.clone()]),
            );

            let mut is_index_at_magic_prefix_expr = index_at_magic_prefix.iter()
                .fold(0.expr(), |acc, x| { acc.clone() + x.config().expr() });

            cb.require_equal(
                "exactly one mark flag active at the same time",
                is_index_at_magic_prefix_expr.clone()
                    + is_section_id_expr.clone()
                    + is_section_len_expr.clone()
                    + is_section_body_expr.clone(),
                1.expr(),
            );

            // bytecode checks
            cb.condition(
                and::expr([not_q_first_expr.clone(), not_q_last_expr.clone()]),
                |cb| {
                    cb.require_equal(
                        "not_q_first && not_q_last => next.byte_index=cur.byte_index+1",
                        byte_index_expr.clone() + 1.expr(),
                        byte_index_next_expr.clone(),
                    );
                },
            );
            cb.condition(q_first_expr.clone(), |cb| {
                cb.require_zero("q_first => byte_index=0", byte_index_expr.clone());
            });

            // wasm magic prefix to sections transition check
            cb.condition(is_index_at_magic_prefix_expr.clone(), |cb| {
                cb.require_zero(
                    "bytecode[0..7] -> !is_section_id && !is_section_len && !is_section_body",
                    or::expr([
                        is_section_id_expr.clone(),
                        is_section_len_expr.clone(),
                        is_section_body_expr.clone(),
                    ]),
                )
            });
            cb.condition(not::expr(is_index_at_magic_prefix_expr.clone()), |cb| {
                cb.require_equal(
                    "not(bytecode[0..7]) -> one_of([is_section_id, is_section_len, is_section_body])=1",
                    is_section_id_expr.clone()
                        + is_section_len_expr.clone()
                        + is_section_body_expr.clone(),
                    1.expr(),
                )
            });
            cb.condition(is_section_body_expr.clone(), |cb| {
                cb.require_equal(
                    "is_section_body -> exactly one section chip is enabled",
                    vc.query_fixed(wasm_type_section_body_chip.config.q_enable, Rotation::cur())
                        + vc.query_fixed(
                        wasm_import_section_body_chip.config.q_enable,
                        Rotation::cur(),
                    )
                        + vc.query_fixed(
                        wasm_function_section_body_chip.config.q_enable,
                        Rotation::cur(),
                    )
                        + vc.query_fixed(
                        wasm_memory_section_body_chip.config.q_enable,
                        Rotation::cur(),
                    )
                        + vc.query_fixed(
                        wasm_export_section_body_chip.config.q_enable,
                        Rotation::cur(),
                    )
                        + vc.query_fixed(
                        wasm_data_section_body_chip.config.q_enable,
                        Rotation::cur(),
                    )
                        + vc.query_fixed(
                        wasm_global_section_body_chip.config.q_enable,
                        Rotation::cur(),
                    )
                        + vc.query_fixed(
                        wasm_code_section_body_chip.config.q_enable,
                        Rotation::cur(),
                    )
                        + vc.query_fixed(
                        wasm_start_section_body_chip.config.q_enable,
                        Rotation::cur(),
                    )
                        + vc.query_fixed(
                        wasm_table_section_body_chip.config.q_enable,
                        Rotation::cur(),
                    )
                        + vc.query_fixed(
                        wasm_element_section_body_chip.config.q_enable,
                        Rotation::cur(),
                    )
                        + is_section_id_expr.clone()
                        + is_section_len_expr.clone(),
                    1.expr(),
                );
            });
            // func_count constraints
            cb.condition(q_first_expr.clone(), |cb| {
                cb.require_zero("q_first => func_count=0", func_count_expr.clone());
            });
            let importdesc_type_is_typeidx_expr = and::expr([
                vc.query_fixed(
                    wasm_import_section_body_chip.config.is_importdesc_type,
                    Rotation::cur(),
                ),
                wasm_import_section_body_chip
                    .config
                    .importdesc_type_chip
                    .config
                    .value_equals(ImportDescType::Typeidx, Rotation::cur())(vc),
            ]);
            let wasm_code_section_q_first_expr =
                vc.query_fixed(wasm_code_section_body_chip.config.q_first, Rotation::cur());
            let not_func_count_inc_expr = and::expr([
                not::expr(importdesc_type_is_typeidx_expr.clone()),
                not::expr(wasm_code_section_q_first_expr.clone()),
            ]);
            cb.condition(
                and::expr([not_q_first_expr.clone(), not_func_count_inc_expr.clone()]),
                |cb| {
                    let func_count_prev_expr = vc.query_advice(func_count, Rotation::prev());
                    cb.require_equal(
                        "not_q_first && not_func_count_inc => prev.func_count=func_count",
                        func_count_prev_expr.clone(),
                        func_count_expr.clone(),
                    );
                },
            );
            cb.condition(importdesc_type_is_typeidx_expr.clone(), |cb| {
                let func_count_prev_expr = vc.query_advice(func_count, Rotation::prev());
                cb.require_equal(
                    "importdesc_type_is_typeidx => func_count increased by 1",
                    func_count_prev_expr.clone() + 1.expr(),
                    func_count_expr.clone(),
                );
            });
            cb.condition(wasm_code_section_q_first_expr.clone(), |cb| {
                let func_count_prev_expr = vc.query_advice(func_count, Rotation::prev());
                let wasm_code_section_leb128_sn_expr = vc.query_advice(
                    wasm_code_section_body_chip.config.leb128_chip.config.sn,
                    Rotation::cur(),
                );
                cb.require_equal(
                    "wasm_code_section_q_first => func_count grew by specific number",
                    func_count_prev_expr.clone() + wasm_code_section_leb128_sn_expr.clone(),
                    func_count_expr.clone(),
                );
            });

            // wasm section layout check
            cb.condition(
                index_at_magic_prefix[WASM_VERSION_PREFIX_END_INDEX].config().expr(),
                |cb| {
                    let is_section_id_next_expr = vc.query_fixed(is_section_id, Rotation::next());
                    cb.require_equal(
                        "prev.bytecode.index=WASM_VERSION_PREFIX_END_INDEX -> is_section_id",
                        is_section_id_next_expr.clone(),
                        1.expr(),
                    )
                }
            );
            // section+(is_section_id{1} -> is_section_len+ -> is_section_body+)
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_section_id{1} -> is_section_len+",
                and::expr([not_q_last_expr.clone(), is_section_id_expr.clone()]),
                true,
                &[is_section_len],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_section_len+ -> is_section_body+",
                and::expr([not_q_last_expr.clone(), is_section_len_expr.clone()]),
                true,
                &[is_section_len, is_section_body],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next (last leb byte): is_section_len+ -> is_section_body+",
                and::expr([
                    not_q_last_expr.clone(),
                    leb128_is_last_byte_expr.clone(),
                    is_section_len_expr.clone(),
                ]),
                true,
                &[is_section_body],
            );
            configure_transition_check(
                &mut cb,
                vc,
                "check next: is_section_body+ -> is_section_id{1} || q_last",
                and::expr([not_q_last_expr.clone(), is_section_body_expr.clone()]),
                true,
                &[is_section_body, is_section_id],
            );
            cb.condition(is_section_id_expr.clone(), |cb| {
                cb.require_equal(
                    "is_section_id -> section_id=byte_value",
                    section_id_expr.clone(),
                    byte_val_expr.clone(),
                )
            });
            cb.condition(and::expr([
                not_q_first_expr.clone(),
                not_q_first_prev_expr.clone(),
            ]), |cb| {
                cb.require_equal(
                    "prev.hash = cur.hash",
                    vc.query_advice(wb_table.code_hash, Rotation::prev()),
                    vc.query_advice(wb_table.code_hash, Rotation::cur()),
                );
            });

            // for the first 8 bytes section_id=SECTION_ID_DEFAULT
            for i in 0..WASM_SECTIONS_START_INDEX {
                cb.require_zero(
                    "id of section equals to default at magic prefix indexes",
                    index_at_magic_prefix[i].config().expr() * (section_id_expr.clone() - SECTION_ID_DEFAULT.expr()),
                );
            }

            cb.condition(not_q_first_expr.clone(), |cb| {
                cb.require_zero(
                    "prev.section_id <= cur.section_id",
                    (section_id_lt_chip.config().is_lt(vc, None) - 1.expr())
                        * (section_id_expr.clone() - section_id_prev_expr.clone()),
                );
            });

            // code_hash check
            // TODO refactor
            // cb.require_zero(
            //     "code hashes match",
            //     index_at_magic_prefix[2].config().expr()
            //         * (wb_table_code_hash.clone() - poseidon_table_hash_id.clone()),
            // );

            cb.gate(q_enable_expr)
        });

        cs.lookup("section_id is a valid number", |vc| {
            let q_enable_expr = Self::get_selector_expr_enriched_with_error_processing(
                vc,
                q_enable,
                &shared_state.borrow(),
                error_code,
            );

            let section_id_expr = vc.query_advice(section_id, Rotation::cur());

            vec![(
                q_enable_expr * section_id_expr,
                section_id_range_table_config.value,
            )]
        });

        // start section crosschecks
        dynamic_indexes_chip.lookup_args("start section: func index refs are valid", cs, |vc| {
            let q_enable_expr = Self::get_selector_expr_enriched_with_error_processing(
                vc,
                q_enable,
                &shared_state.borrow(),
                error_code,
            );
            let cond = vc.query_fixed(
                wasm_start_section_body_chip.config.is_func_index,
                Rotation::cur(),
            ) * q_enable_expr;
            let sn_expr = vc.query_advice(
                wasm_start_section_body_chip.config.leb128_chip.config.sn,
                Rotation::cur(),
            );
            let bytecode_number_expr = vc.query_advice(bytecode_number, Rotation::cur());

            LookupArgsParams {
                cond,
                bytecode_number: bytecode_number_expr,
                index: sn_expr,
                tag: Tag::FuncIndex.expr(),
                is_terminator: false.expr(),
            }
        });
        // import section crosschecks
        dynamic_indexes_chip.lookup_args("import section: typeidx refs are valid", cs, |vc| {
            let cond = and::expr([
                vc.query_fixed(
                    wasm_import_section_body_chip.config.is_importdesc_type,
                    Rotation::cur(),
                ),
                wasm_import_section_body_chip
                    .config
                    .importdesc_type_chip
                    .config
                    .value_equals(ImportDescType::Typeidx, Rotation::cur())(vc),
            ]);
            let cond = cond
                * Self::get_selector_expr_enriched_with_error_processing(
                    vc,
                    q_enable,
                    &shared_state.borrow(),
                    error_code,
                );
            let bytecode_number_expr = vc.query_advice(bytecode_number, Rotation::cur());

            LookupArgsParams {
                cond,
                bytecode_number: bytecode_number_expr,
                index: vc.query_advice(leb128_chip.config.sn, Rotation::next()),
                tag: Tag::TypeIndex.expr(),
                is_terminator: false.expr(),
            }
        });
        // export section crosschecks
        dynamic_indexes_chip.lookup_args("export section: funcidx refs are valid", cs, |vc| {
            let cond = and::expr([
                vc.query_fixed(
                    wasm_export_section_body_chip.config.is_exportdesc_type,
                    Rotation::cur(),
                ),
                wasm_export_section_body_chip
                    .config
                    .exportdesc_type_chip
                    .config
                    .value_equals(ExportDescType::Funcidx, Rotation::cur())(vc),
            ]);
            let cond = cond
                * Self::get_selector_expr_enriched_with_error_processing(
                    vc,
                    q_enable,
                    &shared_state.borrow(),
                    error_code,
                );
            let bytecode_number_expr = vc.query_advice(bytecode_number, Rotation::cur());

            LookupArgsParams {
                cond,
                bytecode_number: bytecode_number_expr,
                index: vc.query_advice(leb128_chip.config.sn, Rotation::next()),
                tag: Tag::TypeIndex.expr(),
                is_terminator: false.expr(),
            }
        });
        dynamic_indexes_chip.lookup_args("export section: tableidx refs are valid", cs, |vc| {
            let cond = and::expr([
                vc.query_fixed(
                    wasm_export_section_body_chip.config.is_exportdesc_type,
                    Rotation::cur(),
                ),
                wasm_export_section_body_chip
                    .config
                    .exportdesc_type_chip
                    .config
                    .value_equals(ExportDescType::Tableidx, Rotation::cur())(vc),
            ]);
            let cond = cond
                * Self::get_selector_expr_enriched_with_error_processing(
                    vc,
                    q_enable,
                    &shared_state.borrow(),
                    error_code,
                );
            let bytecode_number_expr = vc.query_advice(bytecode_number, Rotation::cur());

            LookupArgsParams {
                cond,
                bytecode_number: bytecode_number_expr,
                index: vc.query_advice(leb128_chip.config.sn, Rotation::next()),
                tag: Tag::TableIndex.expr(),
                is_terminator: false.expr(),
            }
        });
        dynamic_indexes_chip.lookup_args("export section: memidx refs are valid", cs, |vc| {
            let cond = and::expr([
                vc.query_fixed(
                    wasm_export_section_body_chip.config.is_exportdesc_type,
                    Rotation::cur(),
                ),
                wasm_export_section_body_chip
                    .config
                    .exportdesc_type_chip
                    .config
                    .value_equals(ExportDescType::Memidx, Rotation::cur())(vc),
            ]);
            let cond = cond
                * Self::get_selector_expr_enriched_with_error_processing(
                    vc,
                    q_enable,
                    &shared_state.borrow(),
                    error_code,
                );
            let bytecode_number_expr = vc.query_advice(bytecode_number, Rotation::cur());

            LookupArgsParams {
                cond,
                bytecode_number: bytecode_number_expr,
                index: vc.query_advice(leb128_chip.config.sn, Rotation::next()),
                tag: Tag::MemIndex.expr(),
                is_terminator: false.expr(),
            }
        });
        dynamic_indexes_chip.lookup_args("export section: globalidx refs are valid", cs, |vc| {
            let cond = and::expr([
                vc.query_fixed(
                    wasm_export_section_body_chip.config.is_exportdesc_type,
                    Rotation::cur(),
                ),
                wasm_export_section_body_chip
                    .config
                    .exportdesc_type_chip
                    .config
                    .value_equals(ExportDescType::Globalidx, Rotation::cur())(vc),
            ]);
            let cond = cond
                * Self::get_selector_expr_enriched_with_error_processing(
                    vc,
                    q_enable,
                    &shared_state.borrow(),
                    error_code,
                );
            let bytecode_number_expr = vc.query_advice(bytecode_number, Rotation::cur());

            LookupArgsParams {
                cond,
                bytecode_number: bytecode_number_expr,
                index: vc.query_advice(leb128_chip.config.sn, Rotation::next()),
                tag: Tag::GlobalIndex.expr(),
                is_terminator: false.expr(),
            }
        });
        // func section crosschecks
        dynamic_indexes_chip.lookup_args("function section: funcidx refs are valid", cs, |vc| {
            let cond = and::expr([vc.query_fixed(
                wasm_function_section_body_chip.config.is_typeidx,
                Rotation::cur(),
            )]);
            let cond = cond
                * Self::get_selector_expr_enriched_with_error_processing(
                    vc,
                    q_enable,
                    &shared_state.borrow(),
                    error_code,
                );
            let bytecode_number_expr = vc.query_advice(bytecode_number, Rotation::cur());

            LookupArgsParams {
                cond,
                bytecode_number: bytecode_number_expr,
                index: vc.query_advice(leb128_chip.config.sn, Rotation::next()),
                tag: Tag::TypeIndex.expr(),
                is_terminator: false.expr(),
            }
        });
        // data section crosschecks
        dynamic_indexes_chip.lookup_args("data section: memidx refs are valid", cs, |vc| {
            let cond = vc.query_fixed(
                wasm_data_section_body_chip.config.is_memidx,
                Rotation::cur(),
            );
            let cond = cond
                * Self::get_selector_expr_enriched_with_error_processing(
                    vc,
                    q_enable,
                    &shared_state.borrow(),
                    error_code,
                );
            let bytecode_number_expr = vc.query_advice(bytecode_number, Rotation::cur());

            LookupArgsParams {
                cond,
                bytecode_number: bytecode_number_expr,
                index: vc.query_advice(leb128_chip.config.sn, Rotation::next()),
                tag: Tag::MemIndex.expr(),
                is_terminator: false.expr(),
            }
        });
        // code section crosschecks
        dynamic_indexes_chip.lookup_args(
            "code section has valid setup for func indexes",
            cs,
            |vc| {
                let q_enable_expr = Self::get_selector_expr_enriched_with_error_processing(
                    vc,
                    q_enable,
                    &shared_state.borrow(),
                    error_code,
                );
                let q_last_expr = vc.query_fixed(q_last, Rotation::cur());
                let cond = and::expr([q_last_expr, q_enable_expr]);
                let bytecode_number_expr = vc.query_advice(bytecode_number, Rotation::cur());

                LookupArgsParams {
                    cond,
                    bytecode_number: bytecode_number_expr,
                    index: vc.query_advice(func_count, Rotation::cur()),
                    tag: Tag::FuncIndex.expr(),
                    is_terminator: true.expr(),
                }
            },
        );
        dynamic_indexes_chip.lookup_args("code section: call opcode param is valid", cs, |vc| {
            let cond = and::expr([
                vc.query_fixed(
                    wasm_code_section_body_chip.config.is_control_instruction,
                    Rotation::cur(),
                ),
                wasm_code_section_body_chip
                    .config
                    .control_instruction_chip
                    .config
                    .value_equals(ControlInstruction::Call, Rotation::cur())(vc),
            ]);
            let cond = cond
                * Self::get_selector_expr_enriched_with_error_processing(
                    vc,
                    q_enable,
                    &shared_state.borrow(),
                    error_code,
                );
            let bytecode_number_expr = vc.query_advice(bytecode_number, Rotation::cur());

            LookupArgsParams {
                cond,
                bytecode_number: bytecode_number_expr,
                index: vc.query_advice(leb128_chip.config.sn, Rotation::next()),
                tag: Tag::FuncIndex.expr(),
                is_terminator: false.expr(),
            }
        });

        let config = WasmConfig {
            _marker: PhantomData,

            bytecode_number,
            poseidon_table,
            wb_table,
            q_enable,
            q_first,
            q_last,
            range_table_config_0_256,
            section_id_range_table_config,
            index_at_magic_prefix,
            magic_prefix_count,
            section_id,
            is_section_id,
            is_section_len,
            is_section_body,
            leb128_chip,
            utf8_chip,
            wasm_type_section_item_chip,
            wasm_type_section_body_chip,
            wasm_import_section_body_chip,
            wasm_function_section_body_chip,
            wasm_memory_section_body_chip,
            wasm_export_section_body_chip,
            wasm_data_section_body_chip,
            wasm_global_section_body_chip,
            wasm_code_section_body_chip,
            wasm_start_section_body_chip,
            wasm_table_section_body_chip,
            wasm_element_section_body_chip,
            section_id_lt_chip,
            range_table_config_0_128,
            dynamic_indexes_chip,
            shared_state,
            func_count,
            block_depth_level,
            body_byte_rev_index_l1,
            body_byte_rev_index_l2,
            body_item_rev_count_l1,
            body_item_rev_count_l2,
            error_code,
        };

        config
    }

    pub fn construct(config: WasmConfig<F>) -> Self {
        let instance = Self {
            config,
            _marker: PhantomData,
        };
        instance
    }

    pub fn assign_auto(
        &mut self,
        region: &mut Region<F>,
        wb: &WasmBytecode,
        wb_offset: usize,
        assign_delta: usize,
    ) -> Result<NewWbOffsetType, Error> {
        let result = self.assign_auto_internal(region, wb, wb_offset, assign_delta);
        let assign_delta = assign_delta
            + if self.config.wb_table.zero_row_enabled {
                1
            } else {
                0
            };

        if let Err(e) = result {
            return if is_recoverable_error(&e)
                & self.config.shared_state.borrow().error_processing_enabled
            {
                debug!("detected recoverable error: {:?}", e);
                match e {
                    Error::IndexOutOfBoundsAt(offset) |
                    Error::AssignAt(offset) |
                    Error::ParseOpcodeFailedAt(offset) |
                    Error::InvalidByteValueAt(offset) |
                    Error::InvalidEnumValueAt(offset) |
                    Error::ComputeValueAt(offset) => {
                        debug!("recoverable error offset: {}", offset);
                        self.shared_state().borrow_mut().error_code = ErrorCode::Error as u64;
                        // cannot use offset received from error because of forward checks 
                        // and also structure markups happen after return with error 
                        for offset in 0..wb.bytes.len() {
                            self.assign(region, wb, offset, assign_delta, &[AssignType::ErrorCode], ErrorCode::Error as u64, None)?;
                        }
                    }

                    Error::IndexOutOfBoundsSimple
                    | Error::Leb128EncodeSigned
                    | Error::Leb128EncodeUnsigned
                    | Error::Leb128MaxBytes
                    | Error::InvalidEnumValue
                    | Error::ComputationFailed => {
                        return Err(Error::FatalRecoverableButNotProcessed(
                            "recoverable error without offset param must be converted inside circuit to sustain error processing mechanics".to_string()
                        ))
                    }

                    _ => return Err(e)
                }

                Ok(wb.bytes.len() + assign_delta)
            } else {
                Err(e)
            };
        }

        return Ok(wb.bytes.len() + assign_delta);
    }

    fn assign_auto_internal(
        &mut self,
        region: &mut Region<F>,
        wb: &WasmBytecode,
        wb_offset: usize,
        assign_delta: usize,
    ) -> Result<OffsetType, Error> {
        debug!("wb.bytes {:x?}", wb.bytes);
        self.assign(
            region,
            wb,
            wb_offset,
            assign_delta,
            &[AssignType::QFirst],
            1,
            None,
        )?;
        let assign_delta = assign_delta
            + if self.config.wb_table.zero_row_enabled {
                1
            } else {
                0
            };
        self.assign(
            region,
            wb,
            wb_offset + wb.bytes.len() - 1,
            assign_delta,
            &[AssignType::QLast],
            1,
            None,
        )?;

        // check magic prefix and version
        let assign_offset_start = wb_offset + WASM_MAGIC_PREFIX_START_INDEX + assign_delta;
        for (idx, ch) in WASM_MAGIC_PREFIX.chars().enumerate() {
            let wb_offset = wb_offset + WASM_MAGIC_PREFIX_START_INDEX + idx;
            let assign_offset = wb_offset + assign_delta;
            self.assign(region, &wb, wb_offset, assign_delta, &[], 1, None)?;
            let byte_val = *wb
                .bytes
                .get(wb_offset)
                .ok_or(Error::IndexOutOfBoundsAt(assign_offset_start))?;
            if byte_val != (ch as u8) {
                return Err(Error::InvalidByteValueAt(assign_offset_start));
            }
        }
        let assign_offset_start = wb_offset + WASM_VERSION_PREFIX_START_INDEX + assign_delta;
        for (idx, ch) in WASM_VERSION_PREFIX.chars().enumerate() {
            let wb_offset = wb_offset + WASM_VERSION_PREFIX_START_INDEX + idx;
            let assign_offset = wb_offset + assign_delta;
            self.assign(region, &wb, wb_offset, assign_delta, &[], 1, None)?;
            let byte_val = *wb
                .bytes
                .get(wb_offset)
                .ok_or(Error::IndexOutOfBoundsAt(assign_offset_start))?;
            if byte_val != digit_char_to_number(&ch) {
                return Err(Error::InvalidByteValueAt(assign_offset_start));
            }
        }

        let mut wb_offset = WASM_SECTIONS_START_INDEX;
        let mut section_id_prev: i64 = SECTION_ID_DEFAULT as i64;
        while wb_offset < wb.bytes.len() {
            let section_start_offset = wb_offset;
            let section_len_start_offset = section_start_offset + 1;
            let section_id = *wb
                .get(wb_offset)
                .ok_or(error_index_out_of_bounds(wb_offset + assign_delta))?
                as u64;
            wb_offset += 1;
            let (section_len, section_len_leb_bytes_count) =
                wasm_compute_section_len(&wb.bytes, wb_offset)
                    .map_err(remap_error_to_compute_value_at(wb_offset + assign_delta))?;
            wb_offset += section_len_leb_bytes_count as usize;
            wb_offset += section_len;
            let section_body_start_offset =
                section_len_start_offset + section_len_leb_bytes_count as usize;
            let section_len_end_offset = section_body_start_offset - 1;
            let section_body_end_offset =
                section_start_offset + section_len_leb_bytes_count as usize + section_len;
            let section_end_offset = section_body_end_offset;

            for wb_offset in section_start_offset..=section_end_offset {
                if wb_offset == section_start_offset {
                    let wasm_section: WasmSection = (section_id as i32).try_into().map_err(
                        remap_error_to_invalid_enum_value_at(wb_offset + assign_delta),
                    )?;
                    debug!(
                        "wasm_section {:?}(id={}) at offset {} (assign_offset {}) offset_end {} (assign_offset {}) section_len {} bytecode(hex) {:x?}",
                        wasm_section,
                        section_id,
                        wb_offset,
                        wb_offset+assign_delta,
                        wb_offset+section_len-1,
                        wb_offset+section_len-1+assign_delta,
                        section_len,
                        &wb.bytes[section_start_offset..=section_end_offset],
                    );
                    self.assign_func_count(region, wb_offset + assign_delta)?;

                    let mut next_section_offset = 0;
                    let section_body_offset = wb_offset + 1; // skip section_id
                    let section_len_last_byte_offset =
                        leb128_compute_last_byte_offset(&wb.bytes[..], section_body_offset)
                            .map_err(remap_error_to_compute_value_at(
                                section_body_offset + assign_delta,
                            ))?;
                    for offset in section_len_last_byte_offset..=section_body_end_offset {
                        self.assign(
                            region,
                            &wb,
                            offset,
                            assign_delta,
                            &[AssignType::BodyByteRevIndexL1],
                            (section_body_end_offset - offset) as u64,
                            None,
                        )?;
                    }
                    for offset in section_body_offset..=section_len_last_byte_offset {
                        self.assign_func_count(region, offset + assign_delta)?;
                    }
                    let section_body_offset = section_len_last_byte_offset + 1;
                    match wasm_section {
                        WasmSection::Type => {
                            next_section_offset = self
                                .config
                                .wasm_type_section_body_chip
                                .assign_auto(region, wb, section_body_offset, assign_delta)
                                .map_err(remap_error_to_assign_at(wb_offset + assign_delta))?;
                        }
                        WasmSection::Import => {
                            next_section_offset = self
                                .config
                                .wasm_import_section_body_chip
                                .assign_auto(region, wb, section_body_offset, assign_delta)
                                .map_err(remap_error_to_assign_at(wb_offset + assign_delta))?;
                        }
                        WasmSection::Function => {
                            next_section_offset = self
                                .config
                                .wasm_function_section_body_chip
                                .assign_auto(region, wb, section_body_offset, assign_delta)
                                .map_err(remap_error_to_assign_at(wb_offset + assign_delta))?;
                        }
                        WasmSection::Table => {
                            next_section_offset = self
                                .config
                                .wasm_table_section_body_chip
                                .assign_auto(region, wb, section_body_offset, assign_delta)
                                .map_err(remap_error_to_assign_at(wb_offset + assign_delta))?;
                        }
                        WasmSection::Memory => {
                            next_section_offset = self
                                .config
                                .wasm_memory_section_body_chip
                                .assign_auto(region, wb, section_body_offset, assign_delta)
                                .map_err(remap_error_to_assign_at(wb_offset + assign_delta))?;
                        }
                        WasmSection::Global => {
                            next_section_offset = self
                                .config
                                .wasm_global_section_body_chip
                                .assign_auto(region, wb, section_body_offset, assign_delta)
                                .map_err(remap_error_to_assign_at(wb_offset + assign_delta))?;
                        }
                        WasmSection::Export => {
                            next_section_offset = self
                                .config
                                .wasm_export_section_body_chip
                                .assign_auto(region, wb, section_body_offset, assign_delta)
                                .map_err(remap_error_to_assign_at(wb_offset + assign_delta))?;
                        }
                        WasmSection::Start => {
                            next_section_offset = self
                                .config
                                .wasm_start_section_body_chip
                                .assign_auto(region, wb, section_body_offset, assign_delta)
                                .map_err(remap_error_to_assign_at(wb_offset + assign_delta))?;
                        }
                        WasmSection::Element => {
                            next_section_offset = self
                                .config
                                .wasm_element_section_body_chip
                                .assign_auto(region, wb, section_body_offset, assign_delta)
                                .map_err(remap_error_to_assign_at(wb_offset + assign_delta))?;
                        }
                        WasmSection::Code => {
                            next_section_offset = self
                                .config
                                .wasm_code_section_body_chip
                                .assign_auto(region, wb, section_body_offset, assign_delta)
                                .map_err(remap_error_to_assign_at(wb_offset + assign_delta))?;
                        }
                        WasmSection::Data => {
                            next_section_offset = self
                                .config
                                .wasm_data_section_body_chip
                                .assign_auto(region, wb, section_body_offset, assign_delta)
                                .map_err(remap_error_to_assign_at(wb_offset + assign_delta))?;
                        }
                        _ => {
                            return Err(Error::FatalUnsupportedValue(format!(
                                "unsupported section value '{:x?}'",
                                wasm_section
                            )))
                        }
                    }
                    debug!(
                        "wasm_section {:?} section_body_offset {} after assign_auto next_section_offset {}",
                        wasm_section,
                        section_body_offset,
                        next_section_offset,
                    );
                }
                region
                    .assign_advice(
                        || format!("assign at {} section_id val {}", wb_offset, section_id),
                        self.config.section_id,
                        wb_offset + assign_delta,
                        || Value::known(F::from(section_id)),
                    )
                    .map_err(remap_error_to_assign_at(wb_offset))?;
                self.config
                    .section_id_lt_chip
                    .assign(
                        region,
                        wb_offset + assign_delta,
                        F::from(section_id_prev as u64),
                        F::from(section_id),
                    )
                    .map_err(remap_error_to_assign_at(wb_offset + assign_delta))?;
                section_id_prev = section_id as i64;
            }

            self.assign(
                region,
                wb,
                section_start_offset,
                assign_delta,
                &[AssignType::IsSectionId],
                1,
                None,
            )?;

            let (_section_len, _section_len_leb_len) = self.markup_leb_section(
                region,
                &wb,
                section_len_start_offset,
                assign_delta,
                &[AssignType::IsSectionLen],
            )?;

            for i in 0..section_len {
                let offset = section_body_start_offset + i;
                self.assign(
                    region,
                    wb,
                    offset,
                    assign_delta,
                    &[AssignType::IsSectionBody],
                    1,
                    None,
                )?;
            }
        }

        let dynamic_indexes_offset = self.config.dynamic_indexes_chip.assign_auto(
            region,
            self.config.shared_state.borrow().dynamic_indexes_offset,
            assign_delta,
            self.config.shared_state.borrow().func_count,
            self.config.shared_state.borrow().bytecode_number,
            Tag::FuncIndex,
        )?;
        self.config.shared_state.borrow_mut().dynamic_indexes_offset = dynamic_indexes_offset;

        Ok(wb_offset + assign_delta)
    }
}
