use std::marker::PhantomData;
use std::rc::Rc;

use halo2_proofs::{
    plonk::{Column, ConstraintSystem},
};
use halo2_proofs::circuit::{Chip, Layouter, Region, Value};
use halo2_proofs::plonk::{Advice, Constraints, Error, Fixed};
use halo2_proofs::poly::Rotation;
use log::debug;
use num_traits::pow;

use eth_types::Field;
use gadgets::is_zero::{IsZeroChip, IsZeroInstruction};
use gadgets::less_than::{LtChip, LtInstruction};
use gadgets::util::{and, Expr, not, or};

use crate::evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon};
use crate::table::PoseidonTable;
use crate::wasm_circuit::common::wasm_compute_section_len;
use crate::wasm_circuit::consts::{WASM_PREAMBLE_MAGIC_PREFIX, WASM_SECTIONS_START_INDEX, WASM_VERSION_PREFIX_BASE_INDEX, WASM_VERSION_PREFIX_LENGTH};
use crate::wasm_circuit::leb128_circuit::circuit::LEB128Chip;
use crate::wasm_circuit::leb128_circuit::helpers::{leb128_compute_last_byte_offset, leb128_compute_sn_recovered_at_position};
use crate::wasm_circuit::tables::range_table::RangeTableConfig;
use crate::wasm_circuit::utf8_circuit::circuit::UTF8Chip;
use crate::wasm_circuit::wasm_bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::wasm_bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::wasm_sections::consts::{SECTION_ID_DEFAULT, WASM_SECTION_ID_MAX, WasmSectionId};
use crate::wasm_circuit::wasm_sections::helpers::configure_check_for_transition;
use crate::wasm_circuit::wasm_sections::wasm_export_section::wasm_export_section_body::circuit::WasmExportSectionBodyChip;
use crate::wasm_circuit::wasm_sections::wasm_function_section::wasm_function_section_body::circuit::WasmFunctionSectionBodyChip;
use crate::wasm_circuit::wasm_sections::wasm_import_section::wasm_import_section_body::circuit::WasmImportSectionBodyChip;
use crate::wasm_circuit::wasm_sections::wasm_memory_section::wasm_memory_section_body::circuit::WasmMemorySectionBodyChip;
use crate::wasm_circuit::wasm_sections::wasm_type_section::wasm_type_section_body::circuit::WasmTypeSectionBodyChip;
use crate::wasm_circuit::wasm_sections::wasm_type_section::wasm_type_section_item::circuit::{WasmTypeSectionItemChip};

pub struct WasmSectionConfig<F: Field> {
    _marker: PhantomData<F>,
}

#[derive(Debug, Clone)]
pub struct WasmConfig<F: Field> {
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
    is_section_id_grows_lt_chip: LtChip<F, 1>,
    index_at_magic_prefix_count: usize,
    index_at_magic_prefix: Vec<IsZeroChip<F>>,
    index_at_magic_prefix_prev: Vec<IsZeroChip<F>>,
    pub(crate) poseidon_table: PoseidonTable,
    pub(crate) range_table_config_0_256: RangeTableConfig<F, 0, 256>,
    pub(crate) section_id_range_table_config: RangeTableConfig<F, 0, { WASM_SECTION_ID_MAX + 1 }>,
    pub(crate) range_table_config_0_128: Rc<RangeTableConfig<F, 0, 128>>,
    pub(crate) wasm_bytecode_table: Rc<WasmBytecodeTable>,

    _marker: PhantomData<F>,
}

impl<F: Field> WasmConfig<F>
{}


#[derive(Debug, Clone)]
pub struct WasmChip<F: Field> {
    pub config: WasmConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> WasmChip<F>
{
    pub fn load(
        &self,
        layouter: &mut impl Layouter<F>,
        wasm_bytecode: &WasmBytecode,
    ) -> Result<(), Error> {
        self.config.wasm_bytecode_table.load(layouter, wasm_bytecode)?;
        self.config.range_table_config_0_256.load(layouter)?;
        self.config.section_id_range_table_config.load(layouter)?;
        self.config.range_table_config_0_128.load(layouter)?;

        self.config
            .poseidon_table
            .dev_load(layouter, &[wasm_bytecode.bytes.clone()])?;

        Ok(())
    }

    pub fn configure(
        cs: &mut ConstraintSystem<F>,
        wasm_bytecode_table: Rc<WasmBytecodeTable>,
    ) -> WasmConfig<F> {
        let range_table_config_0_256 = RangeTableConfig::configure(cs);
        let section_id_range_table_config = RangeTableConfig::configure(cs);
        let range_table_config_0_128 = Rc::new(RangeTableConfig::configure(cs));
        let poseidon_table = PoseidonTable::dev_construct(cs);

        let leb128_config = LEB128Chip::configure(
            cs,
            &wasm_bytecode_table.value,
        );
        let mut leb128_chip = Rc::new(LEB128Chip::construct(leb128_config));

        let utf8_config = UTF8Chip::configure(
            cs,
            range_table_config_0_128.clone(),
            &wasm_bytecode_table.value,
        );
        let mut utf8_chip = Rc::new(UTF8Chip::construct(utf8_config));

        let wasm_type_section_item_config = WasmTypeSectionItemChip::configure(
            cs,
            wasm_bytecode_table.clone(),
            leb128_chip.clone(),
        );
        let wasm_type_section_item_chip = Rc::new(WasmTypeSectionItemChip::construct(wasm_type_section_item_config));
        let wasm_type_section_body_config = WasmTypeSectionBodyChip::configure(
            cs,
            wasm_bytecode_table.clone(),
            leb128_chip.clone(),
            wasm_type_section_item_chip.clone(),
        );
        let wasm_type_section_body_chip = Rc::new(WasmTypeSectionBodyChip::construct(wasm_type_section_body_config));

        let wasm_import_section_body_config = WasmImportSectionBodyChip::configure(
            cs,
            wasm_bytecode_table.clone(),
            leb128_chip.clone(),
            utf8_chip.clone(),
        );
        let wasm_import_section_body_chip = Rc::new(WasmImportSectionBodyChip::construct(wasm_import_section_body_config));

        let wasm_function_section_body_config = WasmFunctionSectionBodyChip::configure(
            cs,
            wasm_bytecode_table.clone(),
            leb128_chip.clone(),
        );
        let wasm_function_section_body_chip = Rc::new(WasmFunctionSectionBodyChip::construct(wasm_function_section_body_config));

        let wasm_memory_section_body_config = WasmMemorySectionBodyChip::configure(
            cs,
            wasm_bytecode_table.clone(),
            leb128_chip.clone(),
        );
        let wasm_memory_section_body_chip = Rc::new(WasmMemorySectionBodyChip::construct(wasm_memory_section_body_config));

        let wasm_export_section_body_config = WasmExportSectionBodyChip::configure(
            cs,
            wasm_bytecode_table.clone(),
            leb128_chip.clone(),
        );
        let wasm_export_section_body_chip = Rc::new(WasmExportSectionBodyChip::construct(wasm_export_section_body_config));

        let index_at_magic_prefix_count = WASM_PREAMBLE_MAGIC_PREFIX.len() + WASM_VERSION_PREFIX_LENGTH;

        let q_enable = cs.fixed_column();
        let q_first = cs.fixed_column();
        let q_last = cs.fixed_column();
        let is_section_id = cs.fixed_column();
        let is_section_len = cs.fixed_column();
        let is_section_body = cs.fixed_column();

        let section_id = cs.advice_column();

        let mut index_at_magic_prefix: Vec<IsZeroChip<F>> = Vec::new();
        for index in 0..index_at_magic_prefix_count {
            let value_inv = cs.advice_column();
            let index_at_magic_prefix_config = IsZeroChip::configure(
                cs,
                |vc| vc.query_fixed(q_enable, Rotation::cur()),
                |vc| vc.query_advice(wasm_bytecode_table.index, Rotation::cur()) - (index as i32).expr(),
                value_inv
            );
            let chip = IsZeroChip::construct(index_at_magic_prefix_config);
            index_at_magic_prefix.push(chip);
        }
        let mut index_at_magic_prefix_prev: Vec<IsZeroChip<F>> = Vec::new();
        for index in 0..index_at_magic_prefix_count {
            let value_inv = cs.advice_column();
            let index_at_magic_prefix_prev_config = IsZeroChip::configure(
                cs,
                |vc| and::expr([vc.query_fixed(q_enable, Rotation::cur()), not::expr(vc.query_fixed(q_first, Rotation::cur()))]),
                |vc| vc.query_advice(wasm_bytecode_table.index, Rotation::prev()) - (index as i32).expr(),
                value_inv
            );
            let chip = IsZeroChip::construct(index_at_magic_prefix_prev_config);
            index_at_magic_prefix_prev.push(chip);
        }

        cs.create_gate("basic row checks", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
            let q_first_expr = vc.query_fixed(q_first, Rotation::cur());
            let q_last_expr = vc.query_fixed(q_last, Rotation::cur());

            let is_section_id_expr = vc.query_fixed(is_section_id, Rotation::cur());
            let is_section_len_expr = vc.query_fixed(is_section_len, Rotation::cur());
            let is_section_body_expr = vc.query_fixed(is_section_body, Rotation::cur());

            let byte_val_expr = vc.query_advice(wasm_bytecode_table.index, Rotation::cur());

            cb.require_boolean("q_enable is boolean", q_enable_expr.clone());
            cb.require_boolean("q_first is boolean", q_first_expr.clone());
            cb.require_boolean("q_last is boolean", q_last_expr.clone());
            cb.require_boolean("is_section_id is boolean", is_section_id_expr.clone());
            cb.require_boolean("is_section_len is boolean", is_section_len_expr.clone());
            cb.require_boolean("is_section_body is boolean", is_section_body_expr.clone());

            cb.require_zero("index==0 when q_first==1", and::expr([q_first_expr.clone(), byte_val_expr.clone(), ]));

            let mut is_index_at_magic_prefix_expr = index_at_magic_prefix.iter()
                .fold(0.expr(), |acc, x| { acc.clone() + x.config().expr() });

            // TODO check
            cb.require_equal(
                "exactly one mark flag active at the same time",
                is_index_at_magic_prefix_expr.clone() + is_section_id_expr.clone() + is_section_len_expr.clone() + is_section_body_expr.clone(),
                1.expr(),
            );

            cb.gate(q_enable_expr)
        });

        cs.create_gate("bytecode checks", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
            let q_last_expr = vc.query_fixed(q_last, Rotation::cur());

            let bytecode_index_expr = vc.query_advice(wasm_bytecode_table.index, Rotation::cur());
            let bytecode_index_next_expr = vc.query_advice(wasm_bytecode_table.index, Rotation::next());

            cb.require_equal(
                "next.bytecode_index == cur.bytecode_index + 1",
                bytecode_index_expr.clone() + 1.expr(),
                bytecode_index_next_expr.clone(),
            );

            cb.gate(and::expr(vec![
                q_enable_expr.clone(),
                not::expr(q_last_expr.clone()),
            ]))
        });
        cs.lookup("all bytecode values are byte values", |vc| {
            let bytecode_value = vc.query_advice(wasm_bytecode_table.value, Rotation::cur());

            vec![(bytecode_value, range_table_config_0_256.value)]
        });

        cs.create_gate("wasm magic prefix check", |vc| {
            let mut cb = BaseConstraintBuilder::default();
            let bytecode_value = vc.query_advice(wasm_bytecode_table.value, Rotation::cur());

            for (i, char) in WASM_PREAMBLE_MAGIC_PREFIX.chars().enumerate() {
                cb.require_zero(
                    "bytecode_val==ord(specific_char) at index",
                    and::expr([
                        index_at_magic_prefix[i].config().expr(),
                        bytecode_value.clone() - (char as i32).expr(),
                    ])
                );
            }
            for i in WASM_VERSION_PREFIX_BASE_INDEX..WASM_VERSION_PREFIX_BASE_INDEX + WASM_VERSION_PREFIX_LENGTH {
                let version_val = if i == WASM_VERSION_PREFIX_BASE_INDEX { 1 } else { 0 };
                cb.require_zero(
                    "bytecode_val==version_val at index",
                    and::expr([
                        index_at_magic_prefix[i].config().expr(),
                        vc.query_advice(wasm_bytecode_table.value, Rotation::cur()) - (version_val).expr(),
                    ])
                );
            }

            cb.gate(and::expr(vec![
                vc.query_fixed(q_enable, Rotation::cur()),
            ]))
        });

        cs.create_gate("wasm magic prefix to sections transition check", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
            let is_section_id_expr = vc.query_fixed(is_section_id, Rotation::cur());
            let is_section_len_expr = vc.query_fixed(is_section_len, Rotation::cur());
            let is_section_body_expr = vc.query_fixed(is_section_body, Rotation::cur());

            let mut is_index_at_magic_prefix_expr = index_at_magic_prefix.iter()
                .fold(0.expr(), |acc, x| { acc.clone() + x.config().expr() });

            cb.condition(
                is_index_at_magic_prefix_expr.clone(),
                |bcb| {
                    bcb.require_zero(
                        "bytecode[0..7] -> !is_section_id && !is_section_len && !is_section_body",
                        or::expr([
                            is_section_id_expr.clone(),
                            is_section_len_expr.clone(),
                            is_section_body_expr.clone(),
                        ]),
                    )
                }
            );
            cb.condition(
                not::expr(is_index_at_magic_prefix_expr.clone()),
                |bcb| {
                    bcb.require_equal(
                        "not(bytecode[0..7]) -> one_of([is_section_id, is_section_len, is_section_body])==1",
                        is_section_id_expr.clone() + is_section_len_expr.clone() + is_section_body_expr.clone(),
                        1.expr(),
                    )
                }
            );

            cb.gate(q_enable_expr)
        });
        cs.create_gate("wasm section layout check", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_last_expr = vc.query_fixed(q_last, Rotation::cur());

            let bytecode_value = vc.query_advice(wasm_bytecode_table.value, Rotation::cur());

            let section_id_expr = vc.query_advice(section_id, Rotation::cur());

            let is_section_id_expr = vc.query_fixed(is_section_id, Rotation::cur());
            let is_section_len_expr = vc.query_fixed(is_section_len, Rotation::cur());
            let is_section_body_expr = vc.query_fixed(is_section_body, Rotation::cur());

            cb.condition(
                index_at_magic_prefix_prev[WASM_SECTIONS_START_INDEX - 1].config().expr(),
                |bcb| {
                    bcb.require_equal(
                        "if previous bytecode index is 7 -> is_section_id",
                        is_section_id_expr.clone(),
                        1.expr(),
                    )
                }
            );
            // TODO: section+(is_section_id(1) -> is_section_len+ -> is_section_body+) (use [configure_check_for_transition])
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_section_id(1) -> is_section_len+",
                is_section_id_expr.clone(),
                true,
                &[is_section_len],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_section_id(1) -> is_section_len+",
                is_section_len_expr.clone(),
                false,
                &[is_section_id, is_section_len],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check next: is_section_len+ -> is_section_body+",
                is_section_len_expr.clone(),
                true,
                &[is_section_len, is_section_body],
            );
            configure_check_for_transition(
                &mut cb,
                vc,
                "check prev: is_section_len+ -> is_section_body+",
                is_section_body_expr.clone(),
                false,
                &[is_section_len, is_section_body],
            );
            // TODO must pass, recheck
            // configure_check_for_transition(
            //     &mut cb,
            //     vc,
            //     "check next: is_section_body+ -> is_section_id(1) || q_last",
            //     true,
            //     and::expr([
            //         is_section_body_expr.clone(),
            //         not::expr(q_last_expr.clone()),
            //     ]),
            //     &[is_section_body, is_section_id, q_last],
            // );

            cb.condition(
                is_section_id_expr.clone(),
                |bcb| {
                    bcb.require_equal(
                        "is_section_id -> section_id==bytecode_value",
                        section_id_expr.clone(),
                        bytecode_value.clone(),
                    )
                }
            );

            // TODO add constraints

            // TODO recover (reuse or not reuse leb cols?)
            // cb.condition(
            //     is_section_body_expr.clone(),
            //     |bcb| {
            //         bcb.require_zero(
            //             "section_len_leb_solid_number decreases by 1 for section_body",
            //             section_len_leb_solid_number_prev_expr.clone() - section_len_leb_solid_number_expr.clone() - 1.expr(),
            //         );
            //     }
            // );
            // cb.condition(
            //     or::expr([
            //         is_section_id_expr.clone() * is_prev_section_body_expr.expr(),
            //         q_last_expr.expr()
            //     ]),
            //     |bcb| {
            //         bcb.require_zero(
            //             "section_len_leb_solid_number_expr must equal 0 at the end of the body",
            //             section_len_leb_solid_number_expr.clone(),
            //         );
            //     }
            // );

            cb.require_equal(
                "prev.hash == cur.hash",
                vc.query_advice(wasm_bytecode_table.code_hash, Rotation::prev()),
                vc.query_advice(wasm_bytecode_table.code_hash, Rotation::cur()),
            );

            cb.gate(and::expr(vec![
                not::expr(vc.query_fixed(q_first, Rotation::cur())),
                vc.query_fixed(q_enable, Rotation::cur()),
            ]))
        });

        cs.create_gate("for the first 8 bytes section_id==SECTION_ID_DEFAULT", |vc| {
            let section_id_expr = vc.query_advice(section_id, Rotation::cur());

            let mut constraints = Vec::new();
            for i in 0..WASM_SECTIONS_START_INDEX {
                let constraint = index_at_magic_prefix[i].config().expr() * (section_id_expr.clone() - SECTION_ID_DEFAULT.expr());
                constraints.push(
                    ("id of section equals to default at magic prefix indexes", constraint)
                );
            }
            Constraints::with_selector(
                vc.query_fixed(q_enable, Rotation::cur()),
                constraints,
            )
        });

        let is_section_id_grows_lt_chip_config = LtChip::configure(
            cs,
            |vc| {
                let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
                let q_first_expr = vc.query_fixed(q_first, Rotation::cur());
                let not_q_first_expr = not::expr(q_first_expr.clone());

                and::expr([
                    not_q_first_expr.clone(),
                    q_enable_expr.clone(),
                ])
            },
            |vc| {
                vc.query_advice(section_id, Rotation::prev())
            },
            |vc| {
                vc.query_advice(section_id, Rotation::cur())
            },
        );
        let is_section_id_grows_lt_chip = LtChip::construct(is_section_id_grows_lt_chip_config);
        cs.create_gate("prev.section_id <= cur.section_id", |vc| {
            let section_id_prev_expr = vc.query_advice(section_id, Rotation::prev());
            let section_id_expr = vc.query_advice(section_id, Rotation::cur());

            let mut constraints = Vec::new();

            constraints.push(
                ("prev.section_id <= cur.section_id",
                 (is_section_id_grows_lt_chip.config().is_lt(vc, None) - 1.expr())
                     * (section_id_expr.clone() - section_id_prev_expr.clone())
                )
            );

            Constraints::with_selector(
                and::expr([
                    not::expr(vc.query_fixed(q_first, Rotation::cur())),
                    vc.query_fixed(q_enable, Rotation::cur()),
                ]),
                constraints,
            )
        });

        cs.create_gate("code_hash check", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let wasm_bytecode_table_code_hash = vc.query_advice(wasm_bytecode_table.code_hash, Rotation::cur());
            let poseidon_table_hash_id = vc.query_advice(poseidon_table.hash_id, Rotation::cur());

            cb.require_zero(
                "code hashes match",
                wasm_bytecode_table_code_hash.clone() - poseidon_table_hash_id.clone(),
            );

            cb.gate(
                and::expr([
                    index_at_magic_prefix[2].config().expr(),
                    vc.query_fixed(q_enable, Rotation::cur()),
                ]),
            )
        });

        cs.lookup("section_id is a valid number", |vc| {
            let section_id_expr = vc.query_advice(section_id, Rotation::cur());

            vec![(section_id_expr.clone(), section_id_range_table_config.value)]
        });

        // TODO uncomment when all section body chips are ready
        // cs.create_gate("exactly one section chip is enabled when is_section_body", |vc| {
        //     let mut cb = BaseConstraintBuilder::default();
        //
        //     let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
        //     let is_section_body_expr = vc.query_fixed(is_section_body, Rotation::cur());
        //
        //     cb.condition(
        //         is_section_body_expr.clone(),
        //         |bcb| {
        //             bcb.require_equal(
        //                 "exactly one section chip is enabled when is_section_body",
        //                 vc.query_fixed(wasm_type_section_body_chip.config.q_enable, Rotation::cur())
        //                 + vc.query_fixed(wasm_import_section_body_chip.config.q_enable, Rotation::cur())
        //                 + vc.query_fixed(wasm_function_section_body_chip.config.q_enable, Rotation::cur()),
        //                 1.expr(),
        //             );
        //         }
        //     );
        //
        //     cb.gate(q_enable_expr.clone())
        // });

        let config = WasmConfig {
            poseidon_table,
            wasm_bytecode_table,
            q_enable,
            q_first,
            q_last,
            range_table_config_0_256,
            section_id_range_table_config,
            index_at_magic_prefix,
            index_at_magic_prefix_prev,
            index_at_magic_prefix_count,
            section_id,
            is_section_id,
            is_section_len,
            is_section_body,
            leb128_chip: leb128_chip.clone(),
            utf8_chip: utf8_chip.clone(),
            wasm_type_section_item_chip: wasm_type_section_item_chip.clone(),
            wasm_type_section_body_chip: wasm_type_section_body_chip.clone(),
            wasm_import_section_body_chip: wasm_import_section_body_chip.clone(),
            wasm_function_section_body_chip: wasm_function_section_body_chip.clone(),
            wasm_memory_section_body_chip: wasm_memory_section_body_chip.clone(),
            wasm_export_section_body_chip: wasm_export_section_body_chip.clone(),
            is_section_id_grows_lt_chip,
            _marker: PhantomData,
            range_table_config_0_128: range_table_config_0_128.clone(),
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

    pub fn assign_init(
        &self,
        region: &mut Region<F>,
        offset_max: usize,
    ) -> Result<(), Error> {
        self.config.leb128_chip.assign_init(region, offset_max);
        self.config.wasm_type_section_item_chip.assign_init(region, offset_max);
        self.config.wasm_type_section_body_chip.assign_init(region, offset_max);
        self.config.wasm_import_section_body_chip.assign_init(region, offset_max);
        self.config.wasm_function_section_body_chip.assign_init(region, offset_max);
        self.config.wasm_memory_section_body_chip.assign_init(region, offset_max);
        self.config.wasm_export_section_body_chip.assign_init(region, offset_max);

        for offset in 0..=offset_max {
            self.assign(
                region,
                offset,
                false,
                false,
                false,
            )?;
        }

        Ok(())
    }

    pub fn assign(
        &self,
        region: &mut Region<F>,
        offset: usize,
        is_enabled: bool,
        is_first_byte: bool,
        is_last_byte: bool,
    ) -> Result<(), Error> {
        region.assign_fixed(
            || format!("assign q_enable at {}", offset),
            self.config.q_enable,
            offset,
            || Value::known(F::from(is_enabled as u64)),
        )?;
        region.assign_fixed(
            || format!("assign q_first at {}", offset),
            self.config.q_first,
            offset,
            || Value::known(F::from(is_first_byte as u64)),
        )?;
        region.assign_fixed(
            || format!("assign q_last at {}", offset),
            self.config.q_last,
            offset,
            || Value::known(F::from(is_last_byte as u64)),
        )?;

        region.assign_fixed(
            || format!("assign is_section_id at {}", offset),
            self.config.is_section_id,
            offset,
            || Value::known(F::zero()),
        )?;
        region.assign_fixed(
            || format!("assign is_section_len at {}", offset),
            self.config.is_section_len,
            offset,
            || Value::known(F::zero()),
        )?;
        region.assign_fixed(
            || format!("assign is_section_body at {}", offset),
            self.config.is_section_body,
            offset,
            || Value::known(F::zero()),
        )?;

        let val: i64 = SECTION_ID_DEFAULT as i64;
        region.assign_advice(
            || format!("assign section_id val {} at {}", val, offset),
            self.config.section_id,
            offset,
            || Value::known(if val < 0 { -F::from(val.abs() as u64) } else { F::from(val as u64) })
        )?;
        if offset > 0 {
            self.config.is_section_id_grows_lt_chip.assign(
                region,
                offset,
                F::zero(),
                F::zero(),
            )?;
        }

        for (index, index_at_magic_prefix) in self.config.index_at_magic_prefix.iter().enumerate() {
            index_at_magic_prefix.assign(region, offset, Value::known(F::from(offset as u64) - F::from(index as u64)))?;
        }
        for (index, index_at_magic_prefix_prev) in self.config.index_at_magic_prefix_prev.iter().enumerate() {
            index_at_magic_prefix_prev.assign(region, offset, Value::known(F::from(offset as u64) - F::from(index as u64) - F::from(1)))?;
        }

        Ok(())
    }

    pub fn assign_auto(
        &self,
        region: &mut Region<F>,
        wasm_bytecode: &WasmBytecode,
    ) -> Result<(), Error> {
        debug!("wasm_bytecode.bytes {:x?}", wasm_bytecode.bytes);
        for (offset, &byte) in wasm_bytecode.bytes.iter().enumerate() {
            self.assign(
                region,
                offset,
                true,
                offset == 0,
                offset == wasm_bytecode.bytes.len() - 1
            )?;
        }

        // scan wasm_bytes for sections
        let mut wasm_bytes_offset = WASM_SECTIONS_START_INDEX;
        let mut section_id_prev: i64 = SECTION_ID_DEFAULT as i64;
        loop {
            let section_start_offset = wasm_bytes_offset;
            let section_len_start_offset = section_start_offset + 1;
            let section_id = wasm_bytecode.bytes[wasm_bytes_offset];
            wasm_bytes_offset += 1;
            let (section_len, section_len_leb_bytes_count) = wasm_compute_section_len(&wasm_bytecode.bytes, wasm_bytes_offset).unwrap();
            wasm_bytes_offset += section_len_leb_bytes_count as usize;
            wasm_bytes_offset += section_len;
            let section_body_start_offset = section_len_start_offset + (section_len_leb_bytes_count as usize);
            let section_len_end_offset = section_body_start_offset - 1;
            let section_body_end_offset = section_start_offset + section_len_leb_bytes_count as usize + section_len;
            let section_end_offset = section_body_end_offset;

            // debug!("");
            // debug!("section_id_prev: {}", section_id_prev);
            // debug!("section_id: {}", section_id);
            // debug!("section_start_offset: {}", section_start_offset);
            // debug!("section_start_offset: {}", section_end_offset);
            // debug!("section_len: {}", section_len);
            // debug!("section_len_start_offset: {}", section_len_start_offset);
            // debug!("section_len_end_offset: {}", section_len_end_offset);
            // debug!("section_body_start_offset: {}", section_body_start_offset);
            // debug!("section_body_end_offset: {}", section_body_end_offset);
            // debug!("");

            {
                let offset = section_start_offset;
                region.assign_fixed(
                    || format!("assign is_section_id at {}", offset),
                    self.config.is_section_id,
                    offset,
                    || Value::known(F::one()),
                )?;
            }
            for i in 0..section_len_leb_bytes_count {
                let offset = section_len_start_offset + (i as usize);
                region.assign_fixed(
                    || format!("assign is_section_len at {}", offset),
                    self.config.is_section_len,
                    offset,
                    || Value::known(F::one()),
                )?;
            }
            for i in 0..section_len {
                let offset = section_body_start_offset + i;
                let val = 1;
                region.assign_fixed(
                    || format!("assign 'is_section_body' to {} at {}", val, offset),
                    self.config.is_section_body,
                    offset,
                    || Value::known(F::from(val)),
                )?;
            }

            let mut sn_recovered_at_pos: u64 = 0;
            let is_signed = false;
            for offset in section_len_start_offset..=section_len_end_offset {
                let rel_byte_offset = offset - section_len_start_offset;
                let rel_last_byte_offset = section_len_end_offset - section_len_start_offset;
                let is_first_leb_byte = rel_byte_offset == 0;
                let is_last_leb_byte = rel_byte_offset == rel_last_byte_offset;
                let is_byte_has_cb = rel_byte_offset < rel_last_byte_offset;

                sn_recovered_at_pos = leb128_compute_sn_recovered_at_position(
                    sn_recovered_at_pos,
                    is_signed,
                    rel_byte_offset,
                    rel_last_byte_offset,
                    wasm_bytecode.bytes[offset],
                );
                self.config.leb128_chip.assign(
                    region,
                    offset,
                    rel_byte_offset,
                    true,
                    is_first_leb_byte,
                    is_last_leb_byte,
                    is_byte_has_cb,
                    is_signed,
                    section_len as u64,
                    sn_recovered_at_pos,
                );
            }

            for offset in section_start_offset..=section_end_offset {
                if offset == section_start_offset {
                    if section_id == WasmSectionId::Type as u8 {
                        debug!("section_id {} offset {}", section_id, offset);
                        let mut section_body_offset = offset + 1; // skips section_id byte
                        let last_byte_offset = leb128_compute_last_byte_offset(
                            &wasm_bytecode.bytes.as_slice(),
                            section_body_offset,
                        ).unwrap();
                        section_body_offset = last_byte_offset + 1;
                        debug!("section_id {} section_body_offset {}", section_id, section_body_offset);
                        let new_offset = self.config.wasm_type_section_body_chip.assign_auto(
                            region,
                            wasm_bytecode,
                            section_body_offset,
                        ).unwrap();
                        debug!("section_id {} after assign_auto new_offset {}", section_id, new_offset);
                    } else if section_id == WasmSectionId::Import as u8 {
                        debug!("section_id {} offset {}", section_id, offset);
                        let mut section_body_offset = offset + 1; // skips section_id byte
                        let last_byte_offset = leb128_compute_last_byte_offset(
                            &wasm_bytecode.bytes.as_slice(),
                            section_body_offset,
                        ).unwrap();
                        section_body_offset = last_byte_offset + 1;
                        debug!("section_id {} section_body_offset {}", section_id, section_body_offset);
                        let new_offset = self.config.wasm_import_section_body_chip.assign_auto(
                            region,
                            wasm_bytecode,
                            section_body_offset,
                        ).unwrap();
                        debug!("section_id {} after assign_auto new_offset {}", section_id, new_offset);
                    } else if section_id == WasmSectionId::Function as u8 {
                        debug!("section_id {} offset {}", section_id, offset);
                        let mut section_body_offset = offset + 1; // skips section_id byte
                        let last_byte_offset = leb128_compute_last_byte_offset(
                            &wasm_bytecode.bytes.as_slice(),
                            section_body_offset,
                        ).unwrap();
                        section_body_offset = last_byte_offset + 1;
                        debug!("section_id {} section_body_offset {}", section_id, section_body_offset);
                        let new_offset = self.config.wasm_function_section_body_chip.assign_auto(
                            region,
                            wasm_bytecode,
                            section_body_offset,
                        ).unwrap();
                        debug!("section_id {} after assign_auto new_offset {}", section_id, new_offset);
                    } else if section_id == WasmSectionId::Memory as u8 {
                        debug!("section_id {} offset {}", section_id, offset);
                        let mut section_body_offset = offset + 1; // skips section_id byte
                        let last_byte_offset = leb128_compute_last_byte_offset(
                            &wasm_bytecode.bytes.as_slice(),
                            section_body_offset,
                        ).unwrap();
                        section_body_offset = last_byte_offset + 1;
                        debug!("section_id {} section_body_offset {}", section_id, section_body_offset);
                        let new_offset = self.config.wasm_memory_section_body_chip.assign_auto(
                            region,
                            wasm_bytecode,
                            section_body_offset,
                        ).unwrap();
                        debug!("section_id {} after assign_auto new_offset {}", section_id, new_offset);
                    } else if section_id == WasmSectionId::Export as u8 {
                        debug!("section_id {} offset {}", section_id, offset);
                        let mut section_body_offset = offset + 1; // skips section_id byte
                        let last_byte_offset = leb128_compute_last_byte_offset(
                            &wasm_bytecode.bytes.as_slice(),
                            section_body_offset,
                        ).unwrap();
                        section_body_offset = last_byte_offset + 1;
                        debug!("section_id {} section_body_offset {}", section_id, section_body_offset);
                        let new_offset = self.config.wasm_export_section_body_chip.assign_auto(
                            region,
                            wasm_bytecode,
                            section_body_offset,
                        ).unwrap();
                        debug!("section_id {} after assign_auto new_offset {}", section_id, new_offset);
                    }
                }
                region.assign_advice(
                    || format!("assign 'section_id' to {} at {}", section_id, offset),
                    self.config.section_id,
                    offset,
                    || Value::known(F::from(section_id as u64))
                )?;
                self.config.is_section_id_grows_lt_chip.assign(
                    region,
                    offset,
                    F::from(section_id_prev as u64),
                    F::from(section_id as u64),
                )?;
                section_id_prev = section_id as i64;
            }

            if wasm_bytes_offset >= wasm_bytecode.bytes.len() { break }
        }

        Ok(())
    }
}