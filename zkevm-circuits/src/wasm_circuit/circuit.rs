use halo2_proofs::{
    plonk::{Column, ConstraintSystem},
};
use std::{marker::PhantomData};
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::plonk::{Advice, Error, Fixed};
use halo2_proofs::poly::Rotation;
use eth_types::Field;
use gadgets::is_zero::{IsZeroChip, IsZeroConfig, IsZeroInstruction};
use gadgets::util::{and, Expr, not, or};
use crate::evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon};
use crate::evm_circuit::util::from_bytes::expr;
use crate::wasm_circuit::common::wasm_compute_section_len;
use crate::wasm_circuit::consts::{WASM_PREAMBLE_MAGIC_PREFIX, WASM_SECTIONS_START_INDEX, WASM_VERSION_PREFIX_BASE_INDEX, WASM_VERSION_PREFIX_LENGTH};
use crate::wasm_circuit::tables::range_table::RangeTableConfig;
use crate::wasm_circuit::wasm_bytecode::bytecode_table::WasmBytecodeTable;

///
pub struct WasmSectionConfig<F: Field> {
    ///
    _marker: PhantomData<F>,
}

///
#[derive(Debug, Clone)]
pub struct WasmConfig<F: Field> {
    ///
    pub(crate) range_table_256_config: RangeTableConfig<F, 256>,
    ///
    pub(crate) wasm_bytecode_table: WasmBytecodeTable,
    ///
    q_enable: Column<Fixed>,
    ///
    q_first: Column<Fixed>,
    ///
    q_last: Column<Fixed>,
    ///
    index_at_positions: Vec<IsZeroConfig<F>>,
    ///
    index_at_prev_positions: Vec<IsZeroConfig<F>>,
    ///
    index_at_position_count: usize,
    ///
    is_section_id: Column<Advice>,
    ///
    is_section_len: Column<Advice>,
    ///
    is_section_body: Column<Advice>,
    ///
    _marker: PhantomData<F>,
}

impl<F: Field> WasmConfig<F>
{}


///
#[derive(Debug, Clone)]
pub struct WasmChip<F: Field> {
    ///
    pub config: WasmConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> WasmChip<F>
{
    ///
    pub fn construct(config: WasmConfig<F>) -> Self {
        let instance = Self {
            config,
            _marker: PhantomData,
        };
        instance
    }

    ///
    pub fn configure(
        cs: &mut ConstraintSystem<F>,
        wasm_bytecode_table: WasmBytecodeTable,
    ) -> WasmConfig<F> {
        let range_table_256_config = RangeTableConfig::configure(cs);
        let index_at_position_count = WASM_PREAMBLE_MAGIC_PREFIX.len() + WASM_VERSION_PREFIX_LENGTH;

        let q_enable = cs.fixed_column();
        let q_first = cs.fixed_column();
        let q_last = cs.fixed_column();
        let is_section_id = cs.advice_column();
        let is_section_len = cs.advice_column();
        let is_section_body = cs.advice_column();

        cs.create_gate("verify row", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_boolean(
                "q_enable is boolean",
                vc.query_fixed(q_enable, Rotation::cur()),
            );
            cb.require_boolean(
                "q_first is boolean",
                vc.query_fixed(q_first, Rotation::cur()),
            );
            cb.require_boolean(
                "q_last is boolean",
                vc.query_fixed(q_last, Rotation::cur()),
            );
            cb.require_boolean(
                "is_section_id is boolean",
                vc.query_advice(is_section_id, Rotation::cur()),
            );
            cb.require_boolean(
                "is_section_len is boolean",
                vc.query_advice(is_section_len, Rotation::cur()),
            );
            cb.require_boolean(
                "is_section_body is boolean",
                vc.query_advice(is_section_body, Rotation::cur()),
            );
            // TODO recheck
            cb.require_zero(
                "index == 0 when q_first == 1",
                and::expr([
                    vc.query_fixed(q_first, Rotation::cur()),
                    vc.query_advice(wasm_bytecode_table.index, Rotation::cur()),
                ]),
            );
            cb.gate(vc.query_fixed(q_enable, Rotation::cur()))
        });

        cs.create_gate("index grow 1 by 1", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_equal(
                "next.index == cur.index + 1",
                vc.query_advice(wasm_bytecode_table.index, Rotation::cur()) + 1.expr(),
                vc.query_advice(wasm_bytecode_table.index, Rotation::next()),
            );

            cb.gate(and::expr(vec![
                vc.query_fixed(q_enable, Rotation::cur()),
                not::expr(vc.query_fixed(q_last, Rotation::cur())),
            ]))
        });
        cs.lookup("all bytecode values are byte values", |vc| {
            // let q_lookup = index_at_positions[i].expr();
            let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
            let value = vc.query_advice(wasm_bytecode_table.value, Rotation::cur());

            vec![(value, range_table_256_config.value)]
        });

        let mut index_at_positions: Vec<IsZeroConfig<F>> = Vec::new();
        for index in 0..index_at_position_count {
            let value_inv = cs.advice_column();
            let index_at_position = IsZeroChip::configure(
                cs,
                |vc| vc.query_fixed(q_enable, Rotation::cur()),
                |vc| vc.query_advice(wasm_bytecode_table.index, Rotation::cur()) - (index as i32).expr(),
                value_inv
            );
            index_at_positions.push(index_at_position);
        }
        let mut index_at_prev_positions: Vec<IsZeroConfig<F>> = Vec::new();
        for index in 0..index_at_position_count {
            let value_inv = cs.advice_column();
            let index_at_prev_position = IsZeroChip::configure(
                cs,
                |vc| and::expr([vc.query_fixed(q_enable, Rotation::cur()), not::expr(vc.query_fixed(q_first, Rotation::cur()))]),
                |vc| vc.query_advice(wasm_bytecode_table.index, Rotation::prev()) - (index as i32).expr(),
                value_inv
            );
            index_at_prev_positions.push(index_at_prev_position);
        }

        cs.create_gate("wasm gate: magic prefix check", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            // first bytes contain '\0asm'
            for (i, char) in WASM_PREAMBLE_MAGIC_PREFIX.chars().enumerate() {
                cb.require_zero(
                    "bytecode.value == ord(char) at index",
                    and::expr([
                        index_at_positions[i].expr(),
                        vc.query_advice(wasm_bytecode_table.value, Rotation::cur()) - (char as i32).expr(),
                    ])
                );
            }
            // and 4 bytes for version (1, 0, 0, 0)
            for i in WASM_VERSION_PREFIX_BASE_INDEX..WASM_VERSION_PREFIX_BASE_INDEX + WASM_VERSION_PREFIX_LENGTH {
                let version_val = if i == WASM_VERSION_PREFIX_BASE_INDEX { 1 } else { 0 };
                cb.require_zero(
                    "bytecode.value == version_val at index",
                    and::expr([
                        index_at_positions[i].expr(),
                        vc.query_advice(wasm_bytecode_table.value, Rotation::cur()) - (version_val as i32).expr(),
                    ])
                );
            }

            cb.gate(and::expr(vec![
                vc.query_fixed(q_enable, Rotation::cur()),
            ]))
        });

        // eligible sections transitions:
        // 1. (checked this step in the previous gate) !is_section_id && !is_section_len && !is_section_body -(N)> !is_section_id && !is_section_len && !is_section_body
        // 2. (only once, if previous bytecode index is 7) !is_section_id && !is_section_len && !is_section_body -(1)> is_section_id
        // 3. is_section_id -(1)> is_section_len
        // 4. is_section_len -(N)> is_section_len || is_section_len -(1)> is_section_body
        // 5. is_section_body -(N)> is_section_body || (shouldn't work for 'is_last') is_section_body -(N)> is_section_id
        // 6. is_section_body && is_last -(N)> is_section_body
        // for the rest: repeat steps 3..5
        cs.create_gate("wasm gate: sections transitions check for magic prefix", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
            let is_section_id_expr = vc.query_advice(is_section_id, Rotation::cur());
            let is_section_len_expr = vc.query_advice(is_section_len, Rotation::cur());
            let is_section_body_expr = vc.query_advice(is_section_body, Rotation::cur());

            // for index=0..7: !is_section_id && !is_section_len && !is_section_body
            for i in 0..WASM_SECTIONS_START_INDEX {
                cb.require_zero(
                    "bytecode[0]...bytecode[7] -> !is_section_id && !is_section_len && !is_section_body",
                    and::expr([
                        index_at_positions[i].expr(),
                        or::expr([is_section_id_expr.clone(), is_section_len_expr.clone(), is_section_body_expr.clone()]),
                    ]),
                );
            }

            cb.gate(and::expr(vec![
                q_enable_expr,
            ]))
        });
        cs.create_gate("wasm gate: section layout check", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_last_expr = vc.query_fixed(q_last, Rotation::cur());

            let is_section_id_expr = vc.query_advice(is_section_id, Rotation::cur());
            let is_prev_section_id_expr = vc.query_advice(is_section_id, Rotation::prev());
            let is_section_len_expr = vc.query_advice(is_section_len, Rotation::cur());
            let is_prev_section_len_expr = vc.query_advice(is_section_len, Rotation::prev());
            let is_section_body_expr = vc.query_advice(is_section_body, Rotation::cur());
            let is_prev_section_body_expr = vc.query_advice(is_section_body, Rotation::prev());

            // 2
            cb.require_zero(
                "(only once, if previous bytecode index is 7) !is_section_id && !is_section_len && !is_section_body -(1)> is_section_id",
                and::expr([
                    index_at_prev_positions[WASM_SECTIONS_START_INDEX - 1].expr(),
                    or::expr([
                        is_section_id_expr.clone() - 1.expr(),
                        is_section_len_expr.clone(),
                        is_section_body_expr.clone(),
                    ])
                ]),
            );
            // 3
            cb.condition(is_prev_section_id_expr.clone(), |bcb| {
                bcb.require_zero(
                    "is_section_id -(1)> is_section_len",
                    is_prev_section_id_expr.clone() - is_section_len_expr.clone(),
                );
            });
            // 4
            cb.condition(is_prev_section_len_expr.clone(), |bcb| {
                bcb.require_zero(
                    "is_section_len -(N)> is_section_len || is_section_len -(1)> is_section_body",
                    is_prev_section_len_expr.clone() - is_section_len_expr.clone() - is_section_body_expr.clone(),
                );
            });
            // 5
            cb.condition(is_prev_section_body_expr.clone(), |bcb| {
                bcb.require_zero(
                    "is_section_body -(N)> is_section_body || (shouldn't work for 'is_last') is_section_body -(N)> is_section_id",
                    is_prev_section_body_expr.clone() - is_section_body_expr.clone() - is_section_id_expr.clone(),
                );
            });
            // 6
            cb.condition(q_last_expr.clone(), |bcb| {
                bcb.require_zero(
                    "is_section_body -(N)> is_section_body",
                    is_prev_section_body_expr.clone() - is_section_body_expr.clone(),
                );
            });

            cb.gate(and::expr(vec![
                not::expr(vc.query_fixed(q_first, Rotation::cur())),
                vc.query_fixed(q_enable, Rotation::cur()),
            ]))
        });

        let config = WasmConfig {
            wasm_bytecode_table,
            q_enable,
            q_first,
            q_last,
            range_table_256_config,
            index_at_positions,
            index_at_prev_positions,
            index_at_position_count,
            is_section_id,
            is_section_len,
            is_section_body,
            _marker: PhantomData,
        };

        config
    }

    ///
    pub fn assign(
        &self,
        region: &mut Region<F>,
        wasm_bytes: &[u8],
    ) -> Result<(), Error> {
        let mut index_at_positions: Vec<IsZeroChip<F>> = Vec::new();
        let mut index_at_prev_positions: Vec<IsZeroChip<F>> = Vec::new();
        for i in 0..self.config.index_at_position_count {
            index_at_positions.push(IsZeroChip::construct(self.config.index_at_positions[i].clone()));
        }
        for i in 0..self.config.index_at_position_count {
            index_at_prev_positions.push(IsZeroChip::construct(self.config.index_at_prev_positions[i].clone()));
        }
        for (i, &_byte) in wasm_bytes.iter().enumerate() {
            let is_enable = true;
            let is_first = if i == 0 { true } else { false };
            let is_last = if i == wasm_bytes.len() - 1 { true } else { false };
            region.assign_fixed(
                || format!("assign q_enable at {}", i),
                self.config.q_enable,
                i,
                || Value::known(F::from(is_enable as u64)),
            )?;
            region.assign_fixed(
                || format!("assign q_first at {}", i),
                self.config.q_first,
                i,
                || Value::known(F::from(is_first as u64)),
            )?;
            region.assign_fixed(
                || format!("assign q_last at {}", i),
                self.config.q_last,
                i,
                || Value::known(F::from(is_last as u64)),
            )?;

            region.assign_advice(
                || format!("assign is_section_id at {}", i),
                self.config.is_section_id,
                i,
                || Value::known(F::zero()),
            )?;
            region.assign_advice(
                || format!("assign is_section_len at {}", i),
                self.config.is_section_len,
                i,
                || Value::known(F::zero()),
            )?;
            region.assign_advice(
                || format!("assign is_section_body at {}", i),
                self.config.is_section_body,
                i,
                || Value::known(F::zero()),
            )?;

            for (index, index_at_position) in index_at_positions.iter().enumerate() {
                index_at_position.assign(region, i, Value::known(F::from(i as u64) - F::from(index as u64)))?;
            }
            for (index, index_at_prev_position) in index_at_prev_positions.iter().enumerate() {
                index_at_prev_position.assign(region, i, Value::known(F::from(i as u64) - F::from(index as u64) - F::from(1)))?;
            }
        }
        // scan wasm_bytes for sections
        let mut index = WASM_SECTIONS_START_INDEX;
        loop {
            let section_start_index = index;
            let section_len_start_index = section_start_index + 1;
            let section_id = wasm_bytes[index];
            index += 1;
            let (section_len, section_len_leb_count) = wasm_compute_section_len(&wasm_bytes, index).unwrap();
            index += section_len_leb_count as usize;
            index += section_len as usize;
            let section_body_start_index = section_len_start_index + (section_len_leb_count as usize);
            // do not add 1 for section_id to not subtract it
            let section_end_index = section_start_index + section_len_leb_count as usize + section_len as usize;

            // println!();
            // println!("section_id: {}", section_id);
            // println!("section_start_index: {}", section_start_index);
            // println!("section_end_index: {}", section_end_index);
            // println!("section_len_leb_count: {}", section_len_leb_count);
            // println!("section_len: {}", section_len);

            let offset = section_start_index;
            region.assign_advice(
                || format!("assign is_section_id at {}", offset),
                self.config.is_section_id,
                offset,
                || Value::known(F::one()),
            )?;
            // println!("is_section_id at {}", offset);
            for i in 0..section_len_leb_count {
                let offset = section_len_start_index + (i as usize);
                region.assign_advice(
                    || format!("assign is_section_len at {}", offset),
                    self.config.is_section_len,
                    offset,
                    || Value::known(F::one()),
                )?;
                // println!("is_section_len at {}", offset);
            }
            for i in 0..section_len {
                let offset = section_body_start_index + (i as usize);
                region.assign_advice(
                    || format!("assign is_section_body at {}", offset),
                    self.config.is_section_body,
                    offset,
                    || Value::known(F::one()),
                )?;
                // println!("is_section_body at {}", offset);
            }

            if index >= wasm_bytes.len() { break }
        }
        Ok(())
    }
}