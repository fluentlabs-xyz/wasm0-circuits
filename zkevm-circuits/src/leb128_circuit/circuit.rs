use halo2_proofs::{
    plonk::{Advice, Column, ConstraintSystem},
};
use std::{marker::PhantomData};
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::plonk::{Constraints, Expression, Selector};
use halo2_proofs::poly::Rotation;
use eth_types::Field;
use gadgets::util::Expr;
use crate::leb128_circuit::consts::{BITS_IN_BYTE, BYTES_IN_BASE64_WORD, EIGHT_LS_BITS_MASK, LEB128_BITS_CHUNK_SIZE};


/// LEB128NumberConfig
#[derive(Debug, Clone)]
pub struct LEB128NumberConfig<F, const BIT_DEPTH: usize, const IS_SIGNED: bool> {
    ///
    pub selector: Selector,
    /// base64 repr of leb128 (each column represents a part of leb128)
    pub leb_base64_words: Column<Advice>,
    /// bytes repr of leb128
    pub leb_bytes: Column<Advice>,
    ///
    pub byte_has_continuation_bit: Column<Advice>,
    /// solid number represented in leb128. TODO maybe we dont need it anymore
    // pub solid_number: Column<Advice>,
    _marker: PhantomData<F>,
}

impl<F: Field, const BIT_DEPTH: usize, const IS_SIGNED: bool> LEB128NumberConfig<F, BIT_DEPTH, IS_SIGNED>
{}


///
#[derive(Debug, Clone)]
pub struct LEB128NumberChip<F, const BIT_DEPTH: usize, const IS_SIGNED: bool> {
    ///
    pub config: LEB128NumberConfig<F, BIT_DEPTH, IS_SIGNED>,
    _marker: PhantomData<F>,
}

impl<F: Field, const BIT_DEPTH: usize, const IS_SIGNED: bool> LEB128NumberChip<F, BIT_DEPTH, IS_SIGNED>
{
    /// max leb bytes needed to represent number with selected BIT_DEPTH
    pub const LEB_BYTES_N: usize = (BIT_DEPTH + 6) / 7;

    fn validate_static_state() {
        if BIT_DEPTH % 8 != 0 || BIT_DEPTH <= 0 || BIT_DEPTH > 64 {
            panic!("LEB128NumberChip: unsupported BIT_DEPTH {}", BIT_DEPTH)
        }
    }

    ///
    pub fn construct(config: LEB128NumberConfig<F, BIT_DEPTH, IS_SIGNED>) -> Self {
        let instance = Self {
            config,
            _marker: PhantomData,
        };
        Self::validate_static_state();
        instance
    }

    ///
    pub fn configure(
        cs: &mut ConstraintSystem<F>,
    ) -> LEB128NumberConfig<F, BIT_DEPTH, IS_SIGNED> {
        Self::validate_static_state();
        let selector = cs.selector();
        // let base64_words_count = (BIT_DEPTH / LEB128_BITS_CHUNK_SIZE + BYTES_IN_BASE64_WORD - 1) / BYTES_IN_BASE64_WORD;
        let leb_base64_words = cs.advice_column();
        let leb_bytes = cs.advice_column();
        let byte_has_continuation_bit = cs.advice_column();
        // let solid_number = cs.advice_column();

        let mut continuation_bits_constraints = Vec::<Expression<F>>::new();
        let mut continuation_bit_transition_constraints = Vec::<Expression<F>>::new();
        cs.create_gate("leb128 gate", |vc| {
            let selector_expr = vc.query_selector(selector);
            // let solid_number_expr = vc.query_advice(solid_number, Rotation(0));
            let mut leb_as_bytes_sum = 0.expr();
            for i in (0..Self::LEB_BYTES_N).rev() {
                let leb_byte_expr = vc.query_advice(leb_bytes, Rotation(i as i32));
                let has_continuation_bit_expr = vc.query_advice(byte_has_continuation_bit, Rotation(i as i32));
                // continuation bit must have 0 or 1 value (TODO replace with lookup)
                continuation_bits_constraints.push(has_continuation_bit_expr.clone() * (has_continuation_bit_expr.clone() - 1.expr()));
                if i < Self::LEB_BYTES_N - 1 {
                    let has_continuation_bit_next_expr = vc.query_advice(byte_has_continuation_bit, Rotation((i + 1) as i32));
                    // continuation bit (CB) eligible transitions: 1->1 or 1->0 or 0->0 not 0->1 (TODO replace CB with lookup mappings)
                    continuation_bit_transition_constraints.push((has_continuation_bit_expr.clone() - 1.expr()) * has_continuation_bit_next_expr);
                }
                leb_as_bytes_sum = leb_as_bytes_sum * 0b10000000.expr() + leb_byte_expr - has_continuation_bit_expr * 0b10000000.expr();
            }

            let mut leb_base64_words_recovered = Vec::<Expression<F>>::new();
            let mut rot_idx = 0;
            let leb_bytes_index_max = Self::LEB_BYTES_N - 1;
            for i in 0..=leb_bytes_index_max {
                if i % BYTES_IN_BASE64_WORD == 0 {
                    leb_base64_words_recovered.push(0.expr());
                    rot_idx = i + 7;
                    if rot_idx > leb_bytes_index_max { rot_idx = leb_bytes_index_max }
                } else {
                    rot_idx -= 1;
                }
                let mut leb_byte_expr = vc.query_advice(leb_bytes, Rotation(rot_idx as i32));
                if rot_idx > 0 && IS_SIGNED {
                    let cb_prev_expr = vc.query_advice(byte_has_continuation_bit, Rotation((rot_idx - 1) as i32));
                    let cb_expr = vc.query_advice(byte_has_continuation_bit, Rotation(rot_idx as i32));
                    let consider_expr = cb_prev_expr.clone() + cb_expr.clone() - cb_prev_expr * cb_expr;
                    let do_not_consider = 1.expr() - consider_expr.clone();
                    leb_byte_expr = leb_byte_expr - do_not_consider.clone() * EIGHT_LS_BITS_MASK.expr();
                }
                let leb_base64_words_last_index = leb_base64_words_recovered.len() - 1;
                let leb_base64_word = leb_base64_words_recovered[leb_base64_words_last_index].clone();
                leb_base64_words_recovered[leb_base64_words_last_index] = leb_byte_expr + leb_base64_word * 0b100000000.expr();
            }

            let mut constraints = Vec::from([
                // ("solid number equals to 7-bits repr sum", leb_as_bytes_sum - solid_number_expr),
            ]);
            for continuation_bits_constraint in continuation_bits_constraints {
                constraints.push(("continuation bit check", continuation_bits_constraint));
            }
            for continuation_bit_transition_constraint in continuation_bit_transition_constraints {
                constraints.push(("continuation bits may transit from 1 to 0 only", continuation_bit_transition_constraint));
            }
            for (i, leb_base64_word_recovered) in leb_base64_words_recovered.iter().enumerate() {
                let leb_base64_word = vc.query_advice(leb_base64_words, Rotation(i as i32));
                constraints.push((
                    "base64 word equals to recovered base64 word",
                    leb_base64_word_recovered.clone() - leb_base64_word
                ));
            }
            Constraints::with_selector(
                selector_expr,
                constraints,
            )
        });

        let config = LEB128NumberConfig {
            selector,
            leb_base64_words,
            leb_bytes,
            byte_has_continuation_bit,
            // solid_number,
            _marker: PhantomData,
        };

        config
    }

    ///
    pub fn assign(
        &self,
        region: &mut Region<F>,
        leb_bytes: &[u8],
        leb_last_byte_index: u64,
        // is_signed: bool,
        // solid_number: u64,
        leb_base64_words: &[u64],
    ) {
        self.config.selector.enable(region, 0).unwrap();

        for i in 0..Self::LEB_BYTES_N {
            region.assign_advice(
                || format!("byte_has_continuation_bit {}", i),
                self.config.byte_has_continuation_bit,
                i,
                || Value::known(F::from((leb_last_byte_index > i as u64) as u64)),
            ).unwrap();
        }

        for i in 0..Self::LEB_BYTES_N {
            region.assign_advice(
                || format!("leb_byte index {} value {}", i, leb_bytes[i]),
                self.config.leb_bytes,
                i,
                || Value::known(F::from(leb_bytes[i] as u64)),
            ).unwrap();
        }

        // region.assign_advice(
        //     || "solid_number",
        //     self.config.solid_number,
        //     0,
        //     || Value::known(F::from(solid_number)),
        // ).unwrap();

        let base64_words_count = (BIT_DEPTH / LEB128_BITS_CHUNK_SIZE + BYTES_IN_BASE64_WORD - 1) / BYTES_IN_BASE64_WORD;
        for i in 0..base64_words_count {
            let leb_base64_word = if i < leb_base64_words.len() { leb_base64_words[i] } else { 0 };
            region.assign_advice(
                || format!("leb_base64_word index {} value {}", i, leb_base64_word),
                self.config.leb_base64_words,
                i,
                || Value::known(F::from(leb_base64_word as u64)),
            ).unwrap();
        };
    }
}