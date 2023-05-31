use halo2_proofs::{
    plonk::{Advice, Column, ConstraintSystem},
};
use std::{marker::PhantomData};
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::plonk::{Constraints, Expression, Fixed, VirtualCells};
use halo2_proofs::poly::Rotation;
use eth_types::Field;
use gadgets::util::{Expr, not};
use crate::wasm_circuit::leb128_circuit::consts::{BYTES_IN_BASE64_WORD, EIGHT_LS_BITS_MASK};

/// LEB128Config
#[derive(Debug, Clone)]
pub struct LEB128Config<F> {
    /// base64 repr of leb128 (each row represents a part of leb)
    pub leb_base64_words: Column<Advice>,
    ///
    pub is_first_leb_byte: Column<Fixed>,
    ///
    pub byte_has_cb: Column<Advice>,
    _marker: PhantomData<F>,
}

///
impl<F: Field> LEB128Config<F>
{}

///
#[derive(Debug, Clone)]
pub struct LEB128Chip<F> {
    ///
    pub config: LEB128Config<F>,
    ///
    _marker: PhantomData<F>,
}

impl<F: Field> LEB128Chip<F>
{
    ///
    pub fn construct(config: LEB128Config<F>) -> Self {
        let instance = Self {
            config,
            _marker: PhantomData,
        };
        instance
    }

    ///
    pub fn configure(
        cs: &mut ConstraintSystem<F>,
        solid_number: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
        leb_bytes: &Column<Advice>,
        is_signed: bool,
        leb_bytes_n: usize,
    ) -> LEB128Config<F> {
        if leb_bytes_n <= 0 || leb_bytes_n > 10 {
            panic!("LEB128Config: unsupported LEB_BYTES_N {}, must be greater 0 and less than or equal 10", leb_bytes_n)
        }
        let is_first_leb_byte = cs.fixed_column();
        let leb_base64_words = cs.advice_column();
        let byte_has_cb = cs.advice_column();

        let mut cbs_constraints = Vec::<Expression<F>>::new();
        let mut cbs_transitions_constraints = Vec::<Expression<F>>::new();
        cs.create_gate("leb128 gate", |vc| {
            let is_first_leb_byte_expr = vc.query_fixed(is_first_leb_byte, Rotation::cur());
            let sn_expr = solid_number(vc);
            let mut sn_recovered_expr = 0.expr();
            let mut number_for_signed_inversion_expr = 0.expr();
            for i in (0..leb_bytes_n).rev() {
                let leb_byte_expr = vc.query_advice(*leb_bytes, Rotation(i as i32));
                let byte_has_cb_expr = vc.query_advice(byte_has_cb, Rotation(i as i32));
                let not_byte_has_cb_expr = not::expr(byte_has_cb_expr.clone());
                // continuation bit must be 0 or 1 value (boolean) (TODO replace with lookup)
                cbs_constraints.push(byte_has_cb_expr.clone() * (byte_has_cb_expr.clone() - 1.expr()));
                if i < leb_bytes_n - 1 {
                    let has_cb_next_expr = vc.query_advice(byte_has_cb, Rotation((i + 1) as i32));
                    // continuation bit (CB) eligible transitions: 1->1 or 1->0 or 0->0 not 0->1 (TODO replace with lookup)
                    cbs_transitions_constraints.push((byte_has_cb_expr.clone() - 1.expr()) * has_cb_next_expr);
                }
                if is_signed {
                    let has_cb_expr = vc.query_advice(byte_has_cb, Rotation(i as i32));
                    let mut is_consider_expr = 1.expr();
                    if i > 0 {
                        let has_cb_prev_expr = vc.query_advice(byte_has_cb, Rotation((i-1) as i32));
                        is_consider_expr = has_cb_prev_expr.clone() + has_cb_expr.clone() - has_cb_prev_expr * has_cb_expr;
                    }
                    number_for_signed_inversion_expr = number_for_signed_inversion_expr * 0b10000000.expr() + 0b1111111.expr() * is_consider_expr.clone();
                    sn_recovered_expr = sn_recovered_expr * 0b10000000.expr()
                        + (leb_byte_expr.clone() - 0b10000000.expr() * byte_has_cb_expr.expr()) * is_consider_expr.clone();
                } else {
                    sn_recovered_expr = sn_recovered_expr * 0b10000000.expr() + leb_byte_expr.clone() - byte_has_cb_expr * 0b10000000.expr();
                }
            }
            if is_signed {
                sn_recovered_expr = sn_recovered_expr.clone() - 1.expr() - number_for_signed_inversion_expr.clone();
            }

            let mut leb_base64_words_recovered = Vec::<Expression<F>>::new();
            let mut rot_idx = 0;
            let leb_bytes_index_max = leb_bytes_n - 1;
            for i in 0..=leb_bytes_index_max {
                if i % BYTES_IN_BASE64_WORD == 0 {
                    leb_base64_words_recovered.push(0.expr());
                    rot_idx = i + 7;
                    if rot_idx > leb_bytes_index_max { rot_idx = leb_bytes_index_max }
                } else {
                    rot_idx -= 1;
                }
                let mut leb_byte_expr = vc.query_advice(*leb_bytes, Rotation(rot_idx as i32));
                if rot_idx > 0 && is_signed {
                    let has_cb_prev_expr = vc.query_advice(byte_has_cb, Rotation((rot_idx - 1) as i32));
                    let has_cb_expr = vc.query_advice(byte_has_cb, Rotation(rot_idx as i32));
                    let is_consider_expr = has_cb_prev_expr.clone() + has_cb_expr.clone() - has_cb_prev_expr * has_cb_expr;
                    let is_not_consider_expr = not::expr(is_consider_expr.clone());
                    leb_byte_expr = leb_byte_expr - is_not_consider_expr.clone() * EIGHT_LS_BITS_MASK.expr();
                }
                let base64_words_last_index = leb_base64_words_recovered.len() - 1;
                let leb_base64_word = leb_base64_words_recovered[base64_words_last_index].clone();
                leb_base64_words_recovered[base64_words_last_index] = leb_byte_expr + leb_base64_word * 0b100000000.expr();
            }

            let mut constraints = Vec::new();
            constraints.push(
                ("solid number equals to recovered", sn_expr.clone() - sn_recovered_expr.clone()),
            );
            for cb_constraint in cbs_constraints {
                constraints.push(("continuation bit check", cb_constraint));
            }
            for continuation_bit_transition_constraint in cbs_transitions_constraints {
                constraints.push(("continuation bits transitions checks", continuation_bit_transition_constraint));
            }
            for (i, leb_base64_word_recovered) in leb_base64_words_recovered.iter().enumerate() {
                let leb_base64_word = vc.query_advice(leb_base64_words, Rotation(i as i32));
                constraints.push((
                    "base64 word equals to recovered base64 word",
                    leb_base64_word_recovered.clone() - leb_base64_word.clone()
                ));
            }
            Constraints::with_selector(
                is_first_leb_byte_expr,
                constraints,
            )
        });

        let config = LEB128Config {
            is_first_leb_byte,
            leb_base64_words,
            byte_has_cb,
            _marker: PhantomData,
        };

        config
    }

    ///
    pub fn init_assign(
        &self,
        region: &mut Region<F>,
        offset_max: usize,
    ) {
        for offset in 0..=offset_max {
            self.assign(
                region,
                offset,
                false,
                false,
                0
            );
        }
    }

    ///
    pub fn assign(
        &self,
        region: &mut Region<F>,
        offset: usize,
        is_first_leb_byte: bool,
        leb_byte_has_continuation_bit: bool,
        leb_base64_word: u64,
    ) {
        region.assign_advice(
            || format!("assign byte_has_cb val {} at {}", leb_byte_has_continuation_bit, offset),
            self.config.byte_has_cb,
            offset,
            || Value::known(F::from(leb_byte_has_continuation_bit as u64)),
        ).unwrap();

        region.assign_fixed(
            || format!("assign is_first_leb_byte val {} at {}", is_first_leb_byte, offset),
            self.config.is_first_leb_byte,
            offset,
            || Value::known(F::from(is_first_leb_byte as u64)),
        ).unwrap();

        region.assign_advice(
            || format!("assign leb_base64_word val {} at {}", leb_base64_word, offset),
            self.config.leb_base64_words,
            offset,
            || Value::known(F::from(leb_base64_word)),
        ).unwrap();
    }
}