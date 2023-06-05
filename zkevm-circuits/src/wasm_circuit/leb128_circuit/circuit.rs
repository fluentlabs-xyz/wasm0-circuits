use halo2_proofs::{
    plonk::{Advice, Column, ConstraintSystem},
};
use std::{marker::PhantomData};
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::plonk::{Expression, Fixed, VirtualCells};
use halo2_proofs::poly::Rotation;
use num_traits::pow;
use eth_types::Field;
use gadgets::util::{and, Expr, not, select};
use crate::evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon};

///
#[derive(Debug, Clone)]
pub struct LEB128Config<F> {
    ///
    pub q_enable: Column<Fixed>,
    ///
    pub is_signed: Column<Fixed>,
    ///
    pub is_first_leb_byte: Column<Fixed>,
    ///
    pub is_last_leb_byte: Column<Fixed>,
    ///
    pub byte_has_cb: Column<Advice>,
    ///
    pub leb_byte_mul: Column<Advice>,
    ///
    pub sn: Column<Advice>,
    ///
    pub sn_recovered_at_pos: Column<Advice>,
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
        bytes: &Column<Advice>,
    ) -> LEB128Config<F> {
        let q_enable = cs.fixed_column();
        let is_signed = cs.fixed_column();
        let is_first_leb_byte = cs.fixed_column();
        let is_last_leb_byte = cs.fixed_column();
        let byte_has_cb = cs.advice_column();
        let leb_byte_mul = cs.advice_column();
        let sn = cs.advice_column();
        let sn_recovered_at_pos = cs.advice_column();

        cs.create_gate("leb128 gate", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
            let is_signed_expr = vc.query_fixed(is_signed, Rotation::cur());
            let is_first_leb_byte_expr = vc.query_fixed(is_first_leb_byte, Rotation::cur());
            let is_last_leb_byte_expr = vc.query_fixed(is_last_leb_byte, Rotation::cur());

            let byte_has_cb_expr = vc.query_advice(byte_has_cb, Rotation::cur());
            let leb_byte_mul_expr = vc.query_advice(leb_byte_mul, Rotation::cur());
            let sn_expr = vc.query_advice(sn, Rotation::cur());
            let sn_recovered_at_pos_expr = vc.query_advice(sn_recovered_at_pos, Rotation::cur());

            let byte_val_expr = vc.query_advice(*bytes, Rotation::cur());

            let is_consider_byte_expr = select::expr(
                not::expr(is_first_leb_byte_expr.clone()),
                vc.query_advice(byte_has_cb, Rotation::prev()) + byte_has_cb_expr.clone() - vc.query_advice(byte_has_cb, Rotation::prev()) * byte_has_cb_expr.clone(),
                q_enable_expr.clone(),
            );

            cb.require_boolean("q_enable is bool", q_enable_expr.clone());
            cb.require_boolean("is_signed is bool", is_signed_expr.clone());
            cb.require_boolean("is_first_leb_byte is bool", is_first_leb_byte_expr.clone());
            cb.require_boolean("is_last_leb_byte is bool", is_last_leb_byte_expr.clone());
            cb.require_boolean("byte_has_cb is bool", byte_has_cb_expr.clone());

            cb.condition(
                is_first_leb_byte_expr.clone(),
                |bcb| {
                    bcb.require_zero(
                        "leb_byte_mul=1 at first byte",
                        leb_byte_mul_expr.clone() - 1.expr(),
                    );
                }
            );
            cb.condition(
                not::expr(is_first_leb_byte_expr.clone()),
                |bcb| {
                    let leb_byte_mul_prev_expr = vc.query_advice(leb_byte_mul.clone(), Rotation::prev());
                    bcb.require_equal(
                        "leb_byte_mul growth consistently",
                        leb_byte_mul_prev_expr.clone() * 0b10000000.expr(),
                        leb_byte_mul_expr.clone(),
                    );
                }
            );

            cb.condition(
                not::expr(is_first_leb_byte_expr.clone()),
                |bcb| {
                    let is_signed_prev_expr = vc.query_fixed(is_signed, Rotation::prev());
                    bcb.require_equal(
                        "is_signed consistent",
                        is_signed_prev_expr.clone(),
                        is_signed_expr.clone(),
                    );
                }
            );

            cb.condition(
                is_last_leb_byte_expr.clone(),
                |bcb| {
                    bcb.require_zero(
                        "byte_has_cb is 0 on last_leb_byte",
                        byte_has_cb_expr.clone(),
                    );
                }
            );
            cb.condition(
                not::expr(is_first_leb_byte_expr.clone()),
                |bcb| {
                    let byte_has_cb_prev_expr = vc.query_advice(byte_has_cb, Rotation::prev());
                    bcb.require_zero(
                        "byte_has_cb eligible transitions: 1->1, 1->0, 0->0 but not 0->1",
                        not::expr(byte_has_cb_prev_expr.clone()) * byte_has_cb_expr.clone(),
                    );
                }
            );

            cb.condition(
                and::expr([
                    not::expr(is_last_leb_byte_expr.clone()),
                    is_consider_byte_expr.clone(),
                ]),
                |bcb| {
                    // TODO recover SN at current position and check it equals to sn_recovered_at_pos_expr
                    let mut sn_recovered_at_pos_manual_expr = (byte_val_expr.clone() - 0b10000000.expr() * byte_has_cb_expr.clone()) * leb_byte_mul_expr.clone();
                    let sn_recovered_at_pos_prev_expr = select::expr(
                        not::expr(is_first_leb_byte_expr.clone()),
                        vc.query_advice(sn_recovered_at_pos, Rotation::prev()),
                        0.expr(),
                    );
                    sn_recovered_at_pos_manual_expr = sn_recovered_at_pos_manual_expr + sn_recovered_at_pos_prev_expr.clone();
                    bcb.require_zero(
                        "sn_recovered_at_pos equals to manually recovered",
                        sn_recovered_at_pos_manual_expr - sn_recovered_at_pos_expr.clone(),
                    )
                }
            );
            cb.condition(
                and::expr([
                    is_last_leb_byte_expr.clone(),
                    is_consider_byte_expr.clone(),
                ]),
                |bcb| {
                    bcb.require_equal(
                        "solid number equals to recovered at the last leb byte",
                        sn_expr.clone(),
                        sn_recovered_at_pos_expr.clone(),
                    );
                }
            );
            cb.condition(
                    not::expr(is_first_leb_byte_expr.clone()),
                |bcb| {
                    let sn_prev_expr = vc.query_advice(sn, Rotation::prev());
                    bcb.require_zero(
                        "sn equals to previous inside the block",
                        sn_expr.clone() - sn_prev_expr.clone(),
                    );
                }
            );

            // cb.constraints.push(
            //     ("solid number equals to recovered at last byte", sn_expr.clone() - sn_recovered_at_pos_expr.clone()),
            // );

            // for (i, leb_base64_word_recovered) in leb_base64_words_recovered.iter().enumerate() {
            //     let leb_base64_word = vc.query_advice(leb_base64_word, Rotation(i as i32));
            //     cb.constraints.push((
            //         "base64 word equals to recovered base64 word",
            //         leb_base64_word_recovered.clone() - leb_base64_word.clone()
            //     ));
            // }

            cb.gate(q_enable_expr.clone())
        });

        let config = LEB128Config {
            q_enable,
            is_signed,
            is_first_leb_byte,
            is_last_leb_byte,
            byte_has_cb,
            leb_byte_mul,
            sn,
            sn_recovered_at_pos,
            _marker: PhantomData,
        };

        config
    }

    ///
    pub fn assign_init(
        &self,
        region: &mut Region<F>,
        offset_max: usize,
    ) {
        for offset in 0..=offset_max {
            self.assign(
                region,
                offset,
                0,
                false,
                false,
                false,
                false,
                false,
                0,
                0,
            );
        }
    }

    ///
    pub fn assign(
        &self,
        region: &mut Region<F>,
        offset: usize,
        leb_byte_offset: usize,
        enabled: bool,
        is_first_leb_byte: bool,
        is_last_leb_byte: bool,
        is_leb_byte_has_cb: bool,
        is_signed: bool,
        sn: u64,
        sn_recovered_at_pos: u64,
    ) {
        region.assign_fixed(
            || format!("assign 'q_enable' to {} at {}", enabled, offset),
            self.config.q_enable,
            offset,
            || Value::known(F::from(enabled as u64)),
        ).unwrap();

        region.assign_fixed(
            || format!("assign 'is_signed' to {} at {}", is_signed, offset),
            self.config.is_signed,
            offset,
            || Value::known(F::from(is_signed as u64)),
        ).unwrap();

        region.assign_advice(
            || format!("assign 'byte_has_cb' to {} at {}", is_leb_byte_has_cb, offset),
            self.config.byte_has_cb,
            offset,
            || Value::known(F::from(is_leb_byte_has_cb as u64)),
        ).unwrap();

        region.assign_fixed(
            || format!("assign 'is_first_leb_byte' to {} at {}", is_first_leb_byte, offset),
            self.config.is_first_leb_byte,
            offset,
            || Value::known(F::from(is_first_leb_byte as u64)),
        ).unwrap();

        region.assign_fixed(
            || format!("assign 'is_last_leb_byte' to {} at {}", is_last_leb_byte, offset),
            self.config.is_last_leb_byte,
            offset,
            || Value::known(F::from(is_last_leb_byte as u64)),
        ).unwrap();

        let leb_byte_mul = pow(0b10000000, leb_byte_offset);
        region.assign_advice(
            || format!("assign 'leb_byte_mul' to {} at {}", leb_byte_mul, offset),
            self.config.leb_byte_mul,
            offset,
            || Value::known(F::from(leb_byte_mul)),
        ).unwrap();

        let val = if is_signed {
            F::from(sn as u64).neg()
        } else {
            F::from(sn as u64)
        };
        region.assign_advice(
            || format!("assign 'sn' is_signed '{}' to {} at {}", is_signed, sn, offset),
            self.config.sn,
            offset,
            || Value::known(F::from(val)),
        ).unwrap();

        let val = if is_signed && is_last_leb_byte {
            F::from(sn_recovered_at_pos as u64).neg()
        } else {
            F::from(sn_recovered_at_pos as u64)
        };
        region.assign_advice(
            || format!("assign 'sn_recovered_at_pos' is_signed '{}' to {} at {}", is_signed, sn_recovered_at_pos, offset),
            self.config.sn_recovered_at_pos,
            offset,
            || Value::known(val),
        ).unwrap();
    }
}