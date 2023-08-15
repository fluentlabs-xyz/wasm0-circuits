use halo2_proofs::{
    plonk::{Advice, Column, ConstraintSystem},
};
use std::{marker::PhantomData};
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::plonk::Fixed;
use halo2_proofs::poly::Rotation;
use num_traits::pow;
use eth_types::Field;
use gadgets::util::{and, Expr, not, or, select};
use crate::evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon};
use crate::wasm_circuit::error::{Error, remap_error_to_assign_at_offset};
use crate::wasm_circuit::sections::consts::LebParams;

#[derive(Debug, Clone)]
pub struct LEB128Config<F> {
    pub q_enable: Column<Fixed>,
    pub is_signed: Column<Fixed>,
    pub is_first_byte: Column<Fixed>,
    pub is_last_byte: Column<Fixed>,
    pub is_byte_has_cb: Column<Fixed>,

    pub byte_mul: Column<Advice>,
    pub sn: Column<Advice>,
    pub sn_recovered: Column<Advice>,

    _marker: PhantomData<F>,
}

impl<F: Field> LEB128Config<F>
{}

#[derive(Debug, Clone)]
pub struct LEB128Chip<F> {
    pub config: LEB128Config<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> LEB128Chip<F>
{
    pub fn construct(config: LEB128Config<F>) -> Self {
        let instance = Self {
            config,
            _marker: PhantomData,
        };
        instance
    }

    pub fn configure(
        cs: &mut ConstraintSystem<F>,
        bytes: &Column<Advice>,
    ) -> LEB128Config<F> {
        let q_enable = cs.fixed_column();
        let is_signed = cs.fixed_column();
        let is_first_byte = cs.fixed_column();
        let is_last_byte = cs.fixed_column();
        let is_byte_has_cb = cs.fixed_column();

        let byte_mul = cs.advice_column();
        let sn = cs.advice_column();
        let sn_recovered = cs.advice_column();

        cs.create_gate("leb128 gate", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
            let is_signed_expr = vc.query_fixed(is_signed, Rotation::cur());
            let is_first_byte_expr = vc.query_fixed(is_first_byte, Rotation::cur());
            let is_last_byte_expr = vc.query_fixed(is_last_byte, Rotation::cur());
            let is_byte_has_cb_expr = vc.query_fixed(is_byte_has_cb, Rotation::cur());

            let leb_byte_mul_expr = vc.query_advice(byte_mul, Rotation::cur());
            let sn_expr = vc.query_advice(sn, Rotation::cur());
            let sn_recovered_expr = vc.query_advice(sn_recovered, Rotation::cur());

            let byte_val_expr = vc.query_advice(*bytes, Rotation::cur());

            let is_consider_byte_expr = select::expr(
                not::expr(is_first_byte_expr.clone()),
                vc.query_fixed(is_byte_has_cb, Rotation::prev()) + is_byte_has_cb_expr.clone() - vc.query_fixed(is_byte_has_cb, Rotation::prev()) * is_byte_has_cb_expr.clone(),
                1.expr(),
            );

            cb.require_boolean("q_enable is bool", q_enable_expr.clone());
            cb.require_boolean("is_signed is bool", is_signed_expr.clone());
            cb.require_boolean("is_first_byte is bool", is_first_byte_expr.clone());
            cb.require_boolean("is_last_byte is bool", is_last_byte_expr.clone());
            cb.require_boolean("is_byte_has_cb is bool", is_byte_has_cb_expr.clone());

            cb.condition(
                is_first_byte_expr.clone(),
                |cb| {
                    cb.require_zero(
                        "leb_byte_mul=1 at first byte",
                        leb_byte_mul_expr.clone() - 1.expr(),
                    );
                }
            );
            cb.condition(
                and::expr([
                    not::expr(is_first_byte_expr.clone()),
                    or::expr([
                        is_byte_has_cb_expr.clone(),
                        is_last_byte_expr.clone(),
                    ]),
                ]),
                |cb| {
                    let leb_byte_mul_prev_expr = vc.query_advice(byte_mul.clone(), Rotation::prev());
                    cb.require_equal(
                        "leb_byte_mul growth",
                        leb_byte_mul_prev_expr.clone() * 0b10000000.expr(),
                        leb_byte_mul_expr.clone(),
                    );
                }
            );

            cb.condition(
                not::expr(is_first_byte_expr.clone()),
                |cb| {
                    let is_signed_prev_expr = vc.query_fixed(is_signed, Rotation::prev());
                    cb.require_equal(
                        "is_signed consistent",
                        is_signed_prev_expr.clone(),
                        is_signed_expr.clone(),
                    );
                }
            );

            cb.condition(
                not::expr(is_first_byte_expr.clone()),
                |cb| {
                    let byte_has_cb_prev_expr = vc.query_fixed(is_byte_has_cb, Rotation::prev());
                    cb.require_zero(
                        "byte_has_cb eligible transitions: 1->1, 1->0, 0->0 but not 0->1",
                        not::expr(byte_has_cb_prev_expr.clone()) * is_byte_has_cb_expr.clone(),
                    );
                }
            );
            cb.condition(
                is_last_byte_expr.clone(),
                |cb| {
                    cb.require_zero(
                        "byte_has_cb is 0 on last_byte",
                        is_byte_has_cb_expr.clone(),
                    );
                }
            );

            cb.condition(
                and::expr([
                    not::expr(is_last_byte_expr.clone()),
                    is_consider_byte_expr.clone(),
                ]),
                |cb| {
                    let mut sn_recovered_manual_expr = (byte_val_expr.clone() - 0b10000000.expr() * is_byte_has_cb_expr.clone()) * leb_byte_mul_expr.clone();
                    let sn_recovered_prev_expr = select::expr(
                        not::expr(is_first_byte_expr.clone()),
                        vc.query_advice(sn_recovered, Rotation::prev()),
                        0.expr(),
                    );
                    sn_recovered_manual_expr = sn_recovered_manual_expr + sn_recovered_prev_expr.clone();
                    cb.require_equal(
                        "sn_recovered equals to sn_recovered_manual",
                        sn_recovered_manual_expr.clone(),
                        sn_recovered_expr.clone(),
                    )
                }
            );
            cb.condition(
                not::expr(is_first_byte_expr.clone()),
                |cb| {
                    let sn_prev_expr = vc.query_advice(sn, Rotation::prev());
                    cb.require_zero(
                        "prev.sn=next.sn inside the block",
                        sn_expr.clone() - sn_prev_expr.clone(),
                    );
                }
            );
            cb.condition(
                is_last_byte_expr.clone(),
                |cb| {
                    cb.require_equal(
                        "sn equals to recovered at the last leb byte",
                        sn_expr.clone(),
                        sn_recovered_expr.clone(),
                    );
                }
            );
            cb.condition(
                not::expr(is_consider_byte_expr.clone()),
                |cb| {
                    cb.require_zero(
                        "bytes after last leb byte have valid values (unsigned)",
                        not::expr(is_signed_expr.clone()) * byte_val_expr.clone(),
                    );
                    cb.require_zero(
                        "bytes after last leb byte have valid values (signed)",
                        is_signed_expr.clone() * (0xff.expr() - byte_val_expr.clone()),
                    );
                    // additional checks
                    cb.require_zero(
                        "flags are zero for unused zone",
                        is_first_byte_expr.clone() + is_last_byte_expr.clone() + is_byte_has_cb_expr.clone(),
                    );
                    cb.require_zero(
                        "leb_byte_mul is zero for unused zone",
                        leb_byte_mul_expr.clone(),
                    );
                }
            );

            cb.gate(q_enable_expr.clone())
        });

        let config = LEB128Config {
            q_enable,
            is_signed,
            is_first_byte,
            is_last_byte,
            is_byte_has_cb,
            byte_mul,
            sn,
            sn_recovered,
            _marker: PhantomData,
        };

        config
    }

    pub fn assign(
        &self,
        region: &mut Region<F>,
        offset: usize,
        q_enable: bool,
        p: LebParams,
    ) -> Result<(), Error> {
        region.assign_fixed(
            || format!("assign 'q_enable' to {} at {}", q_enable, offset),
            self.config.q_enable,
            offset,
            || Value::known(F::from(q_enable as u64)),
        ).map_err(remap_error_to_assign_at_offset(offset))?;

        region.assign_fixed(
            || format!("assign 'is_signed' to {} at {}", p.is_signed, offset),
            self.config.is_signed,
            offset,
            || Value::known(F::from(p.is_signed as u64)),
        ).map_err(remap_error_to_assign_at_offset(offset))?;

        region.assign_fixed(
            || format!("assign 'is_byte_has_cb' to {} at {}", p.is_byte_has_cb(), offset),
            self.config.is_byte_has_cb,
            offset,
            || Value::known(F::from(p.is_byte_has_cb() as u64)),
        ).map_err(remap_error_to_assign_at_offset(offset))?;

        region.assign_fixed(
            || format!("assign 'is_first_byte' to {} at {}", p.is_first_byte(), offset),
            self.config.is_first_byte,
            offset,
            || Value::known(F::from(p.is_first_byte() as u64)),
        ).map_err(remap_error_to_assign_at_offset(offset))?;

        region.assign_fixed(
            || format!("assign 'is_last_byte' to {} at {}", p.is_last_byte(), offset),
            self.config.is_last_byte,
            offset,
            || Value::known(F::from(p.is_last_byte() as u64)),
        ).map_err(remap_error_to_assign_at_offset(offset))?;

        let leb_byte_mul = if p.is_byte_has_cb() || p.is_last_byte() { pow(0b10000000, p.byte_rel_offset) } else { 0 };
        region.assign_advice(
            || format!("assign 'leb_byte_mul' to {} at {}", leb_byte_mul, offset),
            self.config.byte_mul,
            offset,
            || Value::known(F::from(leb_byte_mul)),
        ).map_err(remap_error_to_assign_at_offset(offset))?;

        let mut val = F::from(p.sn);
        if p.is_signed { val = val.neg() }
        region.assign_advice(
            || format!("assign 'sn' is_signed '{}' to {} at {}", p.is_signed, p.sn, offset),
            self.config.sn,
            offset,
            || Value::known(F::from(val)),
        ).map_err(remap_error_to_assign_at_offset(offset))?;

        let val = if p.is_signed && p.is_last_byte() {
            F::from(p.sn_recovered_at_pos).neg()
        } else {
            F::from(p.sn_recovered_at_pos)
        };
        region.assign_advice(
            || format!("assign 'sn_recovered' is_signed '{}' to {} at {}", p.is_signed, p.sn_recovered_at_pos, offset),
            self.config.sn_recovered,
            offset,
            || Value::known(val),
        ).map_err(remap_error_to_assign_at_offset(offset))?;

        Ok(())
    }
}