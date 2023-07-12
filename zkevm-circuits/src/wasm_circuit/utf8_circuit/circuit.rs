use halo2_proofs::{
    plonk::{Advice, Column, ConstraintSystem},
};
use std::{marker::PhantomData};
use std::rc::Rc;
use halo2_proofs::circuit::{Chip, Region, Value};
use halo2_proofs::plonk::Fixed;
use halo2_proofs::poly::Rotation;
use num_traits::pow;
use eth_types::Field;
use gadgets::is_zero::{IsZeroChip, IsZeroInstruction};
use gadgets::util::{Expr, not};
use crate::evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon};
use crate::wasm_circuit::bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::tables::fixed_range::config::RangeTableConfig;

#[derive(Debug, Clone)]
pub struct UTF8Config<F: Field> {
    pub q_enable: Column<Fixed>,
    // pub is_first_byte: Column<Fixed>,
    // pub is_last_byte: Column<Fixed>,
    // pub is_bytes_count_1: Column<Fixed>,
    // pub is_bytes_count_2: Column<Fixed>,
    // pub is_bytes_count_3: Column<Fixed>,
    // pub is_bytes_count_4: Column<Fixed>,

    // pub codepoint: Column<Advice>,
    // pub codepoint_recovered: Column<Advice>,
    // pub byte_mul: Column<Advice>,
    pub(crate) byte_val_is_zero_chip: IsZeroChip<F>,
    pub(crate) eligible_byte_vals_range_table_config: Rc<RangeTableConfig<F, 0, 128>>,

    _marker: PhantomData<F>,
}

impl<F: Field> UTF8Config<F>
{}

#[derive(Debug, Clone)]
pub struct UTF8Chip<F: Field> {
    pub config: UTF8Config<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> UTF8Chip<F>
{
    pub fn construct(config: UTF8Config<F>) -> Self {
        let instance = Self {
            config,
            _marker: PhantomData,
        };
        instance
    }

    pub fn configure(
        cs: &mut ConstraintSystem<F>,
        eligible_byte_vals_range_table_config: Rc<RangeTableConfig<F, 0, 128>>,
        bytes: &Column<Advice>,
    ) -> UTF8Config<F> {
        let q_enable = cs.fixed_column();
        // let is_first_byte = cs.fixed_column();
        // let is_last_byte = cs.fixed_column();
        // let is_bytes_count_1 = cs.fixed_column();
        // let is_bytes_count_2 = cs.fixed_column();
        // let is_bytes_count_3 = cs.fixed_column();
        // let is_bytes_count_4 = cs.fixed_column();

        // let codepoint = cs.advice_column();
        // let codepoint_recovered = cs.advice_column();
        // let byte_mul = cs.advice_column();

        let value_inv = cs.advice_column();
        let byte_val_is_zero_config = IsZeroChip::configure(
            cs,
            |vc| vc.query_fixed(q_enable, Rotation::cur()),
            |vc| vc.query_advice(*bytes, Rotation::cur()),
            value_inv,
        );
        let byte_val_is_zero_chip = IsZeroChip::construct(byte_val_is_zero_config);

        cs.create_gate("UTF8 gate: q_enable=1", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
            // let is_first_byte_expr = vc.query_fixed(is_first_byte, Rotation::cur());
            // let is_last_byte_expr = vc.query_fixed(is_last_byte, Rotation::cur());
            // let is_bytes_count_1_expr = vc.query_fixed(is_bytes_count_1, Rotation::cur());
            // let is_bytes_count_2_expr = vc.query_fixed(is_bytes_count_2, Rotation::cur());
            // let is_bytes_count_3_expr = vc.query_fixed(is_bytes_count_3, Rotation::cur());
            // let is_bytes_count_4_expr = vc.query_fixed(is_bytes_count_4, Rotation::cur());

            // let codepoint_expr = vc.query_advice(codepoint, Rotation::cur());
            // let byte_mul_expr = vc.query_advice(byte_mul, Rotation::cur());
            // let codepoint_recovered_expr = vc.query_advice(codepoint_recovered, Rotation::cur());

            // let byte_val_expr = vc.query_advice(*bytes, Rotation::cur());

            cb.require_boolean("q_enable is bool", q_enable_expr.clone());
            // cb.require_boolean("is_first_byte is bool", is_first_byte_expr.clone());
            // cb.require_boolean("is_last_byte is bool", is_last_byte_expr.clone());
            // cb.require_boolean("is_bytes_count_1 is bool", is_bytes_count_1_expr.clone());
            // cb.require_boolean("is_bytes_count_2 is bool", is_bytes_count_2_expr.clone());
            // cb.require_boolean("is_bytes_count_3 is bool", is_bytes_count_3_expr.clone());
            // cb.require_boolean("is_bytes_count_4 is bool", is_bytes_count_4_expr.clone());

            cb.require_zero("q_enable=1 -> byte_val!=0", byte_val_is_zero_chip.config().expr());

            // TODO test
            // cb.condition(
            //     q_enable_expr.clone(),
            //     |bcb| {
            //         bcb.require_zero(
            //             "test",
            //             (1..pow(2, 7) - 1)
            //                 .fold(
            //                     1.expr(),
            //                     |acc, x| { acc.clone() * (x.expr() - byte_val_expr.clone()) },
            //                 )
            //         );
            //     }
            // );

            // cb.require_equal(
            //     "exactly one is_bytes_count_X must be active at the same time",
            //     is_bytes_count_1_expr.clone() + is_bytes_count_2_expr.clone() + is_bytes_count_3_expr.clone() + is_bytes_count_4_expr.clone(),
            //     1.expr(),
            // );
            // cb.condition(
            //     not::expr(is_first_byte_expr.clone()),
            //     |bcb| {
            //         let is_bytes_count_1_prev_expr = vc.query_fixed(is_bytes_count_1, Rotation::prev());
            //         bcb.require_equal("is_first_byte=0 -> prev.is_byte_count_1 = cur.is_byte_count_1", is_bytes_count_1_prev_expr, is_bytes_count_1_expr.clone());
            //         let is_bytes_count_2_prev_expr = vc.query_fixed(is_bytes_count_2, Rotation::prev());
            //         bcb.require_equal("is_first_byte=0 -> prev.is_byte_count_2 = cur.is_byte_count_2", is_bytes_count_2_prev_expr, is_bytes_count_2_expr.clone());
            //         let is_bytes_count_3_prev_expr = vc.query_fixed(is_bytes_count_3, Rotation::prev());
            //         bcb.require_equal("is_first_byte=0 -> prev.is_byte_count_3 = cur.is_byte_count_3", is_bytes_count_3_prev_expr, is_bytes_count_3_expr.clone());
            //         let is_bytes_count_4_prev_expr = vc.query_fixed(is_bytes_count_4, Rotation::prev());
            //         bcb.require_equal("is_first_byte=0 -> prev.is_byte_count_4 = cur.is_byte_count_4", is_bytes_count_4_prev_expr, is_bytes_count_4_expr.clone());
            //     }
            // );
            //
            // // transition checks: is_first_byte{1} -> q_enable* -> is_last_byte{1}
            // configure_check_for_transition(
            //     &mut cb,
            //     vc,
            //     "check next: is_first_byte{1} -> q_enable* -> is_last_byte{1}",
            //     and::expr([
            //         is_first_byte_expr.clone(),
            //         not::expr(is_last_byte_expr.clone()),
            //     ]),
            //     true,
            //     &[q_enable, is_last_byte],
            // );
            // configure_check_for_transition(
            //     &mut cb,
            //     vc,
            //     "check prev: is_first_byte{1} -> q_enable*",
            //     and::expr([
            //         q_enable_expr.clone(),
            //         not::expr(is_first_byte_expr.clone()),
            //     ]),
            //     false,
            //     &[is_first_byte, q_enable],
            // );
            // configure_check_for_transition(
            //     &mut cb,
            //     vc,
            //     "check next: q_enable* -> is_last_byte{1}",
            //     and::expr([
            //         q_enable_expr.clone(),
            //         not::expr(is_last_byte_expr.clone()),
            //     ]),
            //     true,
            //     &[q_enable, is_last_byte],
            // );
            // configure_check_for_transition(
            //     &mut cb,
            //     vc,
            //     "check prev: is_first_byte{1} -> q_enable* -> is_last_byte{1}",
            //     and::expr([
            //         not::expr(is_first_byte_expr.clone()),
            //         is_last_byte_expr.clone(),
            //     ]),
            //     false,
            //     &[is_first_byte, q_enable],
            // );
            //
            // cb.condition(
            //     is_last_byte_expr.clone(),
            //     |cbc| {
            //         cbc.require_equal(
            //             "is_last_byte=1 -> byte_mul=1",
            //             byte_mul_expr.clone(),
            //             1.expr(),
            //         )
            //     }
            // );
            // cb.condition(
            //     not::expr(is_last_byte_expr.clone()),
            //     |cbc| {
            //         let byte_mul_next = vc.query_advice(byte_mul, Rotation::next());
            //         cbc.require_equal(
            //             "is_last_byte=0 -> cur.byte_mul=next.byte_mul * 0b1000000",
            //             byte_mul_expr.clone(),
            //             byte_mul_next * 0b1000000.expr(),
            //         )
            //     }
            // );
            //
            // cb.condition(
            //     not::expr(is_last_byte_expr.clone()),
            //     |bcb| {
            //         let codepoint_recovered_prev_expr = select::expr(
            //             not::expr(is_first_byte_expr.clone()),
            //             vc.query_advice(codepoint_recovered, Rotation::prev()),
            //             0.expr(),
            //         );
            //         let bit_mask_expr = select::expr(
            //             is_first_byte_expr.clone(),
            //             is_bytes_count_1_expr.clone() * 0b0.expr()
            //                 + is_bytes_count_2_expr.clone() * 0b11000000.expr()
            //                 + is_bytes_count_3_expr.clone() * 0b11100000.expr()
            //                 + is_bytes_count_4_expr.clone() * 0b11110000.expr(),
            //             0b10000000.expr(),
            //         );
            //         bcb.require_equal(
            //             "is_last_byte=0 -> codepoint_recovered = codepoint_recovered_prev + (byte_val - byte_mask) * byte_mul",
            //             codepoint_recovered_expr.clone(),
            //             codepoint_recovered_prev_expr.clone() + (byte_val_expr.clone() - bit_mask_expr.clone()) * byte_mul_expr.clone(),
            //         )
            //     }
            // );
            // cb.condition(
            //     is_last_byte_expr.clone(),
            //     |bcb| {
            //         bcb.require_equal(
            //             "is_last_byte=1 -> codepoint_recovered=codepoint",
            //             codepoint_recovered_expr.clone(),
            //             codepoint_expr.clone(),
            //         )
            //     }
            // );

            // to do: is_first_byte=1 -> remove bit mask and check that value greater 0 (checks for 'overlong encoding' -> not a valid utf8 according to specs)

            // cb.condition(
            //     not::expr(is_first_byte_expr.clone()),
            //     |bcb| {
            //         let codepoint_prev_expr = vc.query_advice(codepoint, Rotation::prev());
            //         bcb.require_equal(
            //             "is_first_byte=0 -> prev.codepoint = cur.codepoint",
            //             codepoint_prev_expr,
            //             codepoint_expr.clone(),
            //         )
            //     }
            // );
            //
            // // block of checks below is for: is_first_byte=1 -> bit mask is valid according to number of bytes for encoding
            // cb.condition(
            //     and::expr([
            //         is_first_byte_expr.clone(),
            //         is_bytes_count_1_expr.clone(),
            //     ]),
            //     |bcb| {
            //         let bit_mask_expr = 0b0.expr();
            //         let byte_val_without_mask_expr = byte_val_expr.clone() - bit_mask_expr.clone();
            //         // TODO replace with lookup
            //         bcb.require_equal(
            //             "is_first_byte=0 -> byte_val-0b00000000 must belong to [1..2^7-1]",
            //             (1..pow(2, 7)-1).fold(1.expr(), |acc, x| { acc.clone() * (x.expr() - byte_val_without_mask_expr.clone()) }),
            //             0.expr(),
            //         )
            //     }
            // );
            // cb.condition(
            //     and::expr([
            //         is_first_byte_expr.clone(),
            //         is_bytes_count_2_expr.clone(),
            //     ]),
            //     |bcb| {
            //         let bit_mask_expr = 0b0.expr();
            //         let byte_val_without_mask_expr = byte_val_expr.clone() - bit_mask_expr.clone();
            //         // TODO replace with lookup
            //         bcb.require_equal(
            //             "is_first_byte=0 -> byte_val-0b11000000 must belong to [1..2^5-1]",
            //             (1..pow(2, 5)-1).fold(1.expr(), |acc, x| { acc.clone() * (x.expr() - byte_val_without_mask_expr.clone()) }),
            //             0.expr(),
            //         )
            //     }
            // );
            // cb.condition(
            //     and::expr([
            //         is_first_byte_expr.clone(),
            //         is_bytes_count_3_expr.clone(),
            //     ]),
            //     |bcb| {
            //         let bit_mask_expr = 0b0.expr();
            //         let byte_val_without_mask_expr = byte_val_expr.clone() - bit_mask_expr.clone();
            //         // TODO replace with lookup
            //         bcb.require_equal(
            //             "is_first_byte=0 -> byte_val-0b11000000 must belong to [1..2^4-1]",
            //             (1..pow(2, 4)-1).fold(1.expr(), |acc, x| { acc.clone() * (x.expr() - byte_val_without_mask_expr.clone()) }),
            //             0.expr(),
            //         )
            //     }
            // );
            // cb.condition(
            //     and::expr([
            //         is_first_byte_expr.clone(),
            //         is_bytes_count_4_expr.clone(),
            //     ]),
            //     |bcb| {
            //         let bit_mask_expr = 0b0.expr();
            //         let byte_val_without_mask_expr = byte_val_expr.clone() - bit_mask_expr.clone();
            //         // TODO replace with lookup
            //         bcb.require_equal(
            //             "is_first_byte=0 -> byte_val-0b11000000 must belong to [1..2^3-1]",
            //             (1..pow(2, 3)-1).fold(1.expr(), |acc, x| { acc.clone() * (x.expr() - byte_val_without_mask_expr.clone()) }),
            //             0.expr(),
            //         )
            //     }
            // );
            // cb.condition(
            //     not::expr(is_first_byte_expr.clone()),
            //     |bcb| {
            //         let bit_mask_expr = 0b10000000.expr();
            //         let byte_val_without_mask_expr = byte_val_expr.clone() - bit_mask_expr;
            //         // TODO replace with lookup
            //         bcb.require_equal(
            //             "is_first_byte=0 -> byte_val-0b10000000 must belong to [1..2^6-1]",
            //             (1..pow(2, 6)-1).fold(1.expr(), |acc, x| { acc.clone() * (x.expr() - byte_val_without_mask_expr.clone()) }),
            //             0.expr(),
            //         )
            //     }
            // );

            cb.gate(q_enable_expr.clone())
        });

        cs.lookup("byte values are UTF8 ASCII compatible", |vc| {
            let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
            let byte_val_expr = vc.query_advice(*bytes, Rotation::cur());

            vec![(q_enable_expr * byte_val_expr, eligible_byte_vals_range_table_config.value)]
        });

        // cs.create_gate("UTF8 gate: q_enable=0", |vc| {
        //     let mut cb = BaseConstraintBuilder::default();
        //
        //     let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
        //     let is_first_byte_expr = vc.query_fixed(is_first_byte, Rotation::cur());
        //
        //     cb.require_zero("is_first_byte=0", is_first_byte_expr.clone());
        //     cb.require_zero("is_last_byte=0", is_first_byte_expr.clone());
        //
        //     cb.gate(not::expr(q_enable_expr.clone()))
        // });

        let config = UTF8Config {
            q_enable,
            // is_first_byte,
            // is_last_byte,
            // is_bytes_count_1,
            // is_bytes_count_2,
            // is_bytes_count_3,
            // is_bytes_count_4,
            // codepoint,
            // codepoint_recovered,
            // byte_mul,
            byte_val_is_zero_chip,
            eligible_byte_vals_range_table_config,
            _marker: PhantomData,
        };

        config
    }

    pub fn assign(
        &self,
        region: &mut Region<F>,
        offset: usize,
        q_enable: bool,
        byte_val: u8,
        // is_first_byte: bool,
        // is_last_byte: bool,
        // codepoint: u64,
        // codepoint_recovered: u64,
        // byte_mul: u64,
        // bytes_count: u8,
    ) {
        self.config.byte_val_is_zero_chip.assign(region, offset, Value::known(F::from(byte_val as u64))).unwrap();

        region.assign_fixed(
            || format!("assign 'q_enable' to {} at {}", q_enable, offset),
            self.config.q_enable,
            offset,
            || Value::known(F::from(q_enable as u64)),
        ).unwrap();

        // region.assign_fixed(
        //     || format!("assign 'is_first_byte' to {} at {}", is_first_byte, offset),
        //     self.config.is_first_byte,
        //     offset,
        //     || Value::known(F::from(is_first_byte as u64)),
        // ).unwrap();
        //
        // region.assign_fixed(
        //     || format!("assign 'is_last_byte' to {} at {}", is_last_byte, offset),
        //     self.config.is_last_byte,
        //     offset,
        //     || Value::known(F::from(is_last_byte as u64)),
        // ).unwrap();
        //
        // region.assign_fixed(
        //     || format!("assign 'is_bytes_count_1' to {} at {}", bytes_count=1, offset),
        //     self.config.is_bytes_count_1,
        //     offset,
        //     || Value::known(F::from((bytes_count=1) as u64)),
        // ).unwrap();
        // region.assign_fixed(
        //     || format!("assign 'is_bytes_count_2' to {} at {}", bytes_count=2, offset),
        //     self.config.is_bytes_count_2,
        //     offset,
        //     || Value::known(F::from((bytes_count=2) as u64)),
        // ).unwrap();
        // region.assign_fixed(
        //     || format!("assign 'is_bytes_count_3' to {} at {}", bytes_count=3, offset),
        //     self.config.is_bytes_count_3,
        //     offset,
        //     || Value::known(F::from((bytes_count=3) as u64)),
        // ).unwrap();
        // region.assign_fixed(
        //     || format!("assign 'is_bytes_count_4' to {} at {}", bytes_count=4, offset),
        //     self.config.is_bytes_count_4,
        //     offset,
        //     || Value::known(F::from((bytes_count=4) as u64)),
        // ).unwrap();
        //
        // region.assign_advice(
        //     || format!("assign 'codepoint' to {} at {}", codepoint, offset),
        //     self.config.codepoint,
        //     offset,
        //     || Value::known(F::from(codepoint)),
        // ).unwrap();
        //
        // region.assign_advice(
        //     || format!("assign 'codepoint_recovered' to {} at {}", codepoint_recovered, offset),
        //     self.config.codepoint_recovered,
        //     offset,
        //     || Value::known(F::from(codepoint_recovered)),
        // ).unwrap();
        //
        // region.assign_advice(
        //     || format!("assign 'byte_mul' to {} at {}", byte_mul, offset),
        //     self.config.byte_mul,
        //     offset,
        //     || Value::known(F::from(byte_mul)),
        // ).unwrap();
    }

    pub fn assign_auto(
        &self,
        region: &mut Region<F>,
        wasm_bytecode: &WasmBytecode,
        bytecode_chunk_len: usize,
        bytecode_offset_start: usize,
        region_offset_start: usize,
    ) {
        for (offset, bytecode_offset) in (bytecode_offset_start..bytecode_offset_start + bytecode_chunk_len).enumerate() {
            self.assign(
                region,
                region_offset_start + offset,
                true,
                wasm_bytecode.bytes[bytecode_offset],
            )
        }
    }
}