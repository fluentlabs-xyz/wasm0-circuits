use std::{marker::PhantomData, rc::Rc};

use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Fixed},
    poly::Rotation,
};
use log::debug;

use eth_types::Field;
use gadgets::{
    binary_number::BinaryNumberChip,
    util::{and, not, Expr},
};

use crate::{
    evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon},
    wasm_circuit::{
        common::configure_constraints_for_q_first_and_q_last,
        error::{remap_error_to_assign_at, remap_error_to_invalid_enum_value_at, Error},
        tables::code_blocks::types::{AssignType, Opcode, OPCODE_VALUES},
    },
};

#[derive(Debug, Clone)]
pub struct CodeBlocksConfig<F> {
    pub q_enable: Column<Fixed>,
    pub q_first: Column<Fixed>,
    pub q_last: Column<Fixed>,
    pub index: Column<Advice>,
    pub opcode: Column<Advice>,

    pub opcode_chip: Rc<BinaryNumberChip<F, Opcode, 8>>,

    _marker: PhantomData<F>,
}

impl<'a, F: Field> CodeBlocksConfig<F> {}

#[derive(Debug, Clone)]
pub struct CodeBlocksChip<F> {
    pub config: CodeBlocksConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> CodeBlocksChip<F> {
    pub fn construct(config: CodeBlocksConfig<F>) -> Self {
        let instance = Self {
            config,
            _marker: PhantomData,
        };
        instance
    }

    pub fn configure(cs: &mut ConstraintSystem<F>) -> CodeBlocksConfig<F> {
        let q_enable = cs.fixed_column();
        let q_first = cs.fixed_column();
        let q_last = cs.fixed_column();
        let opcode = cs.advice_column();

        let index = cs.advice_column();

        let config = BinaryNumberChip::configure(cs, q_enable, Some(opcode.into()));
        let opcode_chip = Rc::new(BinaryNumberChip::construct(config));

        cs.create_gate("CodeBlocks gate", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
            let q_first_expr = vc.query_fixed(q_first, Rotation::cur());
            // let not_q_first_expr = not::expr(q_first_expr.clone());
            let q_last_expr = vc.query_fixed(q_last, Rotation::cur());
            let not_q_last_expr = not::expr(q_last_expr.clone());

            let opcode_expr = vc.query_advice(opcode, Rotation::cur());
            // let opcode_next_expr = vc.query_advice(opcode, Rotation::next());

            let index_expr = vc.query_advice(index, Rotation::cur());
            // let index_next_expr = vc.query_advice(index, Rotation::next());

            let opcode_is_block_expr =
                opcode_chip
                    .config
                    .value_equals(Opcode::Block, Rotation::cur())(vc);
            let opcode_is_block_next_expr =
                opcode_chip
                    .config
                    .value_equals(Opcode::Block, Rotation::next())(vc);
            let opcode_is_loop_expr =
                opcode_chip
                    .config
                    .value_equals(Opcode::Loop, Rotation::cur())(vc);
            let opcode_is_loop_next_expr =
                opcode_chip
                    .config
                    .value_equals(Opcode::Loop, Rotation::next())(vc);
            let opcode_is_if_expr =
                opcode_chip.config.value_equals(Opcode::If, Rotation::cur())(vc);
            let opcode_is_if_next_expr =
                opcode_chip
                    .config
                    .value_equals(Opcode::If, Rotation::next())(vc);
            let opcode_is_else_expr =
                opcode_chip
                    .config
                    .value_equals(Opcode::Else, Rotation::cur())(vc);
            let opcode_is_else_next_expr =
                opcode_chip
                    .config
                    .value_equals(Opcode::Else, Rotation::next())(vc);
            let opcode_is_end_expr = opcode_chip
                .config
                .value_equals(Opcode::End, Rotation::cur())(vc);
            let opcode_is_end_next_expr =
                opcode_chip
                    .config
                    .value_equals(Opcode::End, Rotation::next())(vc);

            cb.require_boolean("q_enable is boolean", q_enable_expr.clone());

            configure_constraints_for_q_first_and_q_last(
                &mut cb,
                vc,
                &q_enable,
                &q_first,
                &[],
                &q_last,
                &[],
            );

            cb.require_in_set(
                "opcode => value is valid",
                opcode_expr.clone(),
                OPCODE_VALUES.iter().map(|&v| v.expr()).collect(),
            );

            cb.require_equal(
                "q_first => index=1",
                q_first_expr.clone() * index_expr.clone(),
                q_first_expr.clone(),
            );

            cb.condition(not_q_last_expr.clone(), |cb| {
                let index_next_expr = vc.query_advice(index, Rotation::next());
                cb.require_zero(
                    "index grows +1",
                    index_expr.clone() + 1.expr() - index_next_expr.clone(),
                );
            });

            cb.condition(
                and::expr([not_q_last_expr.clone(), opcode_is_block_expr.clone()]),
                |cb| {
                    cb.require_equal(
                        "block -> block | loop | if | end",
                        opcode_is_block_next_expr.clone()
                            + opcode_is_loop_next_expr.clone()
                            + opcode_is_if_next_expr.clone()
                            + opcode_is_end_next_expr.clone(),
                        1.expr(),
                    );
                },
            );

            cb.condition(
                and::expr([not_q_last_expr.clone(), opcode_is_loop_expr.clone()]),
                |cb| {
                    cb.require_equal(
                        "loop -> block | loop | if | end",
                        opcode_is_block_next_expr.clone()
                            + opcode_is_loop_next_expr.clone()
                            + opcode_is_if_next_expr.clone()
                            + opcode_is_end_next_expr.clone(),
                        1.expr(),
                    );
                },
            );

            cb.condition(
                and::expr([not_q_last_expr.clone(), opcode_is_if_expr.clone()]),
                |cb| {
                    cb.require_equal(
                        "if -> block | loop | if | else | end",
                        opcode_is_block_next_expr.clone()
                            + opcode_is_loop_next_expr.clone()
                            + opcode_is_if_next_expr.clone()
                            + opcode_is_else_next_expr.clone()
                            + opcode_is_end_next_expr.clone(),
                        1.expr(),
                    );
                },
            );

            cb.condition(
                and::expr([not_q_last_expr.clone(), opcode_is_else_expr.clone()]),
                |cb| {
                    cb.require_equal("else -> end", opcode_is_end_next_expr.clone(), 1.expr());
                },
            );

            cb.condition(
                and::expr([not_q_last_expr.clone(), opcode_is_block_expr.clone()]),
                |cb| {
                    cb.require_equal(
                        "end -> block | loop | if | end",
                        opcode_is_block_next_expr.clone()
                            + opcode_is_loop_next_expr.clone()
                            + opcode_is_if_next_expr.clone()
                            + opcode_is_end_next_expr.clone(),
                        1.expr(),
                    );
                },
            );

            cb.condition(q_last_expr.clone(), |cb| {
                cb.require_equal(
                    "q_last => opcode_is_end",
                    opcode_is_end_expr.clone(),
                    1.expr(),
                );
            });

            cb.gate(q_enable_expr.clone())
        });

        let config = CodeBlocksConfig::<F> {
            _marker: PhantomData,

            q_enable,
            q_first,
            q_last,
            opcode,
            index,
            opcode_chip,
        };

        config
    }

    pub fn assign(
        &self,
        region: &mut Region<F>,
        assign_offset: usize,
        assign_type: AssignType,
        assign_value: u64,
    ) -> Result<(), Error> {
        let q_enable = true;
        debug!(
            "assign at {} q_enable {} assign_type {:?} assign_value {:?}",
            assign_offset, q_enable, assign_type, assign_value,
        );
        region
            .assign_fixed(
                || format!("assign 'q_enable' val {} at {}", q_enable, assign_offset),
                self.config.q_enable,
                assign_offset,
                || Value::known(F::from(q_enable as u64)),
            )
            .unwrap();
        match assign_type {
            AssignType::Index => {
                region
                    .assign_advice(
                        || format!("assign 'index' val {} at {}", assign_value, assign_offset),
                        self.config.index,
                        assign_offset,
                        || Value::known(F::from(assign_value)),
                    )
                    .map_err(remap_error_to_assign_at(assign_offset))?;
            }
            AssignType::Opcode => {
                region
                    .assign_advice(
                        || format!("assign 'opcode' val {} at {}", assign_value, assign_offset),
                        self.config.opcode,
                        assign_offset,
                        || Value::known(F::from(assign_value)),
                    )
                    .map_err(remap_error_to_assign_at(assign_offset))?;
                let opcode: Opcode = (assign_value as u8)
                    .try_into()
                    .map_err(remap_error_to_invalid_enum_value_at(assign_offset))?;
                self.config
                    .opcode_chip
                    .assign(region, assign_offset, &opcode)
                    .map_err(remap_error_to_assign_at(assign_offset))?;
            }
            AssignType::QFirst => {
                region
                    .assign_fixed(
                        || format!("assign 'q_first' val {} at {}", assign_value, assign_offset),
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
        }
        Ok(())
    }
}
