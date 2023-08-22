use std::marker::PhantomData;

use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Expression, Fixed, VirtualCells},
    poly::Rotation,
};
use log::debug;

use eth_types::Field;
use gadgets::util::{and, not, or, Expr};

use crate::{
    evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon},
    wasm_circuit::{
        error::{remap_error_to_assign_at, Error},
        tables::dynamic_indexes::types::{AssignType, LookupArgsParams, Tag, TAG_VALUES},
        types::NewWbOffsetType,
    },
};

#[derive(Debug, Clone)]
pub struct DynamicIndexesConfig<F> {
    pub q_enable: Column<Fixed>,
    pub bytecode_number: Column<Advice>,
    pub index: Column<Advice>,
    pub is_terminator: Column<Fixed>,
    pub tag: Column<Fixed>,

    _marker: PhantomData<F>,
}

impl<'a, F: Field> DynamicIndexesConfig<F> {}

#[derive(Debug, Clone)]
pub struct DynamicIndexesChip<F> {
    pub config: DynamicIndexesConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> DynamicIndexesChip<F> {
    pub fn configure(cs: &mut ConstraintSystem<F>) -> DynamicIndexesConfig<F> {
        let q_enable = cs.fixed_column();
        let is_terminator = cs.fixed_column();
        let tag = cs.fixed_column();

        let bytecode_number = cs.advice_column();
        let index = cs.advice_column();

        cs.create_gate("DynamicIndexes gate", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());
            let q_enable_next_expr = vc.query_fixed(q_enable, Rotation::next());

            let is_terminator_expr = vc.query_fixed(is_terminator, Rotation::cur());
            let is_terminator_next_expr = vc.query_fixed(is_terminator, Rotation::next());

            let tag_expr = vc.query_fixed(tag, Rotation::cur());
            let tag_next_expr = vc.query_fixed(tag, Rotation::next());

            let bytecode_number_expr = vc.query_advice(bytecode_number, Rotation::cur());

            let index_expr = vc.query_advice(index, Rotation::cur());
            let index_next_expr = vc.query_advice(index, Rotation::next());

            cb.require_boolean("q_enable is boolean", q_enable_expr.clone());
            cb.require_boolean("is_terminator is boolean", is_terminator_expr.clone());

            cb.require_in_set(
                "tag => value is valid",
                tag_expr.clone(),
                TAG_VALUES.iter().map(|&v| v.expr()).collect(),
            );

            cb.condition(is_terminator_expr.clone(), |cb| {
                let is_terminator_prev_expr = vc.query_fixed(is_terminator, Rotation::prev());
                let is_terminator_next_expr = vc.query_fixed(is_terminator, Rotation::next());
                cb.require_equal(
                    "is_terminator -> prev.is_terminator=0",
                    is_terminator_prev_expr.clone(),
                    0.expr(),
                );
                cb.require_equal(
                    "is_terminator -> next.is_terminator=0",
                    is_terminator_next_expr.clone(),
                    0.expr(),
                );
            });

            cb.condition(not::expr(is_terminator_expr.clone()), |cb| {
                let bytecode_number_next_expr = vc.query_advice(bytecode_number, Rotation::cur());
                cb.require_equal(
                    "not_is_terminator -> bytecode_number=next.bytecode_number",
                    bytecode_number_expr.clone(),
                    bytecode_number_next_expr,
                );
            });

            cb.condition(
                and::expr([
                    is_terminator_expr.clone(),
                    not::expr(is_terminator_next_expr.clone()),
                    q_enable_next_expr.clone(),
                ]),
                |cb| {
                    let bytecode_number_next_expr =
                        vc.query_advice(bytecode_number, Rotation::cur());
                    cb.require_zero(
                        "not_is_terminator -> bytecode_number=next.bytecode_number || bytecode_number+1=next.bytecode_number",
                        (bytecode_number_next_expr.clone() - bytecode_number_expr.clone() - 1.expr()) *
                        (bytecode_number_next_expr.clone() - bytecode_number_expr.clone()),
                    );
                },
            );

            cb.condition(
                or::expr([
                    and::expr([
                        not::expr(is_terminator_expr.clone()),
                        not::expr(is_terminator_next_expr.clone()),
                    ]),
                    and::expr([
                        not::expr(is_terminator_expr.clone()),
                        is_terminator_next_expr.clone(),
                    ]),
                ]),
                |cb| {
                    cb.require_zero(
                        "tags are equal inside tag-block",
                        tag_expr.clone() - tag_next_expr.clone(),
                    );
                    cb.require_equal(
                        "index grows 1 by 1 inside tag-block",
                        index_expr.clone() + 1.expr(),
                        index_next_expr.clone(),
                    );
                },
            );

            cb.gate(q_enable_expr.clone())
        });

        let config = DynamicIndexesConfig::<F> {
            q_enable,
            is_terminator,
            tag,
            index,
            bytecode_number,

            _marker: Default::default(),
        };

        config
    }

    pub fn construct(config: DynamicIndexesConfig<F>) -> Self {
        let instance = Self {
            config,
            _marker: PhantomData,
        };
        instance
    }

    /// `cond_expr` - must be bool
    pub fn lookup(
        &self,
        cs: &mut ConstraintSystem<F>,
        name: &'static str,
        cond_expr: Expression<F>,
        index: i32,
        tag: Tag,
        is_terminator: bool,
    ) {
        cs.lookup_any(name, |vc| {
            vec![index.expr(), tag.expr(), is_terminator.expr()]
                .into_iter()
                .zip(
                    vec![
                        vc.query_advice(self.config.index, Rotation::cur()),
                        vc.query_fixed(self.config.tag, Rotation::cur()),
                        vc.query_fixed(self.config.is_terminator, Rotation::cur()),
                    ]
                    .into_iter(),
                )
                .map(|(arg, table)| (cond_expr.clone() * arg, table))
                .collect()
        });
    }

    pub fn lookup_args(
        &self,
        name: &'static str,
        cs: &mut ConstraintSystem<F>,
        p: impl FnOnce(&mut VirtualCells<'_, F>) -> LookupArgsParams<F>,
    ) {
        cs.lookup_any(name, |vc| {
            let p = p(vc);

            vec![
                (
                    p.cond.clone() * p.index,
                    vc.query_advice(self.config.index, Rotation::cur()),
                ),
                (
                    p.cond.clone() * p.tag,
                    vc.query_fixed(self.config.tag, Rotation::cur()),
                ),
                (
                    p.cond.clone() * p.is_terminator,
                    vc.query_fixed(self.config.is_terminator, Rotation::cur()),
                ),
            ]
        });
    }

    pub fn assign(
        &self,
        region: &mut Region<F>,
        offset: usize,
        assign_delta: usize,
        assign_type: AssignType,
        assign_value: u64,
    ) -> Result<(), Error> {
        let q_enable = true;
        let assign_offset = offset + assign_delta;
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
            .map_err(remap_error_to_assign_at(assign_offset))?;
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
            AssignType::Tag => {
                region
                    .assign_fixed(
                        || format!("assign 'tag' val {} at {}", assign_value, assign_offset),
                        self.config.tag,
                        assign_offset,
                        || Value::known(F::from(assign_value)),
                    )
                    .map_err(remap_error_to_assign_at(assign_offset))?;
            }
            AssignType::IsTerminator => {
                region
                    .assign_fixed(
                        || {
                            format!(
                                "assign 'is_terminator' val {} at {}",
                                assign_value, assign_offset
                            )
                        },
                        self.config.is_terminator,
                        assign_offset,
                        || Value::known(F::from(assign_value)),
                    )
                    .map_err(remap_error_to_assign_at(assign_offset))?;
            }
            AssignType::BytecodeNumber => {
                region
                    .assign_advice(
                        || {
                            format!(
                                "assign 'bytecode_number' val {} at {}",
                                assign_value, assign_offset
                            )
                        },
                        self.config.bytecode_number,
                        assign_offset,
                        || Value::known(F::from(assign_value)),
                    )
                    .map_err(remap_error_to_assign_at(assign_offset))?;
            }
        }

        Ok(())
    }

    pub fn assign_auto(
        &self,
        region: &mut Region<F>,
        start_offset: usize,
        assign_delta: usize,
        indexes_count: usize,
        bytecode_number: u64,
        tag: Tag,
    ) -> Result<NewWbOffsetType, Error> {
        let mut offset = start_offset;
        for rel_offset in 0..indexes_count + 1 {
            offset += 1;
            self.assign(
                region,
                offset,
                assign_delta,
                AssignType::BytecodeNumber,
                bytecode_number,
            )?;
            self.assign(
                region,
                offset,
                assign_delta,
                AssignType::Index,
                rel_offset as u64,
            )?;
            self.assign(region, offset, assign_delta, AssignType::Tag, tag as u64)?;
            if rel_offset == indexes_count {
                self.assign(region, offset, assign_delta, AssignType::IsTerminator, 1)?;
            }
        }

        Ok(offset)
    }
}
