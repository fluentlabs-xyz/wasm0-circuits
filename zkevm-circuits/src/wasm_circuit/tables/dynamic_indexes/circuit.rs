use halo2_proofs::{
    plonk::{Column, ConstraintSystem},
};
use std::{marker::PhantomData};
use halo2_proofs::circuit::{Region, Value};
use halo2_proofs::plonk::{Advice, Expression, Fixed, VirtualCells};
use halo2_proofs::poly::Rotation;
use log::debug;
use eth_types::Field;
use gadgets::util::{and, Expr, not, or};
use crate::evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon};
use crate::wasm_circuit::error::Error;
use crate::wasm_circuit::tables::dynamic_indexes::types::{AssignType, Tag, TAG_VALUES};
use crate::wasm_circuit::types::SharedState;

#[derive(Debug, Clone)]
pub struct DynamicIndexesConfig<F> {
    pub q_enable: Column<Fixed>,
    pub index: Column<Advice>,
    pub is_terminator: Column<Fixed>,
    pub tag: Column<Fixed>,

    _marker: PhantomData<F>,
}

impl<'a, F: Field> DynamicIndexesConfig<F>
{}

#[derive(Debug, Clone)]
pub struct DynamicIndexesChip<F> {
    pub config: DynamicIndexesConfig<F>,
    _marker: PhantomData<F>,
}

impl<F: Field> DynamicIndexesChip<F>
{
    pub fn construct(config: DynamicIndexesConfig<F>) -> Self {
        let instance = Self {
            config,
            _marker: PhantomData,
        };
        instance
    }

    pub fn configure(
        cs: &mut ConstraintSystem<F>,
    ) -> DynamicIndexesConfig<F> {
        let q_enable = cs.fixed_column();
        let is_terminator = cs.fixed_column();
        let tag = cs.fixed_column();

        let index = cs.advice_column();

        cs.create_gate("DynamicIndexes gate", |vc| {
            let mut cb = BaseConstraintBuilder::default();

            let q_enable_expr = vc.query_fixed(q_enable, Rotation::cur());

            let is_terminator_prev_expr = vc.query_fixed(is_terminator, Rotation::prev());
            let is_terminator_expr = vc.query_fixed(is_terminator, Rotation::cur());
            let is_terminator_next_expr = vc.query_fixed(is_terminator, Rotation::next());

            let tag_prev_expr = vc.query_fixed(tag, Rotation::prev());
            let tag_expr = vc.query_fixed(tag, Rotation::cur());
            let tag_next_expr = vc.query_fixed(tag, Rotation::next());

            let index_prev_expr = vc.query_advice(index, Rotation::prev());
            let index_expr = vc.query_advice(index, Rotation::cur());
            let index_next_expr = vc.query_advice(index, Rotation::next());

            cb.require_boolean("q_enable is boolean", q_enable_expr.clone());
            cb.require_boolean("is_terminator is boolean", is_terminator_expr.clone());

            cb.require_in_set(
                "tag => value is valid",
                tag_expr.clone(),
                TAG_VALUES.iter().map(|v| (*v).expr()).collect(),
            );

            cb.condition(
                is_terminator_expr.clone(),
                |bcb| {
                    let is_terminator_prev_expr = vc.query_fixed(is_terminator, Rotation::prev());
                    let is_terminator_next_expr = vc.query_fixed(is_terminator, Rotation::next());
                    bcb.require_equal(
                        "is_terminator -> prev.is_terminator=0",
                        is_terminator_prev_expr.clone(),
                        0.expr(),
                    );
                    bcb.require_equal(
                        "is_terminator -> next.is_terminator=0",
                        is_terminator_next_expr.clone(),
                        0.expr(),
                    );
                }
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
                |bcb| {
                    bcb.require_zero(
                        "tags are equal inside tag-block",
                        tag_expr.clone() - tag_next_expr.clone(),
                    );
                    bcb.require_equal(
                        "index grows 1 by 1 inside tag-block",
                        index_expr.clone() + 1.expr(),
                        index_next_expr.clone(),
                    );
                }
            );

            cb.gate(q_enable_expr.clone())
        });

        let config = DynamicIndexesConfig::<F> {
            q_enable,
            is_terminator,
            tag,
            index,
            _marker: PhantomData,
        };

        config
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
            vec![
                index.expr(),
                tag.expr(),
                is_terminator.expr(),
            ]
                .into_iter()
                .zip(vec![
                    vc.query_advice(self.config.index, Rotation::cur()),
                    vc.query_fixed(self.config.tag, Rotation::cur()),
                    vc.query_fixed(self.config.is_terminator, Rotation::cur()),
                ].into_iter())
                .map(|(arg, table)| (cond_expr.clone() * arg, table))
                .collect()
        });
    }

    /// `params` must return exprs: [cond, index, tag, is_terminator]
    pub fn lookup_args(
        &self,
        name: &'static str,
        cs: &mut ConstraintSystem<F>,
        params: impl FnOnce(&mut VirtualCells<'_, F>) -> [Expression<F>; 4],
    ) {
        cs.lookup_any(name, |vc| {
            let params = params(vc);

            params[1..4]
                .into_iter()
                .zip(vec![
                    vc.query_advice(self.config.index, Rotation::cur()),
                    vc.query_fixed(self.config.tag, Rotation::cur()),
                    vc.query_fixed(self.config.is_terminator, Rotation::cur()),
                ].into_iter())
                .map(|(arg, table)| (params[0].clone() * arg.clone(), table))
                .collect()
        });
    }

    pub fn assign(
        &self,
        region: &mut Region<F>,
        offset: usize,
        assign_type: AssignType,
        assign_value: u64,
    ) {
        let q_enable = true;
        debug!(
            "dynamic_indexes: assign at offset {} q_enable {} assign_type {:?} assign_value {:?}",
            offset,
            q_enable,
            assign_type,
            assign_value,
        );
        region.assign_fixed(
            || format!("assign 'q_enable' val {} at {}", q_enable, offset),
            self.config.q_enable,
            offset,
            || Value::known(F::from(q_enable as u64)),
        ).unwrap();
        match assign_type {
            AssignType::Index => {
                region.assign_advice(
                    || format!("assign 'index' val {} at {}", assign_value, offset),
                    self.config.index,
                    offset,
                    || Value::known(F::from(assign_value)),
                ).unwrap();
            }
            AssignType::Tag => {
                region.assign_fixed(
                    || format!("assign 'tag' val {} at {}", assign_value, offset),
                    self.config.tag,
                    offset,
                    || Value::known(F::from(assign_value)),
                ).unwrap();
            }
            AssignType::IsTerminator => {
                region.assign_fixed(
                    || format!("assign 'is_terminator' val {} at {}", assign_value, offset),
                    self.config.is_terminator,
                    offset,
                    || Value::known(F::from(assign_value)),
                ).unwrap();
            }
        }
    }

    /// returns new offset
    pub fn assign_auto(
        &self,
        region: &mut Region<F>,
        start_offset: usize,
        indexes_count: usize,
        tag: Tag,
    ) -> Result<usize, Error> {
        let mut offset = start_offset;
        for rel_offset in 0..indexes_count + 1 {
            offset += 1;
            self.assign(
                region,
                offset,
                AssignType::Index,
                rel_offset as u64,
            );
            self.assign(
                region,
                offset,
                AssignType::Tag,
                tag as u64,
            );
            if rel_offset == indexes_count {
                self.assign(
                    region,
                    offset,
                    AssignType::IsTerminator,
                    1,
                );
            }
        }

        Ok(offset)
    }
}