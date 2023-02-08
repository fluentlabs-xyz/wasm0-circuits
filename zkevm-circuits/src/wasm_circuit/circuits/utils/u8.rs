use super::Context;
use crate::wasm_circuit::{circuits::rtable::RangeTableConfig};
use halo2_proofs::{
    arithmetic::FieldExt,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, VirtualCells},
};
use std::marker::PhantomData;
use halo2_proofs::circuit::Value;
use eth_types::Field;
use crate::{curr};

#[derive(Clone)]
pub struct U8Config<F: Field> {
    pub value: Column<Advice>,
    _mark: PhantomData<F>,
}

impl<F: Field> U8Config<F> {
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        cols: &mut impl Iterator<Item = Column<Advice>>,
        rtable: &RangeTableConfig<F>,
        enable: impl Fn(&mut VirtualCells<'_, F>) -> Expression<F>,
    ) -> Self {
        let value = cols.next().unwrap();

        rtable.configure_in_u8_range(meta, "u8", |meta| curr!(meta, value.clone()) * enable(meta));
        Self {
            value,
            _mark: PhantomData,
        }
    }

    pub fn assign(&self, ctx: &mut Context<F>, value: u64) -> Result<(), Error> {
        ctx.region.assign_advice(
            || "u8 value",
            self.value.clone(),
            ctx.offset,
            || Value::<F>::known(value.into()),
        )?;

        Ok(())
    }
}
