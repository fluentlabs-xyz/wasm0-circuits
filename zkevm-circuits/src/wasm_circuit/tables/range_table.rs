use std::marker::PhantomData;

use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{ConstraintSystem, Error, TableColumn},
};
use eth_types::Field;

/// A lookup table of values from 0..RANGE.
#[derive(Debug, Clone)]
pub struct RangeTableConfig<F: Field, const RANGE: usize> {
    pub value: TableColumn,
    _marker: PhantomData<F>,
}

impl<F: Field, const RANGE: usize> RangeTableConfig<F, RANGE> {
    pub fn configure(cs: &mut ConstraintSystem<F>) -> Self {
        let value = cs.lookup_table_column();

        Self {
            value,
            _marker: PhantomData,
        }
    }

    pub fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        layouter.assign_table(
            || "load range-check table",
            |mut table| {
                for value in 0..RANGE {
                    table.assign_cell(
                        || "num_bits",
                        self.value,
                        value,
                        || Value::known(F::from(value as u64)),
                    )?;
                }

                Ok(())
            },
        )
    }
}
