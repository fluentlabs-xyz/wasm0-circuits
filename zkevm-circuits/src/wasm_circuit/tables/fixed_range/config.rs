use std::marker::PhantomData;

use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{ConstraintSystem, Error, TableColumn},
};
use eth_types::Field;

#[derive(Debug, Clone)]
pub struct RangeTableConfig<F: Field, const RANGE_START: usize, const RANGE_FINISH: usize> {
    pub value: TableColumn,
    _marker: PhantomData<F>,
}

impl<F: Field, const RANGE_START: usize, const COUNT: usize> RangeTableConfig<F, RANGE_START, COUNT> {
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
                for (offset, value) in (RANGE_START..RANGE_START+COUNT).enumerate() {
                    table.assign_cell(
                        || "num_bits",
                        self.value,
                        offset,
                        || Value::known(F::from(value as u64)),
                    )?;
                }

                Ok(())
            },
        )
    }
}
