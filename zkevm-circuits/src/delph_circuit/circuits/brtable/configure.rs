use halo2_proofs::{
    plonk::{ConstraintSystem, Expression, TableColumn, VirtualCells},
};
use std::marker::PhantomData;
use eth_types::Field;

use super::BrTableConfig;
use crate::delph_circuit::circuits::traits::ConfigureLookupTable;

impl<F: Field> BrTableConfig<F> {
    pub(crate) fn configure(col: TableColumn) -> Self {
        Self {
            col,
            _mark: PhantomData,
        }
    }
}

impl<F: Field> ConfigureLookupTable<F> for BrTableConfig<F> {
    fn configure_in_table(
        &self,
        meta: &mut ConstraintSystem<F>,
        key: &'static str,
        expr: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
    ) {
        meta.lookup(key, |meta| vec![(expr(meta), self.col)]);
    }
}
