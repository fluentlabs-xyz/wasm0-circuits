use halo2_proofs::{arithmetic::FieldExt, plonk::TableColumn};
use std::marker::PhantomData;
use eth_types::Field;

mod assign;
mod configure;

#[derive(Clone)]
pub struct BrTableConfig<F: Field> {
    pub(self) col: TableColumn,
    _mark: PhantomData<F>,
}

pub struct BrTableChip<F: Field> {
    config: BrTableConfig<F>,
}

impl<F: Field> BrTableChip<F> {
    pub fn new(config: BrTableConfig<F>) -> Self {
        BrTableChip { config }
    }
}
