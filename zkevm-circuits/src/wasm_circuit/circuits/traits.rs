use halo2_proofs::{
    plonk::{ConstraintSystem, Expression, VirtualCells},
};
use eth_types::Field;

pub(super) trait ConfigureLookupTable<F: Field> {
    fn configure_in_table(
        &self,
        meta: &mut ConstraintSystem<F>,
        key: &'static str,
        expr: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
    );
}
