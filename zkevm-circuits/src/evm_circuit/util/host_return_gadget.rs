use halo2_proofs::circuit::Value;
use halo2_proofs::plonk::Error;
use halo2_proofs::plonk::Error::Synthesis;

use eth_types::{Field, ToScalar, Word};
use gadgets::util::Expr;

use crate::evm_circuit::util::{CachedRegion, Cell, RandomLinearCombination};
use crate::evm_circuit::util::constraint_builder::ConstraintBuilder;

#[derive(Clone, Debug)]
pub(crate) struct HostReturnGadget<F, const N_SIZE: usize> {
    dest_offset: Cell<F>,
    value: RandomLinearCombination<F, N_SIZE>,
}

impl<F: Field, const N_SIZE: usize> HostReturnGadget<F, N_SIZE> {
    pub(crate) fn construct(
        cb: &mut ConstraintBuilder<F>,
        value: RandomLinearCombination<F, N_SIZE>,
    ) -> Self {
        // last stack item is memory destination offset
        let dest_offset = cb.query_cell();
        cb.stack_pop(dest_offset.expr());
        // do write lookup for each byte
        for idx in 0..N_SIZE {
            cb.memory_lookup(
                true.expr(),
                dest_offset.expr() + idx.expr(),
                value.cells[N_SIZE - 1 - idx].expr(),
                None,
            );
        }
        Self { dest_offset, value }
    }

    pub(crate) fn assign(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        dest_offset: Word,
        value: [u8; N_SIZE],
    ) -> Result<(), Error> {
        let dest_offset = Value::known(dest_offset.to_scalar().ok_or(Synthesis)?);
        self.dest_offset.assign(region, offset, dest_offset)?;
        self.value.assign(region, offset, Some(value))?;
        Ok(())
    }
}