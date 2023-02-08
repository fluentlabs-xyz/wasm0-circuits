use halo2_proofs::{arithmetic::FieldExt, circuit::Layouter, plonk::Error};
use halo2_proofs::circuit::Value;
use eth_types::Field;
use crate::wasm_circuit::specs::brtable::{BrTable, ElemTable};

use super::BrTableChip;
use crate::wasm_circuit::circuits::utils::bn_to_field;

impl<F: Field> BrTableChip<F> {
    pub(crate) fn assign(
        self,
        layouter: &mut impl Layouter<F>,
        br_table_init: &BrTable,
        elem_table: &ElemTable,
    ) -> Result<(), Error> {
        layouter.assign_table(
            || "minit",
            |mut table| {
                table.assign_cell(|| "brtable init", self.config.col, 0, || Value::known(F::zero()))?;

                let mut offset = 1;

                for e in br_table_init.entries() {
                    table.assign_cell(
                        || "brtable init",
                        self.config.col,
                        offset,
                        || Value::known(bn_to_field::<F>(&e.encode())),
                    )?;

                    offset += 1;
                }

                for e in elem_table.entries() {
                    table.assign_cell(
                        || "call indirect init",
                        self.config.col,
                        offset,
                        || Value::known(bn_to_field::<F>(&e.encode())),
                    )?;

                    offset += 1;
                }

                Ok(())
            },
        )?;

        Ok(())
    }
}
