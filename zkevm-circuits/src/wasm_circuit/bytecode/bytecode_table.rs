use std::array;

use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, *},
};
use itertools::Itertools;

use eth_types::Field;

use crate::{table::LookupTable, wasm_circuit::bytecode::bytecode::WasmBytecode};

#[derive(Clone, Debug)]
pub struct WasmBytecodeTable {
    pub index: Column<Advice>,
    pub value: Column<Advice>,
    pub code_hash: Column<Advice>,

    pub zero_row_enabled: bool,
}

impl WasmBytecodeTable {
    pub fn construct<F: Field>(cs: &mut ConstraintSystem<F>, zero_row_enabled: bool) -> Self {
        let [index, value, code_hash] = array::from_fn(|_| cs.advice_column());
        Self {
            index,
            value,
            code_hash,
            zero_row_enabled,
        }
    }

    pub fn load<'a, F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        wb: &'a WasmBytecode,
        assign_delta: usize,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "wasm bytecode table",
            |mut region| {
                let bytecode_table_columns =
                    <WasmBytecodeTable as LookupTable<F>>::advice_columns(self);

                if self.zero_row_enabled {
                    let assign_offset = assign_delta;
                    for &column in bytecode_table_columns.iter() {
                        region.assign_advice(
                            || format!("assign wasm bytecode table zero row at {}", assign_offset),
                            column,
                            assign_offset,
                            || Value::known(F::from(0)),
                        )?;
                    }
                }

                let assign_delta = assign_delta + if self.zero_row_enabled { 1 } else { 0 };
                for (offset, &row) in wb.table_assignments::<F>().iter().enumerate() {
                    let assign_offset = offset + assign_delta;
                    for (&column, value) in bytecode_table_columns.iter().zip_eq(row) {
                        region.assign_advice(
                            || {
                                format!(
                                    "assign wasm bytecode table row at {} val {:?}",
                                    assign_offset, value
                                )
                            },
                            column,
                            assign_offset,
                            || value,
                        )?;
                    }
                }
                Ok(())
            },
        )
    }
}

impl<F: Field> LookupTable<F> for WasmBytecodeTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![self.index.into(), self.value.into(), self.code_hash.into()]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("index"),
            String::from("value"),
            String::from("code_hash"),
        ]
    }
}
