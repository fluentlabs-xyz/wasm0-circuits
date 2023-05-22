use eth_types::{Field};
use halo2_proofs::{
    circuit::Layouter,
    plonk::{Advice, Column, ConstraintSystem, Error, *},
};
use itertools::Itertools;
use std::array;
use crate::table::LookupTable;
use crate::wasm_circuit::wasm_bytecode::bytecode::WasmBytecode;

///
#[derive(Clone, Debug)]
pub struct WasmBytecodeTable {
    ///
    pub index: Column<Advice>,
    ///
    pub value: Column<Advice>,
}

impl WasmBytecodeTable {
    ///
    pub fn construct<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
        let [index, value] = array::from_fn(|_| meta.advice_column());
        Self {
            index,
            value,
        }
    }

    ///
    pub fn load<'a, F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
        bytecode: &'a WasmBytecode,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "wasm bytecode table",
            |mut region| {
                let mut offset = 0;

                let bytecode_table_columns =
                    <WasmBytecodeTable as LookupTable<F>>::advice_columns(self);
                // for bytecode in bytecodes.clone() {
                for row in bytecode.table_assignments::<F>() {
                    for (&column, value) in bytecode_table_columns.iter().zip_eq(row) {
                        region.assign_advice(
                            || format!("wasm bytecode table row {}", offset),
                            column,
                            offset,
                            || value,
                        )?;
                    }
                    offset += 1;
                }
                // }
                Ok(())
            },
        )
    }
}

impl<F: Field> LookupTable<F> for WasmBytecodeTable {
    fn columns(&self) -> Vec<Column<Any>> {
        vec![
            self.index.into(),
            self.value.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("index"),
            String::from("value"),
        ]
    }
}

