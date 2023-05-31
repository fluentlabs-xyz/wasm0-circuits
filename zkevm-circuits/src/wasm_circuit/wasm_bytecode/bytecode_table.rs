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
    ///
    pub code_hash: Column<Advice>,
}

impl WasmBytecodeTable {
    ///
    pub fn construct<F: Field>(cs: &mut ConstraintSystem<F>) -> Self {
        let [index, value, code_hash] = array::from_fn(|_| cs.advice_column());
        // TODO need this for prod ?
        // let code_hash = cs.advice_column_in(SecondPhase);
        Self {
            index,
            value,
            code_hash,
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
                let bytecode_table_columns =
                    <WasmBytecodeTable as LookupTable<F>>::advice_columns(self);
                for (offset, &row) in bytecode.table_assignments::<F>().iter().enumerate() {
                    for (&column, value) in bytecode_table_columns.iter().zip_eq(row) {
                        region.assign_advice(
                            || format!("assign wasm bytecode table row at {}", offset),
                            column,
                            offset,
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
        vec![
            self.index.into(),
            self.value.into(),
            self.code_hash.into(),
        ]
    }

    fn annotations(&self) -> Vec<String> {
        vec![
            String::from("index"),
            String::from("value"),
            String::from("code_hash"),
        ]
    }
}

