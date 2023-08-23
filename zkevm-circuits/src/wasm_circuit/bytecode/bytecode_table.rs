use std::array;

use halo2_proofs::{
    circuit::{Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, *},
};
use itertools::Itertools;
use log::debug;

use eth_types::Field;

use crate::{
    table::LookupTable,
    wasm_circuit::{bytecode::bytecode::WasmBytecode, types::AssignDeltaType},
};

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
        region: &mut Region<F>,
        wb: &'a WasmBytecode,
        assign_delta: AssignDeltaType,
    ) -> Result<AssignDeltaType, Error> {
        let mut assign_offset = 0;
        assign_offset = assign_delta;
        debug!("wasm bytecode table start assign at {}", assign_offset);
        let bytecode_table_columns = <WasmBytecodeTable as LookupTable<F>>::advice_columns(self);

        if self.zero_row_enabled {
            let value = 0;
            for &column in bytecode_table_columns.iter() {
                debug!(
                    "assign at {} column.index {} wasm_bytecode_table val {:?}",
                    assign_offset, column.index, value
                );
                region.assign_advice(
                    || {
                        format!(
                            "assign at {} column.index {} wasm_bytecode_table val {:?}",
                            assign_offset, column.index, value
                        )
                    },
                    column,
                    assign_offset,
                    || Value::known(F::from(value)),
                )?;
            }
            assign_offset += 1;
        }

        for (offset, &row) in wb.table_assignments::<F>().iter().enumerate() {
            for (&column, value) in bytecode_table_columns.iter().zip_eq(row) {
                debug!(
                    "assign at {} column.index {} wasm_bytecode_table val {:?}",
                    assign_offset, column.index, value
                );
                region.assign_advice(
                    || {
                        format!(
                            "assign at {} column.index {} wasm_bytecode_table val {:?}",
                            assign_offset, column.index, value
                        )
                    },
                    column,
                    assign_offset,
                    || value,
                )?;
            }
            assign_offset += 1;
        }
        Ok(assign_offset)
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
