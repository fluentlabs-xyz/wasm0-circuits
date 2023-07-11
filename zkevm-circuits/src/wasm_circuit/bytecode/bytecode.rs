use halo2_proofs::circuit::Value;
use bus_mapping::state_db::CodeDB;
use eth_types::{Field, ToScalar, ToWord, Word};

#[derive(Clone, Debug)]
pub struct WasmBytecode {
    pub(crate) bytes: Vec<u8>,
    pub(crate) code_hash: Word,
}

impl WasmBytecode {
    /// Construct from bytecode bytes
    pub fn new(bytes: Vec<u8>, code_hash: Word) -> Self {
        Self {
            bytes,
            code_hash,
        }
    }

    /// Assignments for bytecode table
    pub fn table_assignments<F: Field>(&self) -> Vec<[Value<F>; 3]> {
        let n = 1 + self.bytes.len();
        let mut rows = Vec::with_capacity(n);

        for (idx, byte) in self.bytes.iter().enumerate() {
            let idx_val = Value::known(F::from(idx as u64));
            let byte_val = Value::known(F::from(*byte as u64));
            let code_hash_val = Value::known(self.code_hash.to_scalar().unwrap());
            rows.push([
                idx_val,
                byte_val,
                code_hash_val,
            ])
        }
        rows
    }

    /// get byte value
    pub fn get(&self, idx: usize) -> u8 {
        self.bytes[idx]
    }
}

impl From<&eth_types::bytecode::Bytecode> for WasmBytecode {
    fn from(b: &eth_types::bytecode::Bytecode) -> Self {
        // TODO use stack word ?
        let code_hash = CodeDB::hash(&b.code());
        WasmBytecode::new(b.to_vec(), code_hash.to_word())
    }
}