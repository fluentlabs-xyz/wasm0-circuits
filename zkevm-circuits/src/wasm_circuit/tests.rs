use std::cell::RefCell;
use std::marker::PhantomData;
use std::rc::Rc;

use halo2_proofs::{
    plonk::{ConstraintSystem, Error},
};
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::plonk::Circuit;

use eth_types::{Field, Hash, ToWord};

use crate::wasm_circuit::bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::bytecode::bytecode_table::WasmBytecodeTable;
use crate::wasm_circuit::circuit::{WasmChip, WasmConfig};
use crate::wasm_circuit::types::SharedState;

#[derive(Default)]
struct TestCircuit<F> {
    bytes: Vec<u8>,
    code_hash: Hash,
    _marker: PhantomData<F>,
}

impl<F: Field> Circuit<F> for TestCircuit<F> {
    type Config = WasmConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self { Self::default() }

    fn configure(cs: &mut ConstraintSystem<F>) -> Self::Config {
        let shared_state = Rc::new(RefCell::new(SharedState::default()));
        let wasm_bytecode_table = WasmBytecodeTable::construct(cs);
        let config = WasmChip::<F>::configure(cs, Rc::new(wasm_bytecode_table), shared_state);

        config
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let mut wasm_chip = WasmChip::construct(config);
        let wasm_bytecode = WasmBytecode::new(self.bytes.clone(), self.code_hash.to_word());

        wasm_chip.load(&mut layouter, &wasm_bytecode)?;

        layouter.assign_region(
            || "wasm_chip region",
            |mut region| {
                wasm_chip.assign_auto(
                    &mut region,
                    &wasm_bytecode,
                )?;

                Ok(())
            }
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod wasm_circuit_tests {
    use std::marker::PhantomData;

    use ethers_core::k256::pkcs8::der::Encode;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr;
    use log::debug;
    use rand::Rng;
    use wabt::wat2wasm;

    use bus_mapping::state_db::CodeDB;
    use eth_types::Field;

    use crate::wasm_circuit::tests::TestCircuit;

    pub fn get_different_random_byte_val(old_byte_val: u8) -> u8 {
        let mut rng = rand::thread_rng();
        let mut random_byte: u8 = old_byte_val;
        while random_byte == old_byte_val { random_byte = rng.gen(); }
        random_byte
    }

    fn test<'a, F: Field>(test_circuit: TestCircuit<F>, is_ok: bool) {
        let k = 10;
        let prover = MockProver::run(k, &test_circuit, vec![]).unwrap();
        if is_ok {
            prover.assert_satisfied();
        } else {
            assert!(prover.verify().is_err());
        }
    }

    #[test]
    pub fn file1_ok() {
        let path_to_file = "./src/wasm_circuit/test_data/files/cc1.wat";
        let data: Vec<u8> = std::fs::read(path_to_file).unwrap();
        let wasm_binary = wat2wasm(data).unwrap();
        debug!("wasm_binary.len: {}", wasm_binary.len());
        debug!("wasm_binary.len hex: {:x?}", wasm_binary.len());
        debug!("wasm_binary last_index: {}", wasm_binary.len() - 1);
        debug!("wasm_binary last_index hex: {:x?}", wasm_binary.len() - 1);
        debug!("wasm_binary: {:x?}", wasm_binary);
        let code_hash = CodeDB::hash(&wasm_binary);
        let circuit = TestCircuit::<Fr> {
            bytes: wasm_binary.clone(),
            code_hash,
            _marker: PhantomData,
        };
        self::test(circuit, true);
    }

    #[test]
    pub fn file2_ok() {
        let path_to_file = "./src/wasm_circuit/test_data/files/cc2.wat";
        let data: Vec<u8> = std::fs::read(path_to_file).unwrap();
        let wasm_binary = wat2wasm(data).unwrap();
        debug!("wasm_binary.len: {}", wasm_binary.len());
        debug!("wasm_binary.len hex: {:x?}", wasm_binary.len());
        debug!("wasm_binary last_index: {}", wasm_binary.len() - 1);
        debug!("wasm_binary last_index hex: {:x?}", wasm_binary.len() - 1);
        debug!("wasm_binary: {:x?}", wasm_binary);
        let mut code_hash = CodeDB::hash(&wasm_binary);
        let circuit = TestCircuit::<Fr> {
            bytes: wasm_binary.clone(),
            code_hash,
            _marker: PhantomData,
        };
        self::test(circuit, true);
    }

    #[test]
    pub fn file3_ok() {
        let path_to_file = "./src/wasm_circuit/test_data/files/cc3.wat";
        let data: Vec<u8> = std::fs::read(path_to_file).unwrap();
        let wasm_binary = wat2wasm(data).unwrap();
        debug!("wasm_binary.len: {}", wasm_binary.len());
        debug!("wasm_binary.len hex: {:x?}", wasm_binary.len());
        debug!("wasm_binary last_index: {}", wasm_binary.len() - 1);
        debug!("wasm_binary last_index hex: {:x?}", wasm_binary.len() - 1);
        debug!("wasm_binary: {:x?}", wasm_binary);
        let mut code_hash = CodeDB::hash(&wasm_binary);
        let circuit = TestCircuit::<Fr> {
            bytes: wasm_binary.clone(),
            code_hash,
            _marker: PhantomData,
        };
        self::test(circuit, true);
    }

    /// for development only
    #[ignore]
    #[test]
    pub fn string_to_hex_bytes_test() {
        let strings = [
            "g1",
            "g2",
            "g3",
            "js",
            "global",
            "Hello, World",
            "none",
            "\0asm",
            "main",
            "memory",
            "table",
            "spectest",
            "env",
            "_evm_address",
            "_evm_balance",
            "_evm_some_long_name_func_some_long_name_func_some_long_name_func_some_long_name_func_some_long_name_func_some_long_name_func_some_long_name_func_some_long_name_func",
            "test",
            "global-i32",
        ];
        for str in strings {
            debug!("'{}' in hex {:x?} in decimal {:?}", str, str.to_string().as_bytes(), str.to_string().as_bytes());
        }
    }

    #[test]
    pub fn bad_magic_prefix_fails() {
        let path_to_file = "./src/wasm_circuit/test_data/files/cc1.wat";
        let data: Vec<u8> = std::fs::read(path_to_file).unwrap();
        let mut wasm_binary = wat2wasm(data).unwrap();
        for i in 0..4 {
            wasm_binary[i] = get_different_random_byte_val(wasm_binary[i]);
            let circuit = TestCircuit::<Fr> {
                bytes: wasm_binary.clone(),
                code_hash: CodeDB::hash(&wasm_binary),
                _marker: PhantomData,
            };
            self::test(circuit, false);
        }
    }

    #[ignore] // TODO some problems after new module integration
    #[test]
    pub fn test_random_bytecode_must_fail() {
        let wasm_binary: Vec<u8> = [0, 1, 2, 3].to_vec().unwrap();
        let circuit = TestCircuit::<Fr> {
            bytes: wasm_binary.clone(),
            code_hash: CodeDB::hash(&wasm_binary),
            _marker: PhantomData,
        };
        self::test(circuit, false);
    }

    #[ignore] // TODO some problems after new module integration
    #[test]
    pub fn test_wrong_sections_order_must_fail() {
        let path_to_file = "./src/wasm_circuit/test_data/files/cc1.wat";
        let data: Vec<u8> = std::fs::read(path_to_file).unwrap();
        let wasm_binary = wat2wasm(data).unwrap();
        debug!("wasm_binary.len: {}", wasm_binary.len());
        debug!("wasm_binary.len hex: {:x?}", wasm_binary.len());
        debug!("wasm_binary last_index: {}", wasm_binary.len() - 1);
        debug!("wasm_binary last_index hex: {:x?}", wasm_binary.len() - 1);
        debug!("wasm_binary (original): {:x?}", wasm_binary);
        // TODO swap some sections
        debug!("wasm_binary (modified): {:x?}", wasm_binary);
        let circuit = TestCircuit::<Fr> {
            bytes: wasm_binary.clone(),
            code_hash: CodeDB::hash(&wasm_binary),
            _marker: PhantomData,
        };
        self::test(circuit, false);
    }
}