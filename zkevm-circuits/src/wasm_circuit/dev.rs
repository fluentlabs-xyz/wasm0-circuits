use halo2_proofs::{
    plonk::{ConstraintSystem, Error},
};
use std::{marker::PhantomData};
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::plonk::{Circuit};
use eth_types::Field;
use crate::wasm_circuit::circuit::{WasmChip, WasmConfig};
use crate::wasm_circuit::wasm_bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::wasm_bytecode::bytecode_table::WasmBytecodeTable;

#[derive(Default)]
struct TestCircuit<F> {
    bytes: Vec<u8>,
    _marker: PhantomData<F>,
}

impl<F: Field> Circuit<F> for TestCircuit<F> {
    type Config = WasmConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self { Self::default() }

    fn configure(cs: &mut ConstraintSystem<F>) -> Self::Config {
        let wasm_bytecode_table = WasmBytecodeTable::construct(cs);
        let config = WasmChip::<F>::configure(cs, wasm_bytecode_table);

        config
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let chip = WasmChip::construct(config);
        let wasm_bytecode = WasmBytecode::new(self.bytes.clone());

        chip.config.wasm_bytecode_table.load(&mut layouter, &wasm_bytecode)?;
        chip.config.range_table_256_config.load(&mut layouter)?;

        layouter.assign_region(
            || "wasm chip region",
            |mut region| {
                chip.assign(
                    &mut region,
                    self.bytes.as_slice(),
                )?;

                Ok(())
            }
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;
    use ethers_core::k256::pkcs8::der::Encode;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr;
    use rand::Rng;
    use wabt::wat2wasm;
    use eth_types::{Field};
    use crate::wasm_circuit::dev::TestCircuit;

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
    pub fn test_wasm_bytecode_from_file_must_succeed() {
        let path_to_file = "./src/wasm_circuit/test_data/files/br_breaks_1.wat";
        let data: Vec<u8> = std::fs::read(path_to_file).unwrap();
        let data = wat2wasm(data).unwrap();
        println!("data.len: {}", data.len());
        println!("data.len hex: {:x?}", data.len());
        println!("data last_index: {}", data.len() - 1);
        println!("data last_index hex: {:x?}", data.len() - 1);
        println!("data: {:x?}", data);
        let circuit = TestCircuit::<Fr> {
            bytes: data.clone(),
            _marker: PhantomData,
        };
        self::test(circuit, true);
    }

    #[test]
    pub fn test_wasm_bytecode_has_bad_prefix_must_fail() {
        let path_to_file = "./src/wasm_circuit/test_data/files/br_breaks_1.wat";
        let data: Vec<u8> = std::fs::read(path_to_file).unwrap();
        let mut data = wat2wasm(data).unwrap();
        for i in 0..4 {
            data[i] = get_different_random_byte_val(data[i]);
            let circuit = TestCircuit::<Fr> {
                bytes: data.clone(),
                _marker: PhantomData,
            };
            self::test(circuit, false);
        }
    }

    #[test]
    pub fn test_random_bytecode_must_fail() {
        let data: Vec<u8> = [0, 1, 2, 3].to_vec().unwrap();
        let circuit = TestCircuit::<Fr> {
            bytes: data.clone(),
            _marker: PhantomData,
        };
        self::test(circuit, false);
    }

    #[ignore] // TODO implement TODOs
    #[test]
    pub fn test_wrong_sections_order_must_fail() {
        let path_to_file = "./src/wasm_circuit/test_data/files/br_breaks_1.wat";
        let data: Vec<u8> = std::fs::read(path_to_file).unwrap();
        let data = wat2wasm(data).unwrap();
        println!("data.len: {}", data.len());
        println!("data.len hex: {:x?}", data.len());
        println!("data last_index: {}", data.len() - 1);
        println!("data last_index hex: {:x?}", data.len() - 1);
        println!("data (original): {:x?}", data);
        // TODO swap some sections
        println!("data (modified): {:x?}", data);
        let circuit = TestCircuit::<Fr> {
            bytes: data.clone(),
            _marker: PhantomData,
        };
        self::test(circuit, false);
    }
}