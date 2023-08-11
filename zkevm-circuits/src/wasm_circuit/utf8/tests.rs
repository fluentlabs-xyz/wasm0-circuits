use halo2_proofs::{
    plonk::{ConstraintSystem, Error},
};
use std::{marker::PhantomData};
use std::rc::Rc;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Advice, Circuit, Column};
use bus_mapping::state_db::CodeDB;
use eth_types::{Field, ToWord};
use crate::wasm_circuit::utf8::circuit::{UTF8Chip, UTF8Config};
use crate::wasm_circuit::bytecode::bytecode::WasmBytecode;
use crate::wasm_circuit::tables::fixed_range::config::RangeTableConfig;

#[derive(Default)]
struct TestCircuit<'a, F> {
    bytes: &'a [u8],
    offset_shift: usize,
    _marker: PhantomData<F>,
}

#[derive(Clone)]
struct TestCircuitConfig<F: Field> {
    bytes: Column<Advice>,
    eligible_byte_vals_range_table_config: Rc<RangeTableConfig<F, 0, 128>>,
    utf8_config: UTF8Config<F>,
    _marker: PhantomData<F>,
}

impl<'a, F: Field> Circuit<F> for TestCircuit<'a, F> {
    type Config = TestCircuitConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self { Self::default() }

    fn configure(
        cs: &mut ConstraintSystem<F>,
    ) -> Self::Config {
        let bytes = cs.advice_column();
        let eligible_byte_vals_range_table_config = Rc::new(RangeTableConfig::configure(cs));
        let utf8_config = UTF8Chip::<F>::configure(
            cs,
            eligible_byte_vals_range_table_config.clone(),
            &bytes,
        );
        let test_circuit_config = TestCircuitConfig {
            bytes,
            eligible_byte_vals_range_table_config: eligible_byte_vals_range_table_config.clone(),
            utf8_config,
            _marker: Default::default(),
        };

        test_circuit_config
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        config.eligible_byte_vals_range_table_config.load(&mut layouter)?;
        let utf8_chip = UTF8Chip::construct(config.utf8_config);
        let code_hash = CodeDB::hash(&self.bytes);
        let wasm_bytecode = WasmBytecode::new(self.bytes.to_vec(), code_hash.to_word());

        layouter.assign_region(
            || "utf8 region",
            |mut region| {
                for (offset, &byte_val) in self.bytes.iter().enumerate() {
                    let offset = offset + self.offset_shift;
                    region.assign_advice(
                        || format!("assign 'byte_val' to {} at {}", byte_val, offset),
                        config.bytes,
                        offset,
                        || Value::known(F::from(byte_val as u64)),
                    ).unwrap();

                }
                utf8_chip.assign_auto(&mut region, &wasm_bytecode, self.bytes.len(), 0, self.offset_shift);

                Ok(())
            }
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod utf8_circuit_tests {
    use std::marker::PhantomData;
    use ethers_core::k256::pkcs8::der::Encode;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr;
    use log::debug;
    use eth_types::Field;
    use crate::wasm_circuit::utf8::tests::TestCircuit;

    fn test<'a, F: Field>(
        test_circuit: TestCircuit<'_, F>,
        is_ok: bool,
    ) {
        let k = 10;
        let prover = MockProver::run(k, &test_circuit, vec![]).unwrap();
        if is_ok {
            prover.assert_satisfied();
        } else {
            assert!(prover.verify().is_err());
        }
    }

    pub fn exact_utf8bytecode(utf8_bytecode: &[u8], offset_shift: usize, is_ok: bool) {
        let circuit = TestCircuit::<Fr> {
            bytes: utf8_bytecode,
            offset_shift,
            _marker: PhantomData
        };
        self::test(circuit, is_ok);
    }

    #[test]
    pub fn test_valid_bytes() {
        assert_eq!('a' as u8, 97);
        exact_utf8bytecode(vec!['a' as u8, 'b' as u8, 'c' as u8].as_slice(), 0, true);
    }

    #[test]
    pub fn test_valid_bytes_shifted() {
        assert_eq!('a' as u8, 97);
        exact_utf8bytecode(vec!['a' as u8, 'b' as u8, 'c' as u8].as_slice(), 1, true);
    }

    #[test]
    pub fn test_out_of_bound_bytes() {
        exact_utf8bytecode(vec![129].as_slice(), 0, false);
    }

    #[test]
    pub fn test_zero() {
        exact_utf8bytecode(vec![0].as_slice(), 0, false);
    }
}