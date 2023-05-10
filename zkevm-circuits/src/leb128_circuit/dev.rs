use halo2_proofs::{
    plonk::{ConstraintSystem, Error},
};
use std::{marker::PhantomData};
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::plonk::{Circuit};
use eth_types::Field;
use crate::leb128_circuit::circuit::{LEB128NumberChip, LEB128NumberConfig};

#[derive(Default)]
struct TestCircuit<'a, F, const BIT_DEPTH: usize, const IS_SIGNED: bool> {
    leb_base64_words: &'a [u64],
    leb_bytes: &'a [u8],
    leb_last_byte_index: u64,
    // solid_number_is_positive: bool,
    // solid_number: u64,
    _marker: PhantomData<F>,
}

impl<'a, F: Field, const BIT_DEPTH: usize, const IS_SIGNED: bool> Circuit<F> for TestCircuit<'a, F, BIT_DEPTH, IS_SIGNED> {
    type Config = LEB128NumberConfig<F, BIT_DEPTH, IS_SIGNED>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self { Self::default() }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let config = LEB128NumberChip::<F, BIT_DEPTH, IS_SIGNED>::configure(meta);

        config
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let leb128_number_chip = LEB128NumberChip::construct(config);
        // let is_zero_chip = IsZeroChip::construct(leb128_number_chip.config.is_zero_config.clone());

        layouter.assign_region(
            || "leb128 region",
            |mut region| {
                leb128_number_chip.assign(
                    &mut region,
                    self.leb_bytes,
                    self.leb_last_byte_index,
                    // self.solid_number_is_positive,
                    // self.solid_number,
                    self.leb_base64_words,
                );

                Ok(())
            }
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::halo2curves::bn256::Fr;
    use rand::Rng;
    use eth_types::Field;
    use crate::leb128_circuit::consts::{BYTES_IN_BASE64_WORD, EIGHT_LS_BITS_MASK, EIGHT_MS_BIT_MASK, SEVEN_LS_BITS_MASK};
    use crate::leb128_circuit::dev::TestCircuit;

    const ALL_BIT_DEPTHS_BYTES: &[usize] = &[1, 2, 3, 4, 5, 6, 7, 8];

    /// unsigned leb repr and last byte index
    fn convert_to_leb_bytes_unsigned(number: u64, exact_bytes_count: u8) -> (Vec<u8>, usize) {
        let mut res = Vec::new();
        let mut last_byte_index: usize = 0;
        let mut number = number;
        while number > 0 {
            let mut byte = number & 0b1111111;
            number >>= 7;
            if number > 0 {
                byte |= 0b10000000;
                last_byte_index += 1;
            }
            res.push(byte as u8);
        }

        let res = res.as_mut_slice();
        if res.len() == exact_bytes_count as usize {
            return (res.to_vec(), last_byte_index);
        }
        if res.len() > exact_bytes_count as usize {
            panic!("result too long")
        }
        let mut res_vec = vec![0; exact_bytes_count as usize];
        for (i, &item) in res.iter().enumerate() {
            res_vec[i] = item;
        }
        (res_vec, last_byte_index)
    }

    /// singed leb repr and last byte index
    fn convert_to_leb_bytes_signed(number: i64, exact_bytes_count: u8) -> (Vec<u8>, usize) {
        if number >= 0 {
            panic!("only negative numbers can be converted into signed repr")
        }
        let mut res = Vec::new();
        let mut last_byte_index: usize = 0;
        let mut number = number;
        let mut is_positive = true;
        if number < 0 {
            number = -number;
            is_positive = false;
        }
        let mut twos_complement_val: u64 = 1;
        let mut overflow: u64 = 0;
        let mut is_full_7_bit = false;
        while number > 0 || is_full_7_bit {
            let mut byte = !(number as u64) & SEVEN_LS_BITS_MASK as u64;
            is_full_7_bit = byte == 0;
            byte += overflow + twos_complement_val;
            twos_complement_val = 0;
            if byte >= EIGHT_MS_BIT_MASK as u64 {
                overflow = 1;
                byte = byte & SEVEN_LS_BITS_MASK as u64;
            } else {
                overflow = 0;
            }
            number >>= 7;
            if number > 0 || is_full_7_bit || overflow == 1 {
                byte |= 0b10000000;
                last_byte_index += 1;
            }
            res.push(byte as u8);
        }
        if overflow == 1 {
            res.push(!(0b1 & SEVEN_LS_BITS_MASK) & SEVEN_LS_BITS_MASK);
        }

        let res = res.as_mut_slice();
        if res.len() == exact_bytes_count as usize {
            return (res.to_vec(), last_byte_index);
        }
        if res.len() > exact_bytes_count as usize {
            panic!("result too long")
        }
        let mut res_vec = vec![EIGHT_LS_BITS_MASK; exact_bytes_count as usize];
        for (i, &item) in res.iter().enumerate() {
            res_vec[i] = item;
        }
        (res_vec, last_byte_index)
    }

    ///
    pub fn convert_to_leb_bytes(is_positive: bool, number: u64, exact_bytes_count: u8) -> (Vec<u8>, usize) {
        if is_positive || number == 0 {
            return convert_to_leb_bytes_unsigned(number, exact_bytes_count);
        }
        let max_signed_value: u64 = i32::MAX as u64;
        if number >= max_signed_value {
            panic!("max signed value is {} but given {} (is_positive: {})", max_signed_value, number, is_positive)
        }
        convert_to_leb_bytes_signed(if is_positive { number as i64 } else { -(number as i64) }, exact_bytes_count)
    }

    pub fn convert_leb128_to_base64_words(leb128: &Vec<u8>, last_byte_index: usize) -> Vec<u64> {
        let mut base64_words = Vec::<u64>::new();
        let mut index = 0;
        for i in 0..=last_byte_index {
            if i % BYTES_IN_BASE64_WORD == 0 {
                base64_words.push(0);
                index = i + 7;
                if index > last_byte_index { index = last_byte_index };
            } else {
                index -= 1;
            }
            let base64_words_last_index = base64_words.len() - 1;
            let current_word = &mut base64_words[base64_words_last_index];
            let byte = leb128[index];
            (*current_word) = (*current_word) * 0b100000000 + byte as u64;
        }
        base64_words
    }

    pub fn break_bit(byte_to_break: &mut u8, break_mask: u8) {
        *byte_to_break = (!*byte_to_break & break_mask) | (*byte_to_break & !break_mask);
    }

    pub fn leb_break_continuation_bit(rng: &mut rand::prelude::ThreadRng, leb128: &mut Vec<u8>) {
        const BIT_TO_BREAK_MASK: u8 = 0b10000000;
        let byte_number = rng.gen::<usize>() % leb128.len();
        break_bit(&mut leb128[byte_number], BIT_TO_BREAK_MASK);
    }

    pub fn leb_break_random_bit(rng: &mut rand::prelude::ThreadRng, leb128: &mut Vec<u8>) {
        let byte_to_break_number = rng.gen::<usize>() % leb128.len();
        let bit_to_break_number = rng.gen::<u64>() % 8;
        let bit_to_break_mask = 1 << bit_to_break_number;
        break_bit(&mut leb128[byte_to_break_number], bit_to_break_mask);
    }

    fn test<'a, F: Field, const BIT_DEPTH: usize, const IS_SIGNED: bool>(test_circuit: TestCircuit<'_, F, BIT_DEPTH, IS_SIGNED>, is_ok: bool) {
        let k = 5;
        let prover = MockProver::run(k, &test_circuit, vec![]).unwrap();
        if is_ok {
            prover.assert_satisfied();
        } else {
            assert!(prover.verify().is_err());
        }
    }

    pub fn debug_exact_number<const NUMBER: u64, const BIT_DEPTH: usize, const IS_SIGNED: bool>() {
        let (input_number_leb128, last_byte_index) = convert_to_leb_bytes(!IS_SIGNED, NUMBER, ((BIT_DEPTH + 6) / 7) as u8);
        let base64_words = convert_leb128_to_base64_words(&input_number_leb128, last_byte_index);
        let solid_number = NUMBER;
        println!(
            "IS_SIGNED:{} input_number {} base64_words {:x?} leb128 {:x?}",
            IS_SIGNED,
            if IS_SIGNED { -(solid_number as i64) } else { solid_number as i64 },
            base64_words,
            input_number_leb128,
        );
        let circuit = TestCircuit::<Fr, BIT_DEPTH, IS_SIGNED> {
            leb_base64_words: base64_words.as_slice(),
            leb_bytes: input_number_leb128.as_slice(),
            leb_last_byte_index: last_byte_index as u64,
            // solid_number: NUMBER,
            // solid_number_is_positive: !IS_SIGNED,
            _marker: PhantomData
        };
        self::test(circuit, true);
    }

    #[test]
    pub fn test_debug_exact_number() {
        debug_exact_number::<32, 64, false>();
        // debug_exact_number::<1, 64, true>();
        // debug_exact_number::<123456, 64, true>();
        // test_debug_exact_number::<16383, 64, true>();
        // test_debug_exact_number::<16382, 64, true>();
    }

    pub fn test_ok<const BIT_DEPTH: usize, const IS_SIGNED: bool>() {
        let mut rng = rand::thread_rng();
        let mut numbers_to_check = Vec::<(bool, u64)>::new();
        numbers_to_check.push((IS_SIGNED, 0));
        numbers_to_check.push((IS_SIGNED, 1));
        // TODO is it possible to represent 0 as signed?
        for i in 0..(BIT_DEPTH - 1) {
            let mut val: u64 = 2 << i;
            numbers_to_check.push((IS_SIGNED, val));

            if i > 0 {
                let val_rnd: u64 = rng.gen();
                val = val_rnd % val;
                numbers_to_check.push((IS_SIGNED, val));
            }
        }
        for input_number in numbers_to_check {
            let (input_number_leb128, last_byte_index) = convert_to_leb_bytes(!input_number.0, input_number.1, ((BIT_DEPTH + 6) / 7) as u8);
            let base64_words = convert_leb128_to_base64_words(&input_number_leb128, last_byte_index);
            println!(
                "IS_SIGNED:{} input_number {} base64_words {:x?} leb128 {:x?}",
                IS_SIGNED,
                if IS_SIGNED { -(input_number.1 as i64) } else { input_number.1 as i64 },
                base64_words,
                input_number_leb128,
            );
            let circuit = TestCircuit::<'_, Fr, BIT_DEPTH, IS_SIGNED> {
                leb_base64_words: base64_words.as_slice(),
                leb_bytes: input_number_leb128.as_slice(),
                leb_last_byte_index: last_byte_index as u64,
                // solid_number_is_positive: !input_number.0,
                // solid_number: input_number.1,
                _marker: PhantomData
            };
            self::test(circuit, true);
        }
    }

    #[test]
    pub fn test_ok_unsigned() {
        test_ok::<{ 8 * 1 }, false>();
        test_ok::<{ 8 * 2 }, false>();
        test_ok::<{ 8 * 3 }, false>();
        test_ok::<{ 8 * 4 }, false>();
        test_ok::<{ 8 * 5 }, false>();
        test_ok::<{ 8 * 6 }, false>();
        test_ok::<{ 8 * 7 }, false>();
        test_ok::<{ 8 * 8 }, false>();
    }

    #[test]
    pub fn test_ok_signed() {
        test_ok::<{ 8 * 1 }, true>();
        // test_ok::<{ 8 * 2 }, true>();
        // test_ok::<{ 8 * 3 }, true>();
        // test_ok::<{ 8 * 4 }, true>();
        // test_ok::<{ 8 * 5 }, true>();
        // test_ok::<{ 8 * 6 }, true>();
        // test_ok::<{ 8 * 7 }, true>();
    }

    pub fn leb_broken_continuation_bit<const BIT_DEPTH: usize, const IS_SIGNED: bool>() {
        let mut rng = rand::thread_rng();
        let mut solid_numbers_to_check = Vec::<u64>::new();
        solid_numbers_to_check.push(0);
        solid_numbers_to_check.push(1);
        for i in 0..(BIT_DEPTH - 1) {
            let mut val: u64 = 2 << i;
            solid_numbers_to_check.push(val);

            if i > 0 {
                let val_rnd: u64 = rng.gen();
                val = val_rnd % val;
                solid_numbers_to_check.push(val);
            }
        }
        for (i, &solid_number) in solid_numbers_to_check.iter().enumerate() {
            let (mut input_number_leb128, last_byte_index) = convert_to_leb_bytes(!IS_SIGNED, solid_number, ((BIT_DEPTH + 6) / 7) as u8);

            let base64_words = convert_leb128_to_base64_words(&input_number_leb128, last_byte_index);
            leb_break_continuation_bit(&mut rng, &mut input_number_leb128);

            println!(
                "IS_SIGNED:{} input_number {} base64_words {:x?} leb128 {:x?}",
                IS_SIGNED,
                if IS_SIGNED { -(solid_number as i64) } else { solid_number as i64 },
                base64_words,
                input_number_leb128,
            );
            let circuit = TestCircuit::<'_, Fr, BIT_DEPTH, IS_SIGNED> {
                leb_base64_words: base64_words.as_slice(),
                leb_bytes: input_number_leb128.as_slice(),
                leb_last_byte_index: last_byte_index as u64,
                // solid_number_is_positive: !IS_SIGNED,
                // solid_number,
                _marker: PhantomData
            };
            self::test(circuit, false);
        }
    }

    #[test]
    pub fn test_leb_broken_continuation_bit() {
        leb_broken_continuation_bit::<{ 8 * 1 }, false>();
        leb_broken_continuation_bit::<{ 8 * 2 }, false>();
        leb_broken_continuation_bit::<{ 8 * 3 }, false>();
        leb_broken_continuation_bit::<{ 8 * 4 }, false>();
        leb_broken_continuation_bit::<{ 8 * 5 }, false>();
        leb_broken_continuation_bit::<{ 8 * 6 }, false>();
        leb_broken_continuation_bit::<{ 8 * 7 }, false>();
        leb_broken_continuation_bit::<{ 8 * 8 }, false>();
    }

    pub fn leb_broken_random_bit<const BIT_DEPTH: usize, const IS_SIGNED: bool>() {
        let mut rng = rand::thread_rng();
        let mut solid_numbers_to_check = Vec::<u64>::new();
        solid_numbers_to_check.push(0);
        solid_numbers_to_check.push(1);
        for i in 0..(BIT_DEPTH - 1) {
            let mut val: u64 = 2 << i;
            solid_numbers_to_check.push(val);

            if i > 0 {
                let val_rnd: u64 = rng.gen();
                val = val_rnd % val;
                solid_numbers_to_check.push(val);
            }
        }
        for (i, &solid_number) in solid_numbers_to_check.iter().enumerate() {
            let (mut input_number_leb128, last_byte_index) = convert_to_leb_bytes(!IS_SIGNED, solid_number, ((BIT_DEPTH + 6) / 7) as u8);

            let base64_words = convert_leb128_to_base64_words(&input_number_leb128, last_byte_index);
            leb_break_random_bit(&mut rng, &mut input_number_leb128);

            println!(
                "IS_SIGNED:{} input_number {} base64_words {:x?} leb128 {:x?}",
                IS_SIGNED,
                if IS_SIGNED { -(solid_number as i64) } else { solid_number as i64 },
                base64_words,
                input_number_leb128,
            );
            let circuit = TestCircuit::<'_, Fr, BIT_DEPTH, IS_SIGNED> {
                leb_base64_words: base64_words.as_slice(),
                leb_bytes: input_number_leb128.as_slice(),
                leb_last_byte_index: last_byte_index as u64,
                // solid_number_is_positive: !IS_SIGNED,
                // solid_number,
                _marker: PhantomData
            };
            self::test(circuit, false);
        }
    }

    #[test]
    pub fn test_leb_broken_random_bit() {
        leb_broken_random_bit::<{ 8 * 1 }, false>();
        leb_broken_random_bit::<{ 8 * 2 }, false>();
        leb_broken_random_bit::<{ 8 * 3 }, false>();
        leb_broken_random_bit::<{ 8 * 4 }, false>();
        leb_broken_random_bit::<{ 8 * 5 }, false>();
        leb_broken_random_bit::<{ 8 * 6 }, false>();
        leb_broken_random_bit::<{ 8 * 7 }, false>();
        leb_broken_random_bit::<{ 8 * 8 }, false>();
    }

    // pub fn broken_solid_number<const BIT_DEPTH: usize, const IS_SIGNED: bool>() {
    //     let mut rng = rand::thread_rng();
    //     let mut solid_numbers_to_check = Vec::<u64>::new();
    //     solid_numbers_to_check.push(0);
    //     solid_numbers_to_check.push(1);
    //     for i in 0..(BIT_DEPTH - 1) {
    //         let mut val: u64 = 2 << i;
    //         solid_numbers_to_check.push(val);
    //
    //         if i > 0 {
    //             let val_rnd: u64 = rng.gen();
    //             val = val_rnd % val;
    //             solid_numbers_to_check.push(val);
    //         }
    //     }
    //     for (_i, &solid_number) in solid_numbers_to_check.iter().enumerate() {
    //         let (input_number_leb128, last_byte_index) = convert_to_leb_bytes(!IS_SIGNED, solid_number, ((BIT_DEPTH + 6) / 7) as u8);
    //
    //         // break solid number
    //         let mut broken_solid_number: u64;
    //         loop {
    //             broken_solid_number = rng.gen::<u64>();
    //             if broken_solid_number != solid_number { break }
    //         }
    //
    //         // println!("{}. input_number {} leb128 {:x?}", i, broken_solid_number, input_number_leb128);
    //         let base64_words = convert_leb128_to_base64_words(&input_number_leb128);
    //         let circuit = TestCircuit::<'_, Fr, BIT_DEPTH, IS_SIGNED> {
    //             leb_base64_words: base64_words.as_slice(),
    //             leb_bytes: input_number_leb128.as_slice(),
    //             leb_last_byte_index: last_byte_index as u64,
    //             // solid_number_is_positive: !IS_SIGNED,
    //             // solid_number: broken_solid_number,
    //             _marker: PhantomData
    //         };
    //         self::test(circuit, false);
    //     }
    // }
    //
    // #[test]
    // pub fn test_broken_solid_number() {
    //     broken_solid_number::<{ 8 * 1 }, false>();
    //     broken_solid_number::<{ 8 * 2 }, false>();
    //     broken_solid_number::<{ 8 * 3 }, false>();
    //     broken_solid_number::<{ 8 * 4 }, false>();
    //     broken_solid_number::<{ 8 * 5 }, false>();
    //     broken_solid_number::<{ 8 * 6 }, false>();
    //     broken_solid_number::<{ 8 * 7 }, false>();
    //     broken_solid_number::<{ 8 * 8 }, false>();
    // }

    pub fn broken_base64_word<const BIT_DEPTH: usize, const IS_SIGNED: bool>() {
        let mut rng = rand::thread_rng();
        let mut solid_numbers_to_check = Vec::<u64>::new();
        solid_numbers_to_check.push(0);
        solid_numbers_to_check.push(1);
        for i in 0..(BIT_DEPTH - 1) {
            let mut val: u64 = 2 << i;
            solid_numbers_to_check.push(val);

            if i > 0 {
                let val_rnd: u64 = rng.gen();
                val = val_rnd % val;
                solid_numbers_to_check.push(val);
            }
        }
        for (i, &solid_number) in solid_numbers_to_check.iter().enumerate() {
            let (input_number_leb128, last_byte_index) = convert_to_leb_bytes(!IS_SIGNED, solid_number, ((BIT_DEPTH + 6) / 7) as u8);

            let mut base64_words = convert_leb128_to_base64_words(&input_number_leb128, last_byte_index);
            // break base64 word
            let base64_word_index: usize = rng.gen::<usize>() % base64_words.len();
            loop {
                let broken_word = rng.gen::<u64>();
                if broken_word != base64_words[base64_word_index] {
                    base64_words[base64_word_index] = broken_word;
                    break
                }
            }

            println!(
                "{}. IS_SIGNED:{} input_number {} base64_words {:x?} leb128 {:x?}",
                i,
                IS_SIGNED,
                solid_number,
                base64_words,
                input_number_leb128,
            );
            let circuit = TestCircuit::<'_, Fr, BIT_DEPTH, IS_SIGNED> {
                leb_base64_words: base64_words.as_slice(),
                leb_bytes: input_number_leb128.as_slice(),
                leb_last_byte_index: last_byte_index as u64,
                // solid_number_is_positive: !IS_SIGNED,
                // solid_number,
                _marker: PhantomData
            };
            self::test(circuit, false);
        }
    }

    #[test]
    pub fn test_broken_base64_word() {
        broken_base64_word::<{ 8 * 1 }, false>();
        broken_base64_word::<{ 8 * 2 }, false>();
        broken_base64_word::<{ 8 * 3 }, false>();
        broken_base64_word::<{ 8 * 4 }, false>();
        broken_base64_word::<{ 8 * 5 }, false>();
        broken_base64_word::<{ 8 * 6 }, false>();
        broken_base64_word::<{ 8 * 7 }, false>();
        broken_base64_word::<{ 8 * 8 }, false>();
    }
}