use std::ops::{Add, Mul};
use halo2_proofs::plonk::Expression;

use num_bigint::BigUint;
use eth_types::Field;

pub mod opcode;
pub mod table;

pub trait FromBn: Sized + Add<Self, Output = Self> + Mul<Self, Output = Self> {
    fn zero() -> Self;
    fn from_bn(bn: &BigUint) -> Self;
}

impl FromBn for BigUint {
    fn zero() -> Self {
        BigUint::from(0u64)
    }

    fn from_bn(bn: &BigUint) -> Self {
        bn.clone()
    }
}

fn bn_to_field<F: Field>(bn: &BigUint) -> F {
    let mut bytes = bn.to_bytes_le();
    bytes.resize(32, 0);
    let mut bytes32: [u8; 32] = Default::default();
    bytes32.copy_from_slice(&bytes[0..32]);
    F::from_repr(bytes32).unwrap()
}


impl<F: Field> FromBn for Expression<F> {
    fn from_bn(bn: &BigUint) -> Self {
        halo2_proofs::plonk::Expression::Constant(bn_to_field(bn))
    }

    fn zero() -> Self {
        halo2_proofs::plonk::Expression::Constant(F::zero())
    }
}
