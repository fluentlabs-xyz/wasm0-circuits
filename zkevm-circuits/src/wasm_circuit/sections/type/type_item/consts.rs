use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::Expression;
use gadgets::util::Expr;

/// https://webassembly.github.io/spec/core/binary/types.html#binary-functype
#[derive(Copy, Clone)]
pub enum Type {
    FuncType = 0x60,
}
impl<F: FieldExt> Expr<F> for Type {
    fn expr(&self) -> Expression<F> {
        Expression::Constant(F::from(*self as u64))
    }
}
