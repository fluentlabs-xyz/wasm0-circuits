use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::Expression;
use gadgets::util::Expr;

/// https://webassembly.github.io/spec/core/binary/modules.html#export-section
#[derive(Copy, Clone)]
pub enum ExportDesc {
    FuncExportDesc = 0x0,
    TableExportDesc = 0x1,
    MemExportDesc = 0x2,
    GlobalExportDesc = 0x3,
}
impl<F: FieldExt> Expr<F> for ExportDesc {
    #[inline]
    fn expr(&self) -> Expression<F> {
        Expression::Constant(F::from(*self as u64))
    }
}