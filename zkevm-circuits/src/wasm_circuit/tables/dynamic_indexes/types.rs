use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::Expression;
use strum_macros::EnumIter;
use gadgets::util::Expr;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AssignType {
    Index,
    IsTerminator,
    Tag,
}

#[derive(Default, Copy, Clone, Debug, EnumIter, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tag {
    #[default]
    CodeSectionFuncIndex,
    TypeSectionTypeIndex,
}
pub const TAG_VALUES: &[Tag] = &[
    Tag::CodeSectionFuncIndex,
    Tag::TypeSectionTypeIndex,
];
impl<F: FieldExt> Expr<F> for Tag {
    fn expr(&self) -> Expression<F> {
        Expression::Constant(F::from(*self as u64))
    }
}