use halo2_proofs::plonk::{Column, Expression, Fixed, VirtualCells};
use halo2_proofs::poly::Rotation;
use eth_types::Field;
use gadgets::util::Expr;
use crate::evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon};

pub fn configure_check_for_transition<F: Field>(
    cb: &mut BaseConstraintBuilder<F>,
    vc: &mut VirtualCells<F>,
    name: &'static str,
    is_for_next: bool,
    condition: Expression<F>,
    columns_to_check: &[Column<Fixed>],
) {
    cb.condition(
        condition,
        |bcb| {
            let mut lhs = 0.expr();
            for column_to_check in columns_to_check {
                lhs = lhs + vc.query_fixed(*column_to_check, Rotation(if is_for_next { 1 } else { -1 }));
            }
            bcb.require_equal(
                name,
                lhs,
                1.expr(),
            )
        }
    );
}
