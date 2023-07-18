use halo2_proofs::plonk::{Column, Expression, Fixed, VirtualCells};
use halo2_proofs::poly::Rotation;
use eth_types::Field;
use gadgets::util::{and, Expr, not, or};
use crate::evm_circuit::util::constraint_builder::{BaseConstraintBuilder, ConstrainBuilderCommon};

/// `is_check_next` is check next or prev
pub fn configure_transition_check<F: Field>(
    cb: &mut BaseConstraintBuilder<F>,
    vc: &mut VirtualCells<F>,
    name: &'static str,
    condition: Expression<F>,
    is_check_next: bool,
    columns_to_check: &[Column<Fixed>],
) {
    cb.condition(
        condition,
        |bcb| {
            let mut lhs = 0.expr();
            for column_to_check in columns_to_check {
                lhs = lhs + vc.query_fixed(*column_to_check, Rotation(if is_check_next { 1 } else { -1 }));
            }
            bcb.require_equal(
                name,
                lhs,
                1.expr(),
            )
        }
    );
}

pub fn configure_constraints_for_q_first_and_q_last<F: Field>(
    cb: &mut BaseConstraintBuilder<F>,
    vc: &mut VirtualCells<F>,
    q_enable: &Column<Fixed>,
    q_first: &Column<Fixed>,
    q_first_column_selectors: &[Column<Fixed>],
    q_last: &Column<Fixed>,
    q_last_column_selectors: &[Column<Fixed>],
) {
    let q_enable_expr = vc.query_fixed(*q_enable, Rotation::cur());
    let q_first_expr = vc.query_fixed(*q_first, Rotation::cur());
    let q_last_expr = vc.query_fixed(*q_last, Rotation::cur());

    cb.require_boolean("q_first is boolean", q_first_expr.clone());
    cb.require_boolean("q_last is boolean", q_last_expr.clone());

    if q_first_column_selectors.len() <= 0 || q_last_column_selectors.len() <= 0 {
        panic!("*column_selectors must contain at leas 1 element each")
    }

    cb.condition(
        q_first_expr.clone(),
        |bcb| {
            bcb.require_equal(
                "q_first => specific selectors must be active",
                or::expr(q_first_column_selectors.iter().map(|v| vc.query_fixed(*v, Rotation::cur()))),
                1.expr(),
            )
        }
    );
    cb.condition(
        q_last_expr.clone(),
        |bcb| {
            bcb.require_equal(
                "q_last => specific selectors must be active",
                or::expr(q_last_column_selectors.iter().map(|v| vc.query_fixed(*v, Rotation::cur()))),
                1.expr(),
            )
        }
    );

    cb.condition(
        or::expr([
            q_first_expr.clone(),
            q_last_expr.clone(),
        ]),
        |bcb| {
            bcb.require_equal(
                "q_first || q_last => q_enable=1",
                q_enable_expr.clone(),
                1.expr(),
            );
        }
    );
    cb.condition(
        and::expr([
            q_first_expr.clone(),
            not::expr(q_last_expr.clone()),
        ]),
        |bcb| {
            let q_first_next_expr = vc.query_fixed(*q_first, Rotation::next());
            bcb.require_zero(
                "q_first && !q_last -> !next.q_first",
                q_first_next_expr.clone(),
            );
        }
    );
    cb.condition(
        and::expr([
            q_last_expr.clone(),
            not::expr(q_first_expr.clone()),
        ]),
        |bcb| {
            let q_last_prev_expr = vc.query_fixed(*q_last, Rotation::prev());
            bcb.require_zero(
                "q_last && !q_first -> !prev.q_last",
                q_last_prev_expr.clone(),
            );
        }
    );
    cb.condition(
        and::expr([
            not::expr(q_first_expr.clone()),
            not::expr(q_last_expr.clone()),
        ]),
        |bcb| {
            let q_first_next_expr = vc.query_fixed(*q_first, Rotation::next());
            let q_last_prev_expr = vc.query_fixed(*q_last, Rotation::prev());
            bcb.require_zero(
                "!q_first && !q_last -> !next.q_first",
                q_first_next_expr.clone(),
            );
            bcb.require_zero(
                "!q_first && !q_last -> !prev.q_last",
                q_last_prev_expr.clone(),
            );
        }
    );
}
