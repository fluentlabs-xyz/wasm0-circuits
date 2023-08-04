#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AssignType {
    QFirst,
    QLast,

    IsBodyItemsCount,
    IsBody,

    BodyItemRevCount,
}
