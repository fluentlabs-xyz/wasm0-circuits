#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AssignType {
    QFirst,
    QLast,

    IsType,
    IsInputCount,
    IsInputType,
    IsOutputCount,
    IsOutputType,

    BodyItemRevCount,
}
