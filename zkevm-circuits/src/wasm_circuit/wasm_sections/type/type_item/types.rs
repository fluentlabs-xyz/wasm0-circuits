#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AssignType {
    IsType,
    IsInputCount,
    IsInputType,
    IsOutputCount,
    IsOutputType,
}
