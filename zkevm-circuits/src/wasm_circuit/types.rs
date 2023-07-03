#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AssignType {
    Unknown,
    QFirst,
    QLast,
    IsSectionId,
    IsSectionLen,
    IsSectionBody,
}
