#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AssignType {
    QFirst,
    QLast,

    IsItemsCount,
    IsMemSegmentType,
    IsMemIndex,
    IsMemSegmentSizeOpcode,
    IsMemSegmentSize,
    IsBlockEnd,
    IsMemSegmentLen,
    IsMemSegmentBytes,

    IsMemSegmentTypeCtx,

    MemSegmentType,

    BodyByteRevIndex,
    BodyItemRevCount,
}
