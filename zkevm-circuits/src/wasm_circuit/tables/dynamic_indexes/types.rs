use strum_macros::EnumIter;

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
pub const TAG_ALL: &[Tag] = &[
    Tag::CodeSectionFuncIndex,
    Tag::TypeSectionTypeIndex,
];