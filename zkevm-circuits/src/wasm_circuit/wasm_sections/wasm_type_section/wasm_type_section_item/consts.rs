/// https://webassembly.github.io/spec/core/binary/types.html#binary-functype
#[derive(Copy, Clone)]
pub enum Type {
    FuncType = 0x60,
}
