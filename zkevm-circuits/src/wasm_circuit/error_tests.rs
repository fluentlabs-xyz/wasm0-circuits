#[cfg(test)]
mod error_tests {
    use crate::wasm_circuit::error::{Error, is_fatal_error, is_recoverable_error};
    use strum::IntoEnumIterator;

    #[test]
    fn error_must_be_recoverable_or_fatal() {
        for e in Error::iter() {
            let mut is_recoverable = false;
            let mut is_fatal = false;
            if is_recoverable_error(&e) { is_recoverable = true }
            if is_fatal_error(&e) { is_fatal = true }
            if is_recoverable == true && is_fatal == true || is_recoverable != true && is_fatal != true {
                panic!("error 'Error::{:?}' must be put into recoverable or fatal fn checker", e)
            }
        }
    }
}