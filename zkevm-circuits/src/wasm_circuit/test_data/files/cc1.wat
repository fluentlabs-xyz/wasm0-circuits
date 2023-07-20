(module
  (type (;0;) (func))
  (type (;1;) (func))
  (type (;2;) (func (param i32)))
  (type (;3;) (func (param i32 i32)))
  (type (;4;) (func (param i32 i64)))
  (type (;5;) (func (param i64 i32) (result i32)))
  (import "spectest" "table" (table 0 10 funcref))
  (import "env" "_evm_address" (func (;0;) (type 2)))
  (import "env" "_evm_balance" (func (;1;) (type 3)))
  (import "env" "_evm_some_long_name_func_some_long_name_func_some_long_name_func_some_long_name_func_some_long_name_func_some_long_name_func_some_long_name_func_some_long_name_func" (func (;2;) (type 5)))
  (func (;3;) (type 0)
    block  ;; label = @1
      i32.const 1
      i32.const 2
      i32.add
      br 0 (;@1;)
      i32.const 100
      drop
    end)
  (func (;4;) (type 1)
    i32.const 1
    i32.const 2
    i32.add
    drop)
  (memory (;0;) 1)
  (export "main" (func 0))
  (export "memory" (memory 0))
  (data (i32.const 0))
)
