(module
  (type (;0;) (func))
  (type (;1;) (func))
  (type (;2;) (func (param i32 i64)))
  (type (;3;) (func (param i64 i32) (result i32)))
  (func (;0;) (type 0)
    block  ;; label = @1
      i32.const 1
      i32.const 2
      i32.add
      br 0 (;@1;)
      i32.const 100
      drop
    end)
  (func (;1;) (type 1)
      i32.const 1
      i32.const 2
      i32.add
      drop
    )
  (memory (;0;) 1)
  (export "main" (func 0))
  (export "memory" (memory 0)))
