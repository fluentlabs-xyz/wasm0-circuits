(module
  (type (;0;) (func))
  (func (;0;) (type 0)
    block  ;; label = @1
      i32.const 1
      i32.const 2
      i32.add
      br 0 (;@1;)
      i32.const 100
      drop
    end)
  (memory (;0;) 1)
  (export "main" (func 0))
  (export "memory" (memory 0)))
