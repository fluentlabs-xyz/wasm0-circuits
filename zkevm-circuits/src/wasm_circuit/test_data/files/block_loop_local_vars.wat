(module
  (global $g1 (import "js" "global") (mut i32))
  (global $g2 (mut i32) (i32.const 0))
  (global $g3 (mut i64) (i64.const 0))
  (global $g4 (mut i64) (i64.const 77777))
  (type (;0;) (func))
  (type (;1;) (func))
  (type (;2;) (func (param i32)))
  (type (;3;) (func (param i32 i32)))
  (type (;4;) (func (param i32 i64)))
  (type (;5;) (func (param i64 i32) (result i32)))
  (func (;0;) (type 0)
    (local i32)
    i32.const 0
    local.set 0
    block  ;; label = @1
      loop  ;; label = @2
        local.get 0
        br_if 1 (;@1;)
        local.get 0
        i32.const 123456
        i32.add
        local.set 0
        br 0 (;@2;)
      end
    end)
  (func (;1;) (type 2)
    (local i32 i64 i32 i32 i64 i64 i64)
    i32.const 0
    local.set 0
    )
  (func (;2;) (type 0)
    (local i32)
    i32.const 0
    drop
    )
  (start 2)
  (memory (;0;) 1)
  (export "main" (func 0))
  (export "memory" (memory 0))
  (data (;0;) (i32.const 1048575) "none")
  (data (;1;) (i32.const 1048576) "\00asm\01\00\00\00\01\09\02`\02\7f\7f\00`\00\00\02\13\01\03env\0b_evm_return\00\00\03\02\01\01\05\03\01\00\11\06\19\03\7f\01A\80\80\c0\00\0b\7f\00A\8c\80\c0\00\0b\7f\00A\90\80\c0\00\0b\07,\04\06memory\02\00\04main\00\01\0a__data_end\03\01\0b__heap_base\03\02\0a\0d\01\0b\00A\80\80\c0\00A\0c\10\00\0b\0b\15\01\00A\80\80\c0\00\0b\0cHello, World")
)
