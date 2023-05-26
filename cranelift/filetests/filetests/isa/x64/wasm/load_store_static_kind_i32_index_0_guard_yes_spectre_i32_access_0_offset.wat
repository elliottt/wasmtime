;;! target = "x86_64"
;;!
;;! settings = ['enable_heap_access_spectre_mitigation=true']
;;!
;;! compile = true
;;!
;;! [globals.vmctx]
;;! type = "i64"
;;! vmctx = true
;;!
;;! [globals.heap_base]
;;! type = "i64"
;;! load = { base = "vmctx", offset = 0, readonly = true }
;;!
;;! # (no heap_bound global for static heaps)
;;!
;;! [[heaps]]
;;! base = "heap_base"
;;! min_size = 0x10000
;;! offset_guard_size = 0
;;! index_type = "i32"
;;! style = { kind = "static", bound = 0x10000000 }

;; !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
;; !!! GENERATED BY 'make-load-store-tests.sh' DO NOT EDIT !!!
;; !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

(module
  (memory i32 1)

  (func (export "do_store") (param i32 i32)
    local.get 0
    local.get 1
    i32.store offset=0)

  (func (export "do_load") (param i32) (result i32)
    local.get 0
    i32.load offset=0))

;; function u0:0:
;;   push rbp
;;   unwind PushFrameRegs { offset_upward_to_caller_sp: 16 }
;;   mov rbp, rsp
;;   unwind DefineNewFrame { offset_upward_to_caller_sp: 16, offset_downward_to_clobbers: 0 }
;; block0:
;;   mov r10d, edi
;;   mov r8, r10
;;   add r8, r8, qword ptr [rdx + 0x0]
;;   xor r11, r11, r11
;;   cmp r10, $268435452
;;   cmovnbe r8, r11, r8
;;   mov dword ptr [r8 + 0x0], esi
;;   jmp label1
;; block1:
;;   mov rsp, rbp
;;   pop rbp
;;   ret
;;
;; function u0:1:
;;   push rbp
;;   unwind PushFrameRegs { offset_upward_to_caller_sp: 16 }
;;   mov rbp, rsp
;;   unwind DefineNewFrame { offset_upward_to_caller_sp: 16, offset_downward_to_clobbers: 0 }
;; block0:
;;   mov r10d, edi
;;   mov r8, r10
;;   add r8, r8, qword ptr [rsi + 0x0]
;;   xor r11, r11, r11
;;   cmp r10, $268435452
;;   cmovnbe r8, r11, r8
;;   mov eax, dword ptr [r8 + 0x0]
;;   jmp label1
;; block1:
;;   mov rsp, rbp
;;   pop rbp
;;   ret
