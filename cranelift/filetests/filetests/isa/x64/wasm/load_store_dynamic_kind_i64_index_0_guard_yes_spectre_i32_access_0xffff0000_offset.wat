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
;;! [globals.heap_bound]
;;! type = "i64"
;;! load = { base = "vmctx", offset = 8, readonly = true }
;;!
;;! [[heaps]]
;;! base = "heap_base"
;;! min_size = 0x10000
;;! offset_guard_size = 0
;;! index_type = "i64"
;;! style = { kind = "dynamic", bound = "heap_bound" }

;; !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
;; !!! GENERATED BY 'make-load-store-tests.sh' DO NOT EDIT !!!
;; !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

(module
  (memory i64 1)

  (func (export "do_store") (param i64 i32)
    local.get 0
    local.get 1
    i32.store offset=0xffff0000)

  (func (export "do_load") (param i64) (result i32)
    local.get 0
    i32.load offset=0xffff0000))

;; function u0:0:
;;   push rbp
;;   unwind PushFrameRegs { offset_upward_to_caller_sp: 16 }
;;   mov rbp, rsp
;;   unwind DefineNewFrame { offset_upward_to_caller_sp: 16, offset_downward_to_clobbers: 0 }
;; block0:
;;   mov r8, rdi
;;   add r8, r8, const(0)
;;   jb #trap=heap_oob
;;   mov rax, qword ptr [rdx + 0x8]
;;   mov rcx, rdi
;;   add rcx, rcx, qword ptr [rdx + 0x0]
;;   mov edx, 0xffff0000
;;   lea rcx, qword ptr [rcx + rdx]
;;   xor rdx, rdx, rdx
;;   cmp r8, rax
;;   cmovnbe rcx, rdx, rcx
;;   mov dword ptr [rcx + 0x0], esi
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
;;   mov rcx, rdi
;;   add rcx, rcx, const(0)
;;   jb #trap=heap_oob
;;   mov rax, qword ptr [rsi + 0x8]
;;   mov rdx, rdi
;;   add rdx, rdx, qword ptr [rsi + 0x0]
;;   mov r8d, 0xffff0000
;;   lea rsi, qword ptr [rdx + r8]
;;   xor rdx, rdx, rdx
;;   cmp rcx, rax
;;   cmovnbe rsi, rdx, rsi
;;   mov eax, dword ptr [rsi + 0x0]
;;   jmp label1
;; block1:
;;   mov rsp, rbp
;;   pop rbp
;;   ret
