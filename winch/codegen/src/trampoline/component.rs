use super::Trampoline as WinchTrampoline;
use crate::{
    abi::{array_sig, native_sig, wasm_sig, ABISig},
    masm::{CalleeKind, Imm, MacroAssembler, OperandSize, RegImm},
    reg::Reg,
};
use cranelift_codegen::ir::TrapCode;
use wasmtime_environ::{
    component::{
        CanonicalOptions, Component, ComponentTranslation, ComponentTypesBuilder,
        GlobalInitializer, LoweredIndex, RuntimeMemoryIndex, Trampoline, TrampolineIndex,
        TypeFuncIndex, TypeResourceTableIndex, VMComponentOffsets,
    },
    fact::Transcode,
    CompileError, ModuleInternedTypeIndex, PtrSize,
};

#[derive(Copy, Clone)]
pub enum ComponentTrampolineKind {
    Array,
    Native,
    Wasm,
}

impl<M: MacroAssembler> WinchTrampoline<'_, M> {
    pub fn emit_component_trampoline(
        self,
        component: &ComponentTranslation,
        types: &ComponentTypesBuilder,
        index: TrampolineIndex,
        kind: ComponentTrampolineKind,
    ) -> Result<(), CompileError> {
        let mut c = ComponentTrampoline::new(self, component, types, index, kind);

        c.prologue();

        // TODO: wasm-to-native boundary crossing stuff

        c.translate(&component.trampolines[index]);

        c.epilogue();

        Ok(())
    }
}
struct ComponentTrampoline<'a, M: MacroAssembler> {
    trampoline: WinchTrampoline<'a, M>,
    component: &'a Component,
    kind: ComponentTrampolineKind,
    signature: ModuleInternedTypeIndex,
    sig: ABISig,
    offsets: VMComponentOffsets<u8>,
    types: &'a ComponentTypesBuilder,
}

/// Trap code used for debug assertions we emit in our JIT code.
const DEBUG_ASSERT_TRAP_CODE: u16 = u16::MAX;

const ALWAYS_TRAP_CODE: u16 = 100;

const CANNOT_ENTER_CODE: u16 = 101;

impl<'a, M: MacroAssembler> ComponentTrampoline<'a, M> {
    fn new(
        trampoline: WinchTrampoline<'a, M>,
        component: &'a ComponentTranslation,
        types: &'a ComponentTypesBuilder,
        index: TrampolineIndex,
        kind: ComponentTrampolineKind,
    ) -> Self {
        let signature = component.component.trampolines[index];
        let ty = &types[signature];
        let sig = match kind {
            ComponentTrampolineKind::Array => array_sig::<M::ABI>(&trampoline.call_conv),
            ComponentTrampolineKind::Native => native_sig::<M::ABI>(ty, &trampoline.call_conv),
            ComponentTrampolineKind::Wasm => wasm_sig::<M::ABI>(ty),
        };
        let offsets = VMComponentOffsets::new(trampoline.pointer_size.size(), &component.component);
        Self {
            component: &component.component,
            trampoline,
            kind,
            signature,
            sig,
            offsets,
            types,
        }
    }

    fn prologue(&mut self) {
        let (callee_vmctx, caller_vmctx) =
            WinchTrampoline::<'a, M>::callee_and_caller_vmctx(&self.sig.params).unwrap();

        let clobbers = match self.kind {
            ComponentTrampolineKind::Array => self.trampoline.callee_saved_regs.as_slice(),
            ComponentTrampolineKind::Native => self.trampoline.callee_saved_regs.as_slice(),
            ComponentTrampolineKind::Wasm => &[],
        };

        self.trampoline.masm.prologue(caller_vmctx, clobbers);
    }

    fn epilogue(&mut self) {
        let clobbers = match self.kind {
            ComponentTrampolineKind::Array => self.trampoline.callee_saved_regs.as_slice(),
            ComponentTrampolineKind::Native => self.trampoline.callee_saved_regs.as_slice(),
            ComponentTrampolineKind::Wasm => &[],
        };

        self.trampoline.masm.epilogue(clobbers);
    }

    fn clobbers(&self) -> &[(Reg, OperandSize)] {
        match self.kind {
            ComponentTrampolineKind::Array => self.trampoline.callee_saved_regs.as_slice(),
            ComponentTrampolineKind::Native => self.trampoline.callee_saved_regs.as_slice(),
            ComponentTrampolineKind::Wasm => &[],
        }
    }

    fn load_libcall(
        masm: &mut M,
        vmctx: Reg,
        scratch: Reg,
        offsets: &VMComponentOffsets<u8>,
        offset: u32,
    ) {
        // load the libcall into the scratch register
        masm.load(
            masm.address_at_reg(vmctx, offsets.libcalls()),
            scratch,
            OperandSize::S64,
        );
        masm.load(
            masm.address_at_reg(scratch, offset * u32::try_from(offsets.ptr.size()).unwrap()),
            scratch,
            OperandSize::S64,
        );
    }

    fn translate(&mut self, trampoline: &Trampoline) {
        match trampoline {
            Trampoline::Transcoder {
                op,
                from,
                from64,
                to,
                to64,
            } => match self.kind {
                // These trampolines can only actually be called by Wasm, so let's assert that
                // here.
                ComponentTrampolineKind::Array | ComponentTrampolineKind::Native => self
                    .trampoline
                    .masm
                    .trap(TrapCode::User(DEBUG_ASSERT_TRAP_CODE)),
                ComponentTrampolineKind::Wasm => {
                    self.translate_trancode(*op, *from, *from64, *to, *to64)
                }
            },
            Trampoline::LowerImport {
                index,
                lower_ty,
                options,
            } => self.translate_lower_import(*index, options, *lower_ty),
            Trampoline::AlwaysTrap => self.trampoline.masm.trap(TrapCode::User(ALWAYS_TRAP_CODE)),
            Trampoline::ResourceNew(ty) => self.translate_resource_new(*ty),
            Trampoline::ResourceRep(ty) => self.translate_resource_rep(*ty),
            Trampoline::ResourceDrop(ty) => self.translate_resource_drop(*ty),
            Trampoline::ResourceTransferOwn => {
                self.translate_resource_libcall(host::resource_transfer_own)
            }
            Trampoline::ResourceTransferBorrow => {
                self.translate_resource_libcall(host::resource_transfer_borrow)
            }
            Trampoline::ResourceEnterCall => {
                self.translate_resource_libcall(host::resource_enter_call)
            }
            Trampoline::ResourceExitCall => {
                self.translate_resource_libcall(host::resource_exit_call)
            }
        }
    }

    /// Translate a string transcoding operation.
    fn translate_trancode(
        &self,
        op: Transcode,
        from: RuntimeMemoryIndex,
        from64: bool,
        to: RuntimeMemoryIndex,
        to64: bool,
    ) {
        todo!("translate_trancode")
    }

    fn translate_lower_import(
        &self,
        index: LoweredIndex,
        options: &CanonicalOptions,
        lower_ty: TypeFuncIndex,
    ) {
        todo!("translate_lower_import")
    }

    fn translate_resource_new(&self, resourcety: TypeResourceTableIndex) {
        todo!("translate_resource_new")
    }

    fn translate_resource_rep(&self, resourcety: TypeResourceTableIndex) {
        todo!("translate_resource_rep")
    }

    fn translate_resource_drop(&mut self, resource: TypeResourceTableIndex) {
        let args = self.sig.params_without_retptr();
        assert!(args.len() >= 3);

        let (host_sig, offset) = host::resource_drop(&self.trampoline);

        let (offsets, spill_size) = self.trampoline.spill(self.sig.params());

        let vmctx = args[0].unwrap_reg();
        let vmctx_runtime_limits_addr = self.trampoline.vmctx_runtime_limits_addr(vmctx);
        let scratch = self.trampoline.scratch_reg;
        let allocated_stack = self
            .trampoline
            .masm
            .call(host_sig.params_stack_size(), |masm| {
                // load the libcall into the scratch register
                Self::load_libcall(masm, vmctx, scratch, &self.offsets, offset);

                WinchTrampoline::<'a, M>::save_last_wasm_entry_sp(
                    masm,
                    vmctx_runtime_limits_addr,
                    self.trampoline.scratch_reg,
                    &self.trampoline.pointer_size,
                );

                let params = host_sig.params_without_retptr();
                assert_eq!(3, params.len(), "canonical drop function with invalid args");

                // TODO: is there a better way to setup the intrinsic arguments that doesn't
                // require making assumptions about the intrinsic taking its args through
                // registers? WinchTrampoline::assign_args does most of what's needed here, but
                // it would require a bit of fussing to allow some of the args to come from known
                // registers, instead of everything starting spilled on the stack.

                // The arguments this shim passes along to the libcall are:
                //
                //   * the vmctx
                masm.load(
                    masm.address_at_sp(offsets[0]),
                    params[0].unwrap_reg(),
                    OperandSize::S64,
                );

                //   * a constant value for this `ResourceDrop` intrinsic
                masm.mov(
                    RegImm::Imm(Imm::i64(resource.as_u32().try_into().unwrap())),
                    params[1].unwrap_reg(),
                    OperandSize::S64,
                );

                //   * the wasm handle index to drop
                masm.load(
                    masm.address_at_sp(offsets[2]),
                    params[2].unwrap_reg(),
                    OperandSize::S64,
                );

                CalleeKind::Indirect(self.trampoline.scratch_reg)
            });

        self.trampoline.masm.free_stack(allocated_stack);

        let resource_ty = self.types[resource].ty;
        let resource_def = self
            .component
            .defined_resource_index(resource_ty)
            .map(|idx| {
                self.component
                    .initializers
                    .iter()
                    .filter_map(|i| match i {
                        GlobalInitializer::Resource(r) if r.index == idx => Some(r),
                        _ => None,
                    })
                    .next()
                    .unwrap()
            });
        let has_destructor = resource_def.map(|def| def.dtor.is_some()).unwrap_or(false);

        if has_destructor {
            todo!("translate_resource_drop: destructor")
        }

        self.trampoline.masm.free_stack(spill_size);
    }

    fn translate_resource_libcall(
        &self,
        get_libcall: fn(t: &WinchTrampoline<'_, M>) -> (ABISig, u32),
    ) {
        todo!("translate_resource_libcall")
    }
}

/// Module with macro-generated contents that will return the signature and
/// offset for each of the host transcoder functions.
///
/// Note that a macro is used here to keep this in sync with the actual
/// transcoder functions themselves which are also defined via a macro.
mod host {
    use super::WinchTrampoline;
    use crate::{
        abi::{ABISig, ABI},
        masm::MacroAssembler,
    };
    use wasmtime_environ::WasmValType;

    macro_rules! define {
        (
            $(
                $( #[$attr:meta] )*
                $name:ident( $( $pname:ident: $param:ident ),* ) $( -> $result:ident )?;
            )*
        ) => {
            $(
                pub(super) fn $name<'a, M: MacroAssembler>(
                    t: &WinchTrampoline<'a, M>,
                ) -> (ABISig, u32) {
                    let pointer_type = t.pointer_type;
                    let params = vec![
                        $( define!(@ty pointer_type $param) ),*
                    ];
                    let returns = vec![
                        $( define!(@ty pointer_type $result) )?
                    ];
                    let sig = M::ABI::sig_from(&params, &returns, t.call_conv);

                    (sig, offsets::$name)
                }
            )*
        };

        (@ty $ptr:ident size) => ($ptr);
        (@ty $ptr:ident ptr_u8) => ($ptr);
        (@ty $ptr:ident ptr_u16) => ($ptr);
        (@ty $ptr:ident ptr_size) => ($ptr);
        (@ty $ptr:ident u32) => (WasmValType::I32);
        (@ty $ptr:ident u64) => (WasmValType::I64);
        (@ty $ptr:ident vmctx) => ($ptr);
    }

    wasmtime_environ::foreach_transcoder!(define);
    wasmtime_environ::foreach_builtin_component_function!(define);

    mod offsets {
        macro_rules! offsets {
            (
                $(
                    $( #[$attr:meta] )*
                    $name:ident($($t:tt)*) $( -> $result:ident )?;
                )*
            ) => {
                offsets!(@declare (0) $($name)*);
            };

            (@declare ($n:expr)) => (const LAST_BUILTIN: u32 = $n;);
            (@declare ($n:expr) $name:ident $($rest:tt)*) => (
                pub const $name: u32 = $n;
                offsets!(@declare ($n + 1) $($rest)*);
            );
        }

        wasmtime_environ::foreach_builtin_component_function!(offsets);

        macro_rules! transcode_offsets {
            (
                $(
                    $( #[$attr:meta] )*
                    $name:ident($($t:tt)*) $( -> $result:ident )?;
                )*
            ) => {
                transcode_offsets!(@declare (0) $($name)*);
            };

            (@declare ($n:expr)) => ();
            (@declare ($n:expr) $name:ident $($rest:tt)*) => (
                pub const $name: u32 = LAST_BUILTIN + $n;
                transcode_offsets!(@declare ($n + 1) $($rest)*);
            );
        }

        wasmtime_environ::foreach_transcoder!(transcode_offsets);
    }
}
