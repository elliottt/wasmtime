use crate::compiler::Compiler;
use anyhow::Result;
use wasmtime_environ::component::{AllCallFunc, ComponentCompiler};
use winch_codegen::ComponentTrampolineKind;

impl ComponentCompiler for Compiler {
    fn compile_trampoline(
        &self,
        component: &wasmtime_environ::component::ComponentTranslation,
        types: &wasmtime_environ::component::ComponentTypesBuilder,
        trampoline: wasmtime_environ::component::TrampolineIndex,
    ) -> anyhow::Result<AllCallFunc<Box<dyn std::any::Any + Send>>> {
        let compile = |abi: ComponentTrampolineKind| -> Result<_> {
            Ok(Box::new(self.isa.compile_component_trampoline(
                component, types, trampoline, abi,
            )?))
        };

        Ok(AllCallFunc {
            wasm_call: compile(ComponentTrampolineKind::Wasm)?,
            array_call: compile(ComponentTrampolineKind::Array)?,
            native_call: compile(ComponentTrampolineKind::Native)?,
        })
    }
}
