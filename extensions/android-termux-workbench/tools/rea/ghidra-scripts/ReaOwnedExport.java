// Static-only owned sample acceptance; never executes the target binary.
// @category REA.Static
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.Platform;
import ghidra.program.model.listing.*;
import com.google.gson.GsonBuilder;
import java.util.*;
import java.nio.file.*;

public class ReaOwnedExport extends GhidraScript {
    @Override public void run() throws Exception {
        if (getScriptArgs().length != 1) throw new IllegalArgumentException("output path required");
        Map<String,Object> result = new LinkedHashMap<>();
        result.put("task_id", "b06dd042-8638-4a47-937d-8ae644a205b9");
        result.put("program", currentProgram.getName());
        result.put("sha256", currentProgram.getExecutableSHA256());
        result.put("language", currentProgram.getLanguageID().toString());
        result.put("compiler_spec", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        result.put("java_os_name", System.getProperty("os.name"));
        result.put("java_os_arch", System.getProperty("os.arch"));
        result.put("ghidra_platform", Platform.CURRENT_PLATFORM.toString());
        result.put("max_heap_bytes", Runtime.getRuntime().maxMemory());
        result.put("static_only", true);
        List<Map<String,Object>> functions = new ArrayList<>();
        Function selected = null;
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while(it.hasNext()) {
            Function fn = it.next();
            if (functions.size() < 256) functions.add(Map.of("name",fn.getName(),"entry",fn.getEntryPoint().toString(),"external",fn.isExternal()));
            if(fn.getName().equals("owned_add")) selected = fn;
        }
        result.put("functions", functions);
        if(selected == null) throw new IllegalStateException("owned_add function missing");
        result.put("selected_function", selected.getName());
        List<Map<String,String>> instructions = new ArrayList<>();
        InstructionIterator ii = currentProgram.getListing().getInstructions(selected.getBody(), true);
        while(ii.hasNext() && instructions.size()<64) {
            Instruction ins = ii.next();
            instructions.add(Map.of("address",ins.getAddress().toString(),"assembly",ins.toString()));
        }
        result.put("instructions", instructions);
        DecompInterface decompiler = new DecompInterface();
        try {
            if(!decompiler.openProgram(currentProgram)) throw new IllegalStateException("native decompiler cannot open program: " + decompiler.getLastMessage());
            DecompileResults d = decompiler.decompileFunction(selected,15,monitor);
            result.put("decompile_completed", d.decompileCompleted());
            result.put("decompiler_error", d.getErrorMessage());
            if(d.getDecompiledFunction()!=null) result.put("decompiled_c",d.getDecompiledFunction().getC());
        } finally { decompiler.dispose(); }
        Path output=Path.of(getScriptArgs()[0]);
        Files.writeString(output,new GsonBuilder().setPrettyPrinting().create().toJson(result),StandardOpenOption.CREATE_NEW);
        println("REA_OWNED_HEADLESS_EXPORT " + output);
        if(!Boolean.TRUE.equals(result.get("decompile_completed")) || !result.containsKey("decompiled_c") || instructions.isEmpty()) throw new IllegalStateException("native decompilation incomplete");
    }
}
