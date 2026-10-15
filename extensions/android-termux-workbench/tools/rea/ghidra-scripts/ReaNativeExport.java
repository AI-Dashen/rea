// Static-only native export for the REA Android Workbench. Never executes target code.
// @category REA.Static
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.Platform;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import com.google.gson.GsonBuilder;
import java.util.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;

public class ReaNativeExport extends GhidraScript {
    private Map<String,Object> functionSummary(Function function) {
        Map<String,Object> item = new LinkedHashMap<>();
        item.put("name", function.getName());
        item.put("entry", function.getEntryPoint().toString());
        item.put("external", function.isExternal());
        item.put("thunk", function.isThunk());
        return item;
    }

    private Function selectByString(String query, Map<String,Object> result) throws Exception {
        if (query.isEmpty() || query.length() > 512) {
            throw new IllegalArgumentException("invalid string selector");
        }
        Memory memory = currentProgram.getMemory();
        byte[] needle = query.getBytes(StandardCharsets.UTF_8);
        Address cursor = memory.getMinAddress();
        List<Map<String,String>> matches = new ArrayList<>();
        Function selected = null;
        while (cursor != null && matches.size() < 32) {
            Address match = memory.findBytes(cursor, needle, null, true, monitor);
            if (match == null) break;
            ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(match);
            int refCount = 0;
            while (refs.hasNext() && refCount < 128) {
                Reference ref = refs.next();
                refCount++;
                Function owner = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                Map<String,String> evidence = new LinkedHashMap<>();
                evidence.put("string_address", match.toString());
                evidence.put("reference_from", ref.getFromAddress().toString());
                evidence.put("function", owner == null ? "UNKNOWN" : owner.getName());
                matches.add(evidence);
                if (selected == null && owner != null && !owner.isExternal()) selected = owner;
                if (matches.size() >= 32) break;
            }
            try {
                cursor = match.add(1);
            } catch (Exception exhausted) {
                cursor = null;
            }
        }
        result.put("string_query", query);
        result.put("string_references", matches);
        return selected;
    }

    @Override public void run() throws Exception {
        if (getScriptArgs().length < 1 || getScriptArgs().length > 2) {
            throw new IllegalArgumentException("output path [selector]");
        }
        String selector = getScriptArgs().length == 2 ? getScriptArgs()[1] : "";
        Map<String,Object> result = new LinkedHashMap<>();
        result.put("schema_version", 2);
        result.put("program", currentProgram.getName());
        result.put("sha256", currentProgram.getExecutableSHA256());
        result.put("language", currentProgram.getLanguageID().toString());
        result.put("compiler_spec", currentProgram.getCompilerSpec().getCompilerSpecID().toString());
        result.put("ghidra_platform", Platform.CURRENT_PLATFORM.toString());
        result.put("static_only", true);
        result.put("fidelity", "disassembled");
        result.put("selector", selector);

        List<Map<String,Object>> functions = new ArrayList<>();
        List<Function> candidates = new ArrayList<>();
        Function selected = null;
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
        while (iterator.hasNext()) {
            Function function = iterator.next();
            if (functions.size() < 1024) functions.add(functionSummary(function));
            if (!function.isExternal() && !function.getBody().isEmpty()) candidates.add(function);
        }
        result.put("functions", functions);
        result.put("function_count_observed", candidates.size());
        result.put("function_list_truncated", functions.size() >= 1024);

        if (selector.startsWith("symbol:")) {
            String requested = selector.substring("symbol:".length());
            for (Function function : candidates) {
                if (function.getName().equals(requested)) {
                    selected = function;
                    break;
                }
            }
        } else if (selector.startsWith("address:")) {
            Address address = currentProgram.getAddressFactory().getAddress(selector.substring("address:".length()));
            if (address == null) throw new IllegalArgumentException("invalid address selector");
            selected = currentProgram.getFunctionManager().getFunctionAt(address);
            if (selected == null) selected = currentProgram.getFunctionManager().getFunctionContaining(address);
        } else if (selector.startsWith("string:")) {
            selected = selectByString(selector.substring("string:".length()), result);
        } else if (!selector.isEmpty()) {
            // Backward-compatible v1 symbol argument.
            for (Function function : candidates) {
                if (function.getName().equals(selector)) {
                    selected = function;
                    break;
                }
            }
        }

        if (selected == null && selector.isEmpty()) {
            for (Function function : candidates) {
                if (function.getName().equals("JNI_OnLoad") || function.getName().startsWith("Java_")) {
                    selected = function;
                    break;
                }
            }
            if (selected == null && !candidates.isEmpty()) selected = candidates.get(0);
        }
        if (selected == null) throw new IllegalStateException(
                selector.isEmpty() ? "no analyzable function" : "selector did not resolve: " + selector);
        result.put("selected_function", selected.getName());
        result.put("selected_entry", selected.getEntryPoint().toString());

        List<Map<String,String>> instructions = new ArrayList<>();
        InstructionIterator instructionIterator = currentProgram.getListing().getInstructions(selected.getBody(), true);
        while (instructionIterator.hasNext() && instructions.size() < 256) {
            Instruction instruction = instructionIterator.next();
            Map<String,String> item = new LinkedHashMap<>();
            item.put("address", instruction.getAddress().toString());
            item.put("assembly", instruction.toString());
            instructions.add(item);
        }
        result.put("instructions", instructions);

        List<Map<String,Object>> callers = new ArrayList<>();
        for (Function function : selected.getCallingFunctions(monitor)) {
            if (callers.size() >= 256) break;
            callers.add(functionSummary(function));
        }
        List<Map<String,Object>> callees = new ArrayList<>();
        for (Function function : selected.getCalledFunctions(monitor)) {
            if (callees.size() >= 256) break;
            callees.add(functionSummary(function));
        }
        result.put("callers", callers);
        result.put("callees", callees);

        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) {
                throw new IllegalStateException("native decompiler cannot open program: " + decompiler.getLastMessage());
            }
            DecompileResults decompiled = decompiler.decompileFunction(selected, 30, monitor);
            result.put("decompile_completed", decompiled.decompileCompleted());
            result.put("decompiler_error", decompiled.getErrorMessage());
            if (decompiled.getDecompiledFunction() != null) {
                result.put("decompiled_c", decompiled.getDecompiledFunction().getC());
                result.put("decompiled_fidelity", "decompiled_approx");
            }
        } finally {
            decompiler.dispose();
        }

        Path output = Path.of(getScriptArgs()[0]);
        Files.writeString(output,
                new GsonBuilder().setPrettyPrinting().create().toJson(result),
                StandardOpenOption.CREATE_NEW);
        println("REA_NATIVE_HEADLESS_EXPORT " + output);
        if (!Boolean.TRUE.equals(result.get("decompile_completed"))
                || !result.containsKey("decompiled_c") || instructions.isEmpty()) {
            throw new IllegalStateException("native decompilation incomplete");
        }
    }
}
