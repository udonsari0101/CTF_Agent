// Decompile one named function or entry address into the job scratch.
// @category CTF
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

public class DecompileFn extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length == 0 || args[0].isBlank()) {
            throw new IllegalArgumentException("Usage: -postScript DecompileFn.java <function-name-or-address> [output-path]");
        }
        Function target = null;
        for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
            if (function.getName().equals(args[0]) || function.getEntryPoint().toString().equalsIgnoreCase(args[0])) {
                target = function;
                break;
            }
        }
        if (target == null) {
            throw new IllegalArgumentException("Function not found: " + args[0]);
        }
        String safeName = args[0].replaceAll("[^A-Za-z0-9_.-]", "_");
        File output = args.length > 1 ? new File(args[1]) : new File("tmp/ghidra-" + safeName + ".c");
        File parent = output.getAbsoluteFile().getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new IllegalStateException("Cannot create output directory: " + parent);
        }
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) {
                throw new IllegalStateException(decompiler.getLastMessage());
            }
            DecompileResults result = decompiler.decompileFunction(target, 60, monitor);
            if (!result.decompileCompleted() || result.getDecompiledFunction() == null) {
                throw new IllegalStateException("Decompilation failed: " + result.getErrorMessage());
            }
            Files.writeString(output.toPath(), result.getDecompiledFunction().getC(), StandardCharsets.UTF_8);
        } finally {
            decompiler.dispose();
        }
        println("Decompiled " + target.getName() + " to " + output.getAbsolutePath());
    }
}
