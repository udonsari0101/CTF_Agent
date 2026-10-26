// Decompile every discovered function into a UTF-8 file in the job scratch.
// @category CTF
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import java.io.BufferedWriter;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

public class DecompileAll extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        File output = args.length > 0 ? new File(args[0]) : new File("tmp/decompiled.c");
        File parent = output.getAbsoluteFile().getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()) {
            throw new IllegalStateException("Cannot create output directory: " + parent);
        }
        int count = 0;
        DecompInterface decompiler = new DecompInterface();
        try (BufferedWriter writer = Files.newBufferedWriter(output.toPath(), StandardCharsets.UTF_8)) {
            if (!decompiler.openProgram(currentProgram)) {
                throw new IllegalStateException(decompiler.getLastMessage());
            }
            for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
                monitor.checkCancelled();
                if (function.isExternal()) {
                    continue;
                }
                DecompileResults result = decompiler.decompileFunction(function, 30, monitor);
                if (!result.decompileCompleted() || result.getDecompiledFunction() == null) {
                    continue;
                }
                writer.write("/* " + function.getName() + " @ " + function.getEntryPoint() + " */\n");
                writer.write(result.getDecompiledFunction().getC());
                writer.write("\n\n");
                count++;
            }
        } finally {
            decompiler.dispose();
        }
        println("Decompiled " + count + " functions to " + output.getAbsolutePath());
    }
}
