// BulkDecompile.java
// @category LegacyPE
// @menupath Tools.LegacyPE.Bulk Decompile
//
// Runs from analyzeHeadless -process after normal auto-analysis has completed.
// Arguments: <output_dir> <timeout_seconds_per_function> <max_new_functions_0_is_all> <skip|retry-errors|force>
// Outputs one JSON record per known internal function, safely resumable.
// No proprietary output belongs in a public Git repository.

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.Iterator;
import java.util.Locale;

public class BulkDecompile extends GhidraScript {
    private static String jsonString(String value) {
        if (value == null) return "null";
        StringBuilder b = new StringBuilder(value.length() + 16);
        b.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        b.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
            }
        }
        b.append('"');
        return b.toString();
    }

    private static String hashPrefix(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] bytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        return String.format(Locale.ROOT, "%02x", bytes[0] & 0xff);
    }

    private static String safeFileName(String input) {
        return input.replaceAll("[^a-zA-Z0-9_.-]", "_");
    }

    private static void atomicWrite(Path target, String contents) throws IOException {
        Files.createDirectories(target.getParent());
        Path temp = Files.createTempFile(target.getParent(), ".tmp-", ".json");
        try {
            Files.write(temp, contents.getBytes(StandardCharsets.UTF_8));
            try {
                Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE,
                           StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException ex) {
                Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    private static boolean shouldSkip(Path file, String mode) throws IOException {
        if (!Files.exists(file)) return false;
        if ("skip".equals(mode)) return true;
        if ("force".equals(mode)) return false;
        // Keep successful results, retry only timeout/error records.
        String data = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
        return data.contains("\"status\":\"ok\"");
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException(
                "BulkDecompile.java <output_dir> [timeout_seconds=30] [max_new=0] [skip|retry-errors|force]");
        }
        Path output = Paths.get(args[0]).toAbsolutePath().normalize();
        int timeoutSeconds = args.length >= 2 ? Integer.parseInt(args[1]) : 30;
        int maxNew = args.length >= 3 ? Integer.parseInt(args[2]) : 0;
        String mode = args.length >= 4 ? args[3] : "skip";
        if (timeoutSeconds < 1 || maxNew < 0 ||
            !("skip".equals(mode) || "retry-errors".equals(mode) || "force".equals(mode))) {
            throw new IllegalArgumentException("Invalid timeout/maxNew/mode");
        }
        if (currentProgram == null) throw new IllegalStateException("No current Ghidra program");
        Files.createDirectories(output);
        println("[MCPE-RE] Starting; program=" + currentProgram.getName() +
                " output=" + output + " mode=" + mode);

        DecompInterface ifc = new DecompInterface();
        ifc.setOptions(new DecompileOptions());
        ifc.toggleCCode(true);
        ifc.toggleSyntaxTree(false);  // avoid extra memory for pcode trees
        if (!ifc.openProgram(currentProgram)) {
            throw new IllegalStateException("Ghidra decompiler could not open program: " + ifc.getLastMessage());
        }

        long visited = 0, attempted = 0, skipped = 0, ok = 0, failed = 0;
        long started = System.currentTimeMillis();
        try {
            Iterator<Function> functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext()) {
                if (monitor.isCancelled()) break;
                Function fn = functions.next();
                if (fn.isExternal()) continue;
                visited++;
                String address = fn.getEntryPoint().toString();
                String hash = hashPrefix(address);
                Path target = output.resolve(hash).resolve(safeFileName(address) + ".json");
                if (shouldSkip(target, mode)) {
                    skipped++;
                    continue;
                }
                if (maxNew > 0 && attempted >= maxNew) break;
                attempted++;

                String status = "error";
                String error = "";
                String code = "";
                long start = System.currentTimeMillis();
                try {
                    DecompileResults result = ifc.decompileFunction(fn, timeoutSeconds, monitor);
                    if (result != null && result.decompileCompleted() &&
                        result.getDecompiledFunction() != null) {
                        code = result.getDecompiledFunction().getC();
                        status = "ok";
                    } else {
                        error = result == null ? "Ghidra returned null" : result.getErrorMessage();
                        if (error == null) error = "Decompiler returned no code";
                        if (error.toLowerCase(Locale.ROOT).contains("timed out") ||
                            error.toLowerCase(Locale.ROOT).contains("timeout")) {
                            status = "timeout";
                        }
                    }
                } catch (Exception e) {
                    error = e.toString();
                }
                long elapsedMs = System.currentTimeMillis() - start;

                StringBuilder json = new StringBuilder(Math.max(512, code.length() + 384));
                json.append("{");
                json.append("\"address\":").append(jsonString(address)).append(",");
                json.append("\"name\":").append(jsonString(fn.getName())).append(",");
                json.append("\"full_name\":").append(jsonString(fn.getName(true))).append(",");
                json.append("\"signature\":").append(jsonString(fn.getSignature().toString())).append(",");
                json.append("\"bytes_in_body\":").append(fn.getBody().getNumAddresses()).append(",");
                json.append("\"is_thunk\":").append(fn.isThunk()).append(",");
                json.append("\"status\":").append(jsonString(status)).append(",");
                json.append("\"error\":").append(jsonString(error)).append(",");
                json.append("\"elapsed_ms\":").append(elapsedMs).append(",");
                json.append("\"pseudocode\":").append(jsonString(code));
                json.append("}\n");
                atomicWrite(target, json.toString());
                if ("ok".equals(status)) ok++; else failed++;
                if ((attempted % 100) == 0) {
                    println("[MCPE-RE] visited=" + visited + " new=" + attempted +
                            " ok=" + ok + " failed=" + failed + " skipped=" + skipped);
                }
            }
        } finally {
            ifc.dispose();
        }
        long elapsed = System.currentTimeMillis() - started;
        println("[MCPE-RE] FINISHED visited=" + visited + " new=" + attempted +
                " ok=" + ok + " failed=" + failed + " skipped=" + skipped +
                " elapsedMs=" + elapsed);
    }
}
