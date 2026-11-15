import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
public class FunctionCensus extends GhidraScript {
 public void run() throws Exception {
  List<String> rows = new ArrayList<>();
  Iterator<Function> it=currentProgram.getFunctionManager().getFunctions(true);
  while(it.hasNext()) { Function f=it.next(); if(!f.isExternal()) rows.add(f.getEntryPoint().toString()+"\t"+f.getName(true)+"\t"+f.isThunk()); }
  Files.write(Paths.get(getScriptArgs()[0]), rows, StandardCharsets.UTF_8);
  println("CENSUS internal_functions="+rows.size());
 }
}
