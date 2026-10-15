// @category REA.Static
import ghidra.app.script.GhidraScript;
import ghidra.framework.Platform;
public class ReaPlatformProbe extends GhidraScript {
  public void run() throws Exception {
    println("REA_PLATFORM="+Platform.CURRENT_PLATFORM);
    println("REA_OSDIR="+Platform.CURRENT_PLATFORM.getDirectoryName());
    println("REA_JAVA_OS="+System.getProperty("os.name")+"/"+System.getProperty("os.arch"));
  }
}
