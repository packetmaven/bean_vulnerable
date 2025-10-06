import io.shiftleft.codepropertygraph.generated._
import io.joern.console._
import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.shiftleft.semanticcpg.language.dotextension._
import java.nio.file.{Files,Paths}

val sourceFile = sys.env.getOrElse("SOURCE_FILE", "")
val outputDir = sys.env.getOrElse("OUTPUT_DIR", ".")

println(s"Source: $sourceFile")
println(s"Output: $outputDir")

val cpg = importCode(sourceFile)
val methods = cpg.method.internal.l
println(s"Found ${methods.size} internal methods")

if (methods.nonEmpty) {
  val m = methods.head
  println(s"Processing: ${m.name}")
  
  // PDG
  val pdg = m.dotPdg.l
  if (pdg.nonEmpty) {
    Files.write(Paths.get(s"$outputDir/pdg_slice.dot"), pdg.head.getBytes("UTF-8"))
    println("✅ PDG written")
  } else {
    println("⚠️  PDG empty")
  }
  
  // CFG
  val cfg = m.dotCfg.l
  if (cfg.nonEmpty) {
    Files.write(Paths.get(s"$outputDir/cfg_slice.dot"), cfg.head.getBytes("UTF-8"))
    println("✅ CFG written")
  } else {
    println("⚠️  CFG empty")
  }
  
  // DFG
  val dfg = m.dotCpg14.l
  if (dfg.nonEmpty) {
    Files.write(Paths.get(s"$outputDir/dfg_slice1.dot"), dfg.head.getBytes("UTF-8"))
    println("✅ DFG written")
  } else {
    println("⚠️  DFG empty")
  }
}

println("Done")

