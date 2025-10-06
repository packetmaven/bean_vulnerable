// Joern script to generate CFG, DFG, and PDG graphs
// Usage: joern --script generate_joern_graphs.sc

import io.shiftleft.codepropertygraph.generated._
import io.joern.console._
import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.shiftleft.semanticcpg.language.dotextension._
import java.nio.file.{Files,Paths}

// Get arguments from environment or use defaults
val sourceFile = sys.env.getOrElse("SOURCE_FILE", "")
val outputDir = sys.env.getOrElse("OUTPUT_DIR", ".")

if (sourceFile.isEmpty) {
  println("ERROR: SOURCE_FILE environment variable not set")
  sys.exit(1)
}

println(s"Analyzing: $sourceFile")
println(s"Output directory: $outputDir")

// Import code
val cpg = importCode(sourceFile)

// Get non-external methods (up to 3)
val methods = cpg.method.internal.take(3)
println(s"Methods found: ${methods.size}")

if (methods.size == 0) {
  println("WARNING: No internal methods found")
  sys.exit(0)
}

// Generate PDG for each method
methods.zipWithIndex.foreach { case (m, idx) =>
  println(s"\nProcessing method ${idx + 1}: ${m.name}")
  
  // PDG (Program Dependence Graph)
  val pdgDots = m.dotPdg.l
  println(s"  PDG list size: ${pdgDots.size}")
  if (pdgDots.nonEmpty) {
    val pdgFile = s"$outputDir/pdg_slice${if(idx > 0) idx else ""}.dot"
    Files.write(Paths.get(pdgFile), pdgDots.head.getBytes("UTF-8"))
    println(s"  ✅ PDG written: $pdgFile")
  }
  
  // CFG (Control Flow Graph)
  val cfgDots = m.dotCfg.l
  println(s"  CFG list size: ${cfgDots.size}")
  if (cfgDots.nonEmpty) {
    val cfgFile = s"$outputDir/cfg_slice${if(idx > 0) idx else ""}.dot"
    Files.write(Paths.get(cfgFile), cfgDots.head.getBytes("UTF-8"))
    println(s"  ✅ CFG written: $cfgFile")
  }
  
  // DFG (Data Flow Graph) using dotCpg14
  val dfgDots = m.dotCpg14.l
  println(s"  DFG list size: ${dfgDots.size}")
  if (dfgDots.nonEmpty) {
    val dfgFile = s"$outputDir/dfg_slice${if(idx > 0) idx+1 else 1}.dot"
    Files.write(Paths.get(dfgFile), dfgDots.head.getBytes("UTF-8"))
    println(s"  ✅ DFG written: $dfgFile")
  }
}

println("\n✅ Graph generation complete!")

