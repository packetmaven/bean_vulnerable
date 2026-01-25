// Comprehensive Joern graph export (CFG, DFG, PDG) per method
// Usage: joern --script comprehensive_graphs.sc

import io.shiftleft.codepropertygraph.generated._
import io.joern.console._
import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.shiftleft.semanticcpg.language.dotextension._
import java.nio.file.{Files,Paths}

val sourceFile = sys.env.getOrElse("SOURCE_FILE", "")
val outputDir = sys.env.getOrElse("OUTPUT_DIR", ".")

if (sourceFile.isEmpty) {
  println("ERROR: SOURCE_FILE environment variable not set")
  sys.exit(1)
}

println(s"Analyzing: $sourceFile")
println(s"Output directory: $outputDir")

val cpg = importCode(sourceFile)
val methods = cpg.method.internal.l
println(s"Methods found: ${methods.size}")

def safeName(name: String, idx: Int): String = {
  val cleaned = name.replaceAll("[^A-Za-z0-9_]+", "_")
  s"${idx + 1}_${cleaned}"
}

methods.zipWithIndex.foreach { case (m, idx) =>
  val base = safeName(m.name, idx)
  println(s"\nProcessing method ${idx + 1}: ${m.name}")

  val pdgDots = m.dotPdg.l
  if (pdgDots.nonEmpty) {
    val pdgFile = s"$outputDir/pdg_${base}.dot"
    Files.write(Paths.get(pdgFile), pdgDots.head.getBytes("UTF-8"))
    println(s"  ✅ PDG written: $pdgFile")
  } else {
    println("  ⚠️  PDG empty")
  }

  val cfgDots = m.dotCfg.l
  if (cfgDots.nonEmpty) {
    val cfgFile = s"$outputDir/cfg_${base}.dot"
    Files.write(Paths.get(cfgFile), cfgDots.head.getBytes("UTF-8"))
    println(s"  ✅ CFG written: $cfgFile")
  } else {
    println("  ⚠️  CFG empty")
  }

  val dfgDots = m.dotCpg14.l
  if (dfgDots.nonEmpty) {
    val dfgFile = s"$outputDir/dfg_${base}.dot"
    Files.write(Paths.get(dfgFile), dfgDots.head.getBytes("UTF-8"))
    println(s"  ✅ DFG written: $dfgFile")
  } else {
    println("  ⚠️  DFG empty")
  }
}

def escapeJson(value: String): String = {
  value
    .replace("\\", "\\\\")
    .replace("\"", "\\\"")
    .replace("\n", "\\n")
    .replace("\r", "\\r")
    .replace("\t", "\\t")
}

val indexEntries = methods.zipWithIndex.map { case (m, idx) =>
  val base = safeName(m.name, idx)
  val startLine = m.lineNumber.getOrElse(-1)
  val endLine = m.lineNumberEnd.getOrElse(-1)
  val methodName = escapeJson(m.name)
  s"""{"index":${idx + 1},"base":"${base}","method":"${methodName}","start_line":${startLine},"end_line":${endLine}}"""
}
val indexJson = "[" + indexEntries.mkString(",") + "]"
Files.write(Paths.get(s"$outputDir/graph_index.json"), indexJson.getBytes("UTF-8"))
println(s"\n✅ Graph index written: $outputDir/graph_index.json")

println("\n✅ Comprehensive graph generation complete!")
