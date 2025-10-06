#!/bin/bash
# Script to generate CFG, DFG, and PDG graphs for a Java file

if [ $# -lt 2 ]; then
    echo "Usage: $0 <java_file> <output_dir>"
    echo "Example: $0 test.java report/"
    exit 1
fi

JAVA_FILE="$1"
OUTPUT_DIR="$2"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Create Joern script
cat > /tmp/joern_graphs.sc << 'EOF'
import io.shiftleft.codepropertygraph.generated._
import io.joern.console._
import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import io.shiftleft.semanticcpg.language.dotextension._
import java.nio.file.{Files,Paths}

val file="__JAVA_FILE__"
val outDir="__OUTPUT_DIR__"

val cpg = importCode(file)
val methods = cpg.method.filterNot(_.isExternal).take(3)

println(s"Found ${methods.size} methods")

// Generate PDG for each method
var idx = 0
methods.foreach { m =>
  println(s"Generating graphs for method: ${m.name}")
  
  // PDG
  val pdgDots = m.dotPdg.l
  if (pdgDots.nonEmpty) {
    val pdgFile = s"${outDir}/pdg_slice${if(idx > 0) idx else ""}.dot"
    Files.write(Paths.get(pdgFile), pdgDots.head.getBytes("UTF-8"))
    println(s"  PDG written: $pdgFile")
  }
  
  // CFG
  val cfgDots = m.dotCfg.l
  if (cfgDots.nonEmpty) {
    val cfgFile = s"${outDir}/cfg_slice${if(idx > 0) idx else ""}.dot"
    Files.write(Paths.get(cfgFile), cfgDots.head.getBytes("UTF-8"))
    println(s"  CFG written: $cfgFile")
  }
  
  // DFG (using CPG)
  val dfgDots = m.dotCpg14.l
  if (dfgDots.nonEmpty) {
    val dfgFile = s"${outDir}/dfg_slice${if(idx > 0) idx+1 else 1}.dot"
    Files.write(Paths.get(dfgFile), dfgDots.head.getBytes("UTF-8"))
    println(s"  DFG written: $dfgFile")
  }
  
  idx += 1
}

println("Graph generation complete!")
EOF

# Replace placeholders
sed -i '' "s|__JAVA_FILE__|$JAVA_FILE|g" /tmp/joern_graphs.sc
sed -i '' "s|__OUTPUT_DIR__|$OUTPUT_DIR|g" /tmp/joern_graphs.sc

# Run Joern
echo "🎨 Generating graphs with Joern..."
/usr/local/bin/joern --script /tmp/joern_graphs.sc

# Convert DOT files to PNG and SVG
echo "🖼️  Converting DOT files to PNG/SVG..."
for dot_file in "$OUTPUT_DIR"/*.dot; do
    if [ -f "$dot_file" ]; then
        base="${dot_file%.dot}"
        echo "  Converting $(basename $dot_file)..."
        dot -Tpng "$dot_file" -o "${base}.png" 2>/dev/null || /opt/homebrew/bin/dot -Tpng "$dot_file" -o "${base}.png" 2>/dev/null
        dot -Tsvg "$dot_file" -o "${base}.svg" 2>/dev/null || /opt/homebrew/bin/dot -Tsvg "$dot_file" -o "${base}.svg" 2>/dev/null
    fi
done

echo "✅ Graph generation complete!"
echo "📁 Output directory: $OUTPUT_DIR"
ls -lh "$OUTPUT_DIR"/*.{png,svg,dot} 2>/dev/null | tail -20

