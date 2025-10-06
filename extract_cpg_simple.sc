/**
 * Simple CPG Structure Extraction for Spatial GNN
 * Extracts real graph structure from Joern CPG
 */

import $ivy.`com.lihaoyi::ujson:1.4.0`
import java.io.PrintWriter
import java.nio.file.{Files, Paths}

@main def exec(cpgFile: String, outputDir: String) = {
    loadCpg(cpgFile)
    
    val outputPath = Paths.get(outputDir)
    Files.createDirectories(outputPath)
    
    // Get all nodes
    val allNodes = cpg.all.l
    val nodeMap = allNodes.zipWithIndex.toMap
    
    // Extract nodes
    val nodes = allNodes.zipWithIndex.map { case (node, idx) =>
        ujson.Obj(
            "id" -> idx,
            "label" -> node.label,
            "code" -> node.propertyOption[String]("CODE").getOrElse(""),
            "name" -> node.propertyOption[String]("NAME").getOrElse(""),
            "line" -> node.propertyOption[Int]("LINE_NUMBER").getOrElse(0),
            "order" -> node.propertyOption[Int]("ORDER").getOrElse(0)
        )
    }
    
    // Extract AST edges
    val astEdges = allNodes.flatMap { node =>
        val sourceIdx = nodeMap(node)
        node.astChildren.flatMap { child =>
            nodeMap.get(child).map { targetIdx =>
                ujson.Obj(
                    "source" -> sourceIdx,
                    "target" -> targetIdx,
                    "type" -> "AST",
                    "type_id" -> 0
                )
            }
        }
    }
    
    // Extract CFG edges
    val cfgEdges = cpg.method.flatMap { method =>
        method.cfgNode.flatMap { node =>
            nodeMap.get(node).flatMap { sourceIdx =>
                node.cfgNext.flatMap { next =>
                    nodeMap.get(next).map { targetIdx =>
                        ujson.Obj(
                            "source" -> sourceIdx,
                            "target" -> targetIdx,
                            "type" -> "CFG",
                            "type_id" -> 1
                        )
                    }
                }
            }
        }
    }.l
    
    // Extract call graph edges
    val callEdges = cpg.call.flatMap { call =>
        nodeMap.get(call).flatMap { sourceIdx =>
            call.callee.headOption.flatMap { callee =>
                nodeMap.get(callee).map { targetIdx =>
                    ujson.Obj(
                        "source" -> sourceIdx,
                        "target" -> targetIdx,
                        "type" -> "CALL",
                        "type_id" -> 2
                    )
                }
            }
        }
    }.l
    
    val allEdges = astEdges ++ cfgEdges ++ callEdges
    
    // Build output
    val output = ujson.Obj(
        "nodes" -> nodes,
        "edges" -> allEdges,
        "stats" -> ujson.Obj(
            "num_nodes" -> nodes.size,
            "num_edges" -> allEdges.size,
            "num_ast_edges" -> astEdges.size,
            "num_cfg_edges" -> cfgEdges.size,
            "num_call_edges" -> callEdges.size
        )
    )
    
    // Write to file
    val outputFile = outputPath.resolve("cpg_structure.json").toFile
    val writer = new PrintWriter(outputFile)
    try {
        writer.write(ujson.write(output, indent = 2))
        println(s"✅ Extracted CPG structure:")
        println(s"   Nodes: ${nodes.size}")
        println(s"   Edges: ${allEdges.size} (AST: ${astEdges.size}, CFG: ${cfgEdges.size}, CALL: ${callEdges.size})")
        println(s"   Output: ${outputFile.getAbsolutePath}")
    } finally {
        writer.close()
    }
}

