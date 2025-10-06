/**
 * Extract Complete CPG Structure for Spatial GNN (Joern v2 API)
 * 
 * Outputs:
 * - Nodes with types, properties, and semantic features
 * - Edges with explicit types (AST, CFG, DFG, PDG, CDG)
 * - Taint information per node
 * - Method and call information
 * 
 * Research Foundation:
 * - Devign (NeurIPS 2019): Node types + edge types for heterogeneous GNNs
 * - IVDetect (ASE 2021): Multi-relational graph structure
 * - LineVul (MSR 2022): Statement-level features with control/data flow
 */

import java.io.PrintWriter
import java.nio.file.{Files, Paths}

@main def exec(cpgFile: String, outputDir: String) = {
    val outputPath = Paths.get(outputDir)
    Files.createDirectories(outputPath)
    
    // Check if cpgFile is a .java source file or an existing CPG
    val cpgFilePath = Paths.get(cpgFile)
    if (cpgFile.endsWith(".java")) {
        // Generate CPG from Java source
        println(s"Generating CPG from Java source: $cpgFile")
        importCode(cpgFile)
    } else {
        // Load existing CPG
        println(s"Loading existing CPG: $cpgFile")
        loadCpg(cpgFile)
    }
    
    // Get all nodes and create index mapping
    val allNodes = cpg.all.l
    val nodeToIdx = allNodes.zipWithIndex.toMap
    
    println(s"Processing ${allNodes.size} nodes...")
    
    // Extract nodes with semantic features
    val nodesJson = allNodes.zipWithIndex.map { case (node, idx) =>
        val nodeType = node.label
        val code = node.propertyOption[String]("CODE").getOrElse("")
        val name = node.propertyOption[String]("NAME").getOrElse("")
        val lineNumber = node.propertyOption[Int]("LINE_NUMBER").getOrElse(0)
        val columnNumber = node.propertyOption[Int]("COLUMN_NUMBER").getOrElse(0)
        val order = node.propertyOption[Int]("ORDER").getOrElse(0)
        
        // Determine node category for GNN features
        val category = nodeType match {
            case "METHOD" => "method"
            case "METHOD_PARAMETER_IN" => "parameter"
            case "METHOD_PARAMETER_OUT" => "parameter"
            case "METHOD_RETURN" => "return"
            case "CALL" => "call"
            case "IDENTIFIER" => "identifier"
            case "LITERAL" => "literal"
            case "LOCAL" => "local"
            case "BLOCK" => "block"
            case "CONTROL_STRUCTURE" => "control"
            case "RETURN" => "return"
            case "FIELD_IDENTIFIER" => "field"
            case "TYPE" => "type"
            case "TYPE_DECL" => "type_decl"
            case "MEMBER" => "member"
            case "NAMESPACE_BLOCK" => "namespace"
            case "FILE" => "file"
            case "UNKNOWN" => "unknown"
            case _ => "other"
        }
        
        // Extract method information if applicable
        val methodName = node.propertyOption[String]("METHOD_FULL_NAME").getOrElse("")
        val signature = node.propertyOption[String]("SIGNATURE").getOrElse("")
        
        // Check if node is in a security-sensitive context
        val isSink = nodeType == "CALL" && (
            code.contains("exec") || 
            code.contains("Runtime") ||
            code.contains("ProcessBuilder") ||
            code.contains("executeQuery") ||
            code.contains("executeUpdate") ||
            code.contains("createQuery") ||
            code.contains("getConnection")
        )
        
        val isSource = nodeType == "METHOD_PARAMETER_IN" || 
                      (nodeType == "CALL" && (
                          code.contains("getParameter") ||
                          code.contains("getHeader") ||
                          code.contains("getCookie") ||
                          code.contains("readLine") ||
                          code.contains("nextLine")
                      ))
        
        s"""{"id":$idx,"node_type":"$nodeType","category":"$category","code":"${escapeJson(code)}","name":"${escapeJson(name)}","line":$lineNumber,"column":$columnNumber,"order":$order,"method_name":"${escapeJson(methodName)}","signature":"${escapeJson(signature)}","is_source":$isSource,"is_sink":$isSink}"""
    }
    
    println("Extracting AST edges...")
    // Extract AST edges using Joern v2 API
    val astEdges = allNodes.flatMap { node =>
        val sourceIdx = nodeToIdx(node)
        // Use _astOut for outgoing AST edges in Joern v2
        node._astOut.flatMap { child =>
            nodeToIdx.get(child).map { targetIdx =>
                s"""{"source":$sourceIdx,"target":$targetIdx,"edge_type":"AST","edge_type_id":0}"""
            }
        }
    }
    
    println("Extracting CFG edges...")
    // Extract CFG edges
    val cfgEdges = cpg.method.flatMap { method =>
        method.cfgNode.flatMap { node =>
            nodeToIdx.get(node).toSeq.flatMap { sourceIdx =>
                // Use _cfgOut for outgoing CFG edges in Joern v2
                node._cfgOut.flatMap { next =>
                    nodeToIdx.get(next).map { targetIdx =>
                        s"""{"source":$sourceIdx,"target":$targetIdx,"edge_type":"CFG","edge_type_id":1}"""
                    }
                }
            }
        }
    }.l
    
    println("Extracting DFG edges...")
    // Extract DFG edges (data dependencies via REF edges)
    val dfgEdges = allNodes.flatMap { node =>
        nodeToIdx.get(node).toSeq.flatMap { sourceIdx =>
            // Get outgoing REF edges which represent data flow
            node._refOut.flatMap { target =>
                nodeToIdx.get(target).map { targetIdx =>
                    s"""{"source":$sourceIdx,"target":$targetIdx,"edge_type":"DFG","edge_type_id":2}"""
                }
            }
        }
    }
    
    println("Extracting CDG edges...")
    // Extract CDG edges (control dependencies)
    val cdgEdges = cpg.method.flatMap { method =>
        method.controlStructure.flatMap { ctrl =>
            nodeToIdx.get(ctrl).toSeq.flatMap { sourceIdx =>
                // Get all nodes under this control structure
                ctrl._astOut.l.flatMap { child =>
                    def getAllDescendants(n: io.shiftleft.codepropertygraph.generated.nodes.StoredNode): List[io.shiftleft.codepropertygraph.generated.nodes.StoredNode] = {
                        val children = n._astOut.l
                        n :: children.flatMap(getAllDescendants)
                    }
                    
                    getAllDescendants(child).flatMap { desc =>
                        nodeToIdx.get(desc).map { targetIdx =>
                            s"""{"source":$sourceIdx,"target":$targetIdx,"edge_type":"CDG","edge_type_id":3}"""
                        }
                    }
                }
            }
        }
    }.l
    
    println("Extracting CALL edges...")
    // Extract call edges
    val callEdges = cpg.call.flatMap { call =>
        nodeToIdx.get(call).toSeq.flatMap { sourceIdx =>
            call.callee.headOption.flatMap { callee =>
                nodeToIdx.get(callee).map { targetIdx =>
                    s"""{"source":$sourceIdx,"target":$targetIdx,"edge_type":"CALL","edge_type_id":4}"""
                }
            }
        }
    }.l
    
    val allEdges = astEdges ++ cfgEdges ++ dfgEdges ++ cdgEdges ++ callEdges
    
    println("Extracting method information...")
    // Extract method statistics
    val methodsJson = cpg.method.filterNot(_.isExternal).map { method =>
        // Check modifiers properly
        val modifiers = method.modifier.map(_.modifierType).l
        val isPublic = modifiers.contains("PUBLIC")
        val isStatic = modifiers.contains("STATIC")
        val isPrivate = modifiers.contains("PRIVATE")
        val isProtected = modifiers.contains("PROTECTED")
        
        s"""{"name":"${escapeJson(method.name)}","full_name":"${escapeJson(method.fullName)}","signature":"${escapeJson(method.signature)}","line_number":${method.lineNumber.getOrElse(0)},"num_parameters":${method.parameter.size},"num_locals":${method.local.size},"num_calls":${method.call.size},"cyclomatic_complexity":${method.controlStructure.size},"is_public":$isPublic,"is_static":$isStatic,"is_private":$isPrivate,"is_protected":$isProtected}"""
    }.l
    
    // Build final JSON structure manually
    val output = new StringBuilder()
    output.append("{\n")
    output.append(s"""  "nodes": [${nodesJson.mkString(",\n    ")}],\n""")
    output.append(s"""  "edges": [${allEdges.mkString(",\n    ")}],\n""")
    output.append(s"""  "methods": [${methodsJson.mkString(",\n    ")}],\n""")
    output.append(s"""  "statistics": {\n""")
    output.append(s"""    "num_nodes": ${nodesJson.size},\n""")
    output.append(s"""    "num_edges": ${allEdges.size},\n""")
    output.append(s"""    "num_ast_edges": ${astEdges.size},\n""")
    output.append(s"""    "num_cfg_edges": ${cfgEdges.size},\n""")
    output.append(s"""    "num_dfg_edges": ${dfgEdges.size},\n""")
    output.append(s"""    "num_cdg_edges": ${cdgEdges.size},\n""")
    output.append(s"""    "num_call_edges": ${callEdges.size},\n""")
    output.append(s"""    "num_methods": ${methodsJson.size}\n""")
    output.append(s"""  }\n""")
    output.append("}\n")
    
    // Write to file
    val outputFile = outputPath.resolve("cpg_structure.json").toFile
    val writer = new PrintWriter(outputFile)
    try {
        writer.write(output.toString)
        println("="*60)
        println("✅ CPG Structure Extracted Successfully")
        println("="*60)
        println(s"Output File: ${outputFile.getAbsolutePath}")
        println(s"Nodes: ${nodesJson.size}")
        println(s"Edges: ${allEdges.size}")
        println(s"  - AST: ${astEdges.size}")
        println(s"  - CFG: ${cfgEdges.size}")
        println(s"  - DFG: ${dfgEdges.size}")
        println(s"  - CDG: ${cdgEdges.size}")
        println(s"  - CALL: ${callEdges.size}")
        println(s"Methods: ${methodsJson.size}")
        println("="*60)
    } finally {
        writer.close()
    }
}

// Helper function to escape JSON strings
def escapeJson(s: String): String = {
    s.replace("\\", "\\\\")
     .replace("\"", "\\\"")
     .replace("\n", "\\n")
     .replace("\r", "\\r")
     .replace("\t", "\\t")
     .take(500) // Limit length to prevent huge JSON
}
