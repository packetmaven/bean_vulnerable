package com.beanvulnerable.aeg;

import com.beanvulnerable.aeg.domain.BasicBlock;
import com.beanvulnerable.aeg.domain.ClassAnalysis;
import com.beanvulnerable.aeg.domain.ControlFlowGraph;
import com.beanvulnerable.aeg.domain.DataFlowSink;
import com.beanvulnerable.aeg.domain.DataFlowSource;
import com.beanvulnerable.aeg.domain.MethodAnalysis;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Bytecode Analysis Engine
 *
 * Responsibilities:
 * - Parse .class files using ASM library
 * - Extract method control flow graphs (CFGs)
 * - Identify data flow sources (untrusted input)
 * - Identify data flow sinks (dangerous operations)
 * - Build basic block representation
 *
 * Technology: ASM 9.5 (20+ year production history)
 * Maturity: Production-grade
 */
public class BytecodeAnalyzer {

    private static final int ASM_API_VERSION = Opcodes.ASM9;
    private final Map<String, MethodInfo> methodCache;
    private final DataFlowSourceRegistry sourceRegistry;
    private final DataFlowSinkRegistry sinkRegistry;

    // ============================================
    // CONSTRUCTORS
    // ============================================

    public BytecodeAnalyzer() {
        this.methodCache = new ConcurrentHashMap<>();
        this.sourceRegistry = new DataFlowSourceRegistry();
        this.sinkRegistry = new DataFlowSinkRegistry();
        initializeSourceRegistry();
        initializeSinkRegistry();
    }

    // ============================================
    // 1. CLASS FILE PARSING
    // ============================================

    /**
     * Parse .class file into ASM ClassNode
     *
     * @param classFilePath Path to .class file
     * @return ClassNode representing parsed class
     * @throws IOException if file cannot be read
     */
    public ClassNode parseClassFile(String classFilePath) throws IOException {
        ClassReader reader = new ClassReader(new FileInputStream(classFilePath));
        ClassNode classNode = new ClassNode(ASM_API_VERSION);

        // Parse with full analysis flags
        reader.accept(classNode, ClassReader.EXPAND_FRAMES);

        return classNode;
    }

    /**
     * Parse .class file from byte array
     *
     * @param classBytes Raw .class file bytes
     * @return ClassNode
     */
    public ClassNode parseClassBytes(byte[] classBytes) {
        ClassReader reader = new ClassReader(classBytes);
        ClassNode classNode = new ClassNode(ASM_API_VERSION);
        reader.accept(classNode, ClassReader.EXPAND_FRAMES);
        return classNode;
    }

    /**
     * Parse JAR file, extract all .class files
     *
     * @param jarPath Path to JAR file
     * @return Map of class names to ClassNodes
     * @throws IOException if JAR cannot be read
     */
    public Map<String, ClassNode> parseJarFile(String jarPath) throws IOException {
        Map<String, ClassNode> classes = new HashMap<>();

        try (java.util.jar.JarFile jar = new java.util.jar.JarFile(jarPath)) {
            jar.stream()
                .filter(entry -> entry.getName().endsWith(".class"))
                .forEach(entry -> {
                    try {
                        byte[] classBytes = readAllBytes(jar.getInputStream(entry));
                        ClassNode classNode = parseClassBytes(classBytes);
                        classes.put(entry.getName().replace(".class", ""), classNode);
                    } catch (IOException e) {
                        System.err.println("Failed to parse: " + entry.getName());
                    }
                });
        }

        return classes;
    }

    private byte[] readAllBytes(java.io.InputStream inputStream) throws IOException {
        byte[] buffer = new byte[8192];
        int bytesRead;
        java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();
        try {
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                output.write(buffer, 0, bytesRead);
            }
            return output.toByteArray();
        } finally {
            inputStream.close();
        }
    }

    // ============================================
    // 2. CONTROL FLOW GRAPH (CFG) EXTRACTION
    // ============================================

    /**
     * Extract CFG from method
     */
    public ControlFlowGraph extractMethodCFG(MethodNode method) {
        ControlFlowGraph cfg = new ControlFlowGraph(method.name, method.desc);

        // Extract basic blocks
        List<BasicBlock> basicBlocks = extractBasicBlocks(method);
        basicBlocks.forEach(cfg::addBasicBlock);

        // Build edges between blocks
        buildControlFlowEdges(method, cfg, basicBlocks);

        // Identify entry and exit blocks
        if (!basicBlocks.isEmpty()) {
            cfg.setEntryBlock(basicBlocks.get(0));
        }
        identifyExitBlocks(cfg);

        return cfg;
    }

    /**
     * Extract basic blocks from method instructions
     */
    private List<BasicBlock> extractBasicBlocks(MethodNode method) {
        List<BasicBlock> blocks = new ArrayList<>();

        if (method.instructions == null || method.instructions.size() == 0) {
            return blocks;
        }

        BasicBlock currentBlock = new BasicBlock("block_0", 0);
        int blockCounter = 1;

        // Iterate through instructions
        for (int i = 0; i < method.instructions.size(); i++) {
            AbstractInsnNode insnNode = method.instructions.get(i);

            if (insnNode instanceof LabelNode && currentBlock.getInstructions().size() > 0) {
                blocks.add(currentBlock);
                currentBlock = new BasicBlock("block_" + blockCounter++, i);
            }

            currentBlock.addInstruction(insnNode);

            if (isBranchTerminator(insnNode) || isReturnTerminator(insnNode)) {
                blocks.add(currentBlock);

                if (i < method.instructions.size() - 1) {
                    currentBlock = new BasicBlock("block_" + blockCounter++, i + 1);
                }
            }
        }

        if (!blocks.contains(currentBlock) && currentBlock.getInstructions().size() > 0) {
            blocks.add(currentBlock);
        }

        return blocks;
    }

    private boolean isBranchTerminator(AbstractInsnNode insnNode) {
        int opcode = insnNode.getOpcode();
        return opcode >= Opcodes.IFEQ && opcode <= Opcodes.LOOKUPSWITCH;
    }

    private boolean isReturnTerminator(AbstractInsnNode insnNode) {
        int opcode = insnNode.getOpcode();
        return (opcode >= Opcodes.IRETURN && opcode <= Opcodes.RETURN)
            || opcode == Opcodes.ATHROW;
    }

    private void buildControlFlowEdges(MethodNode method, ControlFlowGraph cfg, List<BasicBlock> blocks) {
        if (blocks.isEmpty()) {
            return;
        }

        for (int i = 0; i < blocks.size() - 1; i++) {
            BasicBlock block = blocks.get(i);
            AbstractInsnNode lastInsn = block.getLastInstruction();

            if (lastInsn == null) {
                continue;
            }

            if (!isBranchTerminator(lastInsn) && !isReturnTerminator(lastInsn)) {
                cfg.addEdge(block, blocks.get(i + 1), "sequential");
                continue;
            }

            if (lastInsn instanceof JumpInsnNode) {
                JumpInsnNode jumpInsn = (JumpInsnNode) lastInsn;
                BasicBlock target = findBlockByLabel(blocks, jumpInsn.label);
                if (target != null) {
                    cfg.addEdge(block, target, "branch");
                }

                if (lastInsn.getOpcode() >= Opcodes.IFEQ &&
                    lastInsn.getOpcode() <= Opcodes.IF_ACMPNE &&
                    i + 1 < blocks.size()) {
                    cfg.addEdge(block, blocks.get(i + 1), "fall-through");
                }
            }

            if (lastInsn instanceof TableSwitchInsnNode) {
                TableSwitchInsnNode switchInsn = (TableSwitchInsnNode) lastInsn;
                for (LabelNode label : switchInsn.labels) {
                    BasicBlock target = findBlockByLabel(blocks, label);
                    if (target != null) {
                        cfg.addEdge(block, target, "switch");
                    }
                }
                BasicBlock defaultTarget = findBlockByLabel(blocks, switchInsn.dflt);
                if (defaultTarget != null) {
                    cfg.addEdge(block, defaultTarget, "switch-default");
                }
            }

            if (lastInsn instanceof LookupSwitchInsnNode) {
                LookupSwitchInsnNode switchInsn = (LookupSwitchInsnNode) lastInsn;
                for (LabelNode label : switchInsn.labels) {
                    BasicBlock target = findBlockByLabel(blocks, label);
                    if (target != null) {
                        cfg.addEdge(block, target, "switch");
                    }
                }
                BasicBlock defaultTarget = findBlockByLabel(blocks, switchInsn.dflt);
                if (defaultTarget != null) {
                    cfg.addEdge(block, defaultTarget, "switch-default");
                }
            }
        }
    }

    private BasicBlock findBlockByLabel(List<BasicBlock> blocks, LabelNode label) {
        if (label == null) {
            return null;
        }
        for (BasicBlock block : blocks) {
            for (AbstractInsnNode insn : block.getInstructions()) {
                if (insn == label) {
                    return block;
                }
            }
        }
        return null;
    }

    private void identifyExitBlocks(ControlFlowGraph cfg) {
        cfg.getBasicBlocks().stream()
            .filter(block -> {
                AbstractInsnNode last = block.getLastInstruction();
                return last != null && isReturnTerminator(last);
            })
            .forEach(cfg::addExitBlock);
    }

    // ============================================
    // 3. DATA FLOW SOURCE IDENTIFICATION
    // ============================================

    public Set<DataFlowSource> identifyDataFlowSources(MethodNode method) {
        Set<DataFlowSource> sources = new HashSet<>();

        Type[] argumentTypes = Type.getArgumentTypes(method.desc);
        for (int i = 0; i < argumentTypes.length; i++) {
            DataFlowSource source = new DataFlowSource(
                "param_" + i,
                argumentTypes[i].getClassName(),
                method.name,
                "method_parameter"
            );
            sources.add(source);
        }

        for (AbstractInsnNode insn : method.instructions.toArray()) {
            if (insn instanceof MethodInsnNode) {
                MethodInsnNode methodInsn = (MethodInsnNode) insn;
                if (sourceRegistry.isSource(methodInsn.owner, methodInsn.name)) {
                    DataFlowSource source = sourceRegistry.getSource(
                        methodInsn.owner, methodInsn.name
                    );
                    sources.add(source);
                }
            }
        }

        return sources;
    }

    // ============================================
    // 4. DATA FLOW SINK IDENTIFICATION
    // ============================================

    public Set<DataFlowSink> identifyDataFlowSinks(MethodNode method) {
        Set<DataFlowSink> sinks = new HashSet<>();

        for (AbstractInsnNode insn : method.instructions.toArray()) {
            if (insn instanceof MethodInsnNode) {
                MethodInsnNode methodInsn = (MethodInsnNode) insn;
                if (sinkRegistry.isSink(methodInsn.owner, methodInsn.name)) {
                    DataFlowSink sink = sinkRegistry.getSink(
                        methodInsn.owner, methodInsn.name
                    );
                    sinks.add(sink);
                } else {
                    DataFlowSink heuristic = buildHeuristicSink(methodInsn);
                    if (heuristic != null) {
                        sinks.add(heuristic);
                    }
                }
            }
        }

        return sinks;
    }

    private DataFlowSink buildHeuristicSink(MethodInsnNode methodInsn) {
        String name = methodInsn.name;
        String owner = methodInsn.owner != null ? methodInsn.owner.replace('/', '.') : "unknown";
        String sinkType = null;

        boolean isResponseWriter = owner.endsWith("PrintWriter")
            || owner.endsWith("JspWriter")
            || owner.endsWith("ServletOutputStream");

        if (("print".equals(name) || "println".equals(name) || "write".equals(name)) && isResponseWriter) {
            sinkType = "xss";
        } else if ("executeQuery".equals(name) || "executeUpdate".equals(name) || "execute".equals(name)) {
            sinkType = "sql_injection";
        } else if ("exec".equals(name)) {
            sinkType = "command_injection";
        } else if ("readObject".equals(name)) {
            sinkType = "deserialization";
        } else if ("evaluate".equals(name)) {
            sinkType = "xpath_injection";
        } else if ("search".equals(name) && (owner.contains("DirContext") || owner.contains("Ldap"))) {
            sinkType = "ldap_injection";
        } else if ("eval".equals(name) && owner.contains("EL")) {
            sinkType = "el_injection";
        } else if ("parse".equals(name)
            && (owner.contains("DocumentBuilder") || owner.contains("SAXParser") || owner.contains("XMLReader"))) {
            sinkType = "xxe";
        } else if ("sendRedirect".equals(name) || "setHeader".equals(name) || "addHeader".equals(name)) {
            sinkType = "http_response_splitting";
        } else if ("readAllBytes".equals(name) || "newInputStream".equals(name) || "newOutputStream".equals(name)) {
            sinkType = "path_traversal";
        } else if ("write".equals(name)) {
            if (owner.endsWith("Files") ||
                owner.endsWith("FileOutputStream") ||
                owner.endsWith("FileWriter")) {
                sinkType = "path_traversal";
            }
        } else if ("<init>".equals(name)) {
            if (owner.endsWith("FileInputStream") ||
                owner.endsWith("FileOutputStream") ||
                owner.endsWith("FileReader") ||
                owner.endsWith("FileWriter")) {
                sinkType = "path_traversal";
            }
        }

        if (sinkType == null) {
            return null;
        }

        String sinkId = owner + "#" + name;
        return new DataFlowSink(sinkId, owner, name, sinkType);
    }

    // ============================================
    // 5. SOURCE/SINK REGISTRY INITIALIZATION
    // ============================================

    private void initializeSourceRegistry() {
        sourceRegistry.register("java/lang/String", "<init>", "parameter_source");
        sourceRegistry.register("java/net/Socket", "getInputStream", "network_source");
        sourceRegistry.register("java/net/URLConnection", "getInputStream", "network_source");
        sourceRegistry.register("java/io/FileReader", "<init>", "file_source");
        sourceRegistry.register("java/nio/file/Files", "readAllBytes", "file_source");
    }

    private void initializeSinkRegistry() {
        sinkRegistry.register("java/sql/Statement", "execute", "sql_injection");
        sinkRegistry.register("java/sql/PreparedStatement", "setString", "sql_injection");
        sinkRegistry.register("java/lang/Runtime", "exec", "command_injection");
        sinkRegistry.register("java/io/PrintWriter", "print", "xss");
        sinkRegistry.register("java/io/PrintWriter", "println", "xss");
        sinkRegistry.register("java/io/PrintWriter", "write", "xss");
        sinkRegistry.register("javax/servlet/ServletOutputStream", "write", "xss");
        sinkRegistry.register("javax/servlet/jsp/JspWriter", "print", "xss");
        sinkRegistry.register("javax/servlet/jsp/JspWriter", "println", "xss");
        sinkRegistry.register("javax/servlet/jsp/JspWriter", "write", "xss");
        sinkRegistry.register("java/nio/file/Files", "write", "path_traversal");
        sinkRegistry.register("java/nio/file/Files", "newInputStream", "path_traversal");
        sinkRegistry.register("java/nio/file/Files", "newOutputStream", "path_traversal");
        sinkRegistry.register("java/io/FileInputStream", "<init>", "path_traversal");
        sinkRegistry.register("java/io/FileOutputStream", "<init>", "path_traversal");
        sinkRegistry.register("java/io/FileReader", "<init>", "path_traversal");
        sinkRegistry.register("java/io/FileWriter", "<init>", "path_traversal");
        sinkRegistry.register("java/lang/Class", "forName", "reflection_injection");
        sinkRegistry.register("java/lang/reflect/Method", "invoke", "reflection_injection");
        sinkRegistry.register("javax/xml/xpath/XPath", "evaluate", "xpath_injection");
        sinkRegistry.register("java/io/ObjectInputStream", "readObject", "deserialization");
        sinkRegistry.register("javax/naming/directory/DirContext", "search", "ldap_injection");
        sinkRegistry.register("javax/naming/directory/InitialDirContext", "search", "ldap_injection");
        sinkRegistry.register("javax/naming/ldap/LdapContext", "search", "ldap_injection");
        sinkRegistry.register("javax/el/ELProcessor", "eval", "el_injection");
        sinkRegistry.register("javax/el/ExpressionFactory", "createValueExpression", "el_injection");
        sinkRegistry.register("javax/el/ExpressionFactory", "createMethodExpression", "el_injection");
        sinkRegistry.register("javax/xml/parsers/DocumentBuilder", "parse", "xxe");
        sinkRegistry.register("javax/xml/parsers/SAXParser", "parse", "xxe");
        sinkRegistry.register("javax/xml/stream/XMLInputFactory", "createXMLStreamReader", "xxe");
        sinkRegistry.register("javax/xml/stream/XMLInputFactory", "createXMLEventReader", "xxe");
        sinkRegistry.register("javax/servlet/http/HttpServletResponse", "sendRedirect", "http_response_splitting");
        sinkRegistry.register("javax/servlet/http/HttpServletResponse", "addHeader", "http_response_splitting");
        sinkRegistry.register("javax/servlet/http/HttpServletResponse", "setHeader", "http_response_splitting");
    }

    // ============================================
    // 6. PUBLIC API
    // ============================================

    public ClassAnalysis analyzeClass(String classFilePath) throws IOException {
        ClassNode classNode = parseClassFile(classFilePath);
        ClassAnalysis analysis = new ClassAnalysis(classNode.name);

        for (MethodNode method : classNode.methods) {
            MethodAnalysis methodAnalysis = analyzeMethod(method);
            analysis.addMethodAnalysis(methodAnalysis);
        }

        return analysis;
    }

    public MethodAnalysis analyzeMethod(MethodNode method) {
        MethodAnalysis analysis = new MethodAnalysis(method.name, method.desc);

        ControlFlowGraph cfg = extractMethodCFG(method);
        analysis.setCfg(cfg);

        Set<DataFlowSource> sources = identifyDataFlowSources(method);
        Set<DataFlowSink> sinks = identifyDataFlowSinks(method);

        analysis.setSources(sources);
        analysis.setSinks(sinks);

        return analysis;
    }
}
