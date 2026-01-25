package com.beanvulnerable.aeg.domain;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

// ============================================
// ControlFlowGraph: Represents method CFG
// ============================================
public class ControlFlowGraph {
    private final String methodName;
    private final String methodDescriptor;
    private final Set<BasicBlock> basicBlocks;
    private final Map<BasicBlock, List<BasicBlock>> successors;
    private final Map<BasicBlock, List<BasicBlock>> predecessors;
    private BasicBlock entryBlock;
    private final Set<BasicBlock> exitBlocks;

    public ControlFlowGraph(String methodName, String methodDescriptor) {
        this.methodName = methodName;
        this.methodDescriptor = methodDescriptor;
        this.basicBlocks = new LinkedHashSet<>();
        this.successors = new HashMap<>();
        this.predecessors = new HashMap<>();
        this.exitBlocks = new HashSet<>();
    }

    public void addBasicBlock(BasicBlock block) {
        if (block == null) {
            return;
        }
        basicBlocks.add(block);
        successors.putIfAbsent(block, new ArrayList<>());
        predecessors.putIfAbsent(block, new ArrayList<>());
    }

    public void addEdge(BasicBlock from, BasicBlock to, String edgeType) {
        if (from == null || to == null) {
            return;
        }
        successors.computeIfAbsent(from, ignored -> new ArrayList<>()).add(to);
        predecessors.computeIfAbsent(to, ignored -> new ArrayList<>()).add(from);
    }

    public void setEntryBlock(BasicBlock entryBlock) {
        this.entryBlock = entryBlock;
    }

    public void addExitBlock(BasicBlock exitBlock) {
        if (exitBlock != null) {
            exitBlocks.add(exitBlock);
        }
    }

    public BasicBlock getEntryBlock() {
        return entryBlock;
    }

    public Set<BasicBlock> getExitBlocks() {
        return exitBlocks;
    }

    public List<BasicBlock> getSuccessors(BasicBlock block) {
        return successors.getOrDefault(block, Collections.emptyList());
    }

    public List<BasicBlock> getPredecessors(BasicBlock block) {
        return predecessors.getOrDefault(block, Collections.emptyList());
    }

    public Set<BasicBlock> getBasicBlocks() {
        return basicBlocks;
    }

    public String getMethodName() {
        return methodName;
    }

    public String getMethodDescriptor() {
        return methodDescriptor;
    }
}
