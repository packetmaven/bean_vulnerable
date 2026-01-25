package com.beanvulnerable.aeg.domain;

import org.objectweb.asm.tree.AbstractInsnNode;

import java.util.ArrayList;
import java.util.List;

// ============================================
// BasicBlock: Unit of CFG analysis
// ============================================
public class BasicBlock {
    private final String id;
    private final int startIndex;
    private final List<AbstractInsnNode> instructions;
    private final List<String> labels;

    public BasicBlock(String id, int startIndex) {
        this.id = id;
        this.startIndex = startIndex;
        this.instructions = new ArrayList<>();
        this.labels = new ArrayList<>();
    }

    public void addInstruction(AbstractInsnNode insn) {
        if (insn != null) {
            instructions.add(insn);
        }
    }

    public void addLabel(String label) {
        if (label != null && !label.isEmpty()) {
            labels.add(label);
        }
    }

    public AbstractInsnNode getLastInstruction() {
        return instructions.isEmpty() ? null : instructions.get(instructions.size() - 1);
    }

    public List<AbstractInsnNode> getInstructions() {
        return instructions;
    }

    public String getId() {
        return id;
    }

    public int getStartIndex() {
        return startIndex;
    }

    public List<String> getLabels() {
        return labels;
    }
}
