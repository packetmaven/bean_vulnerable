package com.beanvulnerable.aeg.domain;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SymbolicExecutionState {
    private final MethodAnalysis methodAnalysis;
    private final ControlFlowGraph cfg;
    private BasicBlock currentBlock;
    private final List<Constraint> constraints;
    private final Map<String, SymbolicValue> symbolicVariables;

    public SymbolicExecutionState(MethodAnalysis methodAnalysis,
                                  ControlFlowGraph cfg,
                                  List<Constraint> initialConstraints) {
        this.methodAnalysis = methodAnalysis;
        this.cfg = cfg;
        this.constraints = initialConstraints != null ? new ArrayList<>(initialConstraints) : new ArrayList<>();
        this.symbolicVariables = new HashMap<>();
        this.currentBlock = cfg != null ? cfg.getEntryBlock() : null;
    }

    public MethodAnalysis getMethodAnalysis() {
        return methodAnalysis;
    }

    public ControlFlowGraph getCfg() {
        return cfg;
    }

    public BasicBlock getCurrentBasicBlock() {
        return currentBlock;
    }

    public void setCurrentBasicBlock(BasicBlock block) {
        this.currentBlock = block;
    }

    public void addConstraint(Constraint constraint) {
        if (constraint != null) {
            constraints.add(constraint);
        }
    }

    public List<Constraint> getConstraints() {
        return constraints;
    }

    public Map<String, SymbolicValue> getSymbolicVariables() {
        return symbolicVariables;
    }

    public SymbolicValue getSymbolicValue(String name) {
        return symbolicVariables.get(name);
    }

    public void putSymbolicValue(String name, SymbolicValue value) {
        if (name != null && value != null) {
            symbolicVariables.put(name, value);
        }
    }

    public SymbolicExecutionState clone() {
        SymbolicExecutionState copy = new SymbolicExecutionState(methodAnalysis, cfg, constraints);
        copy.currentBlock = currentBlock;
        copy.symbolicVariables.putAll(symbolicVariables);
        return copy;
    }
}
