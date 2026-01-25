package com.beanvulnerable.aeg;

import com.beanvulnerable.aeg.domain.Constraint;
import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.Context;
import com.microsoft.z3.Expr;
import com.microsoft.z3.FuncDecl;
import com.microsoft.z3.IntNum;
import com.microsoft.z3.Model;
import com.microsoft.z3.SeqExpr;
import com.microsoft.z3.SeqSort;
import com.microsoft.z3.Solver;
import com.microsoft.z3.Sort;
import com.microsoft.z3.Status;
import com.microsoft.z3.Symbol;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Z3 Constraint Solver
 *
 * SMT Solver (Satisfiability Modulo Theories)
 * - Determines SAT/UNSAT of constraint sets
 * - Generates concrete values (SAT models)
 * - Supports integers, strings, arrays, etc.
 *
 * Used for:
 * 1. Path feasibility checking (SAT = feasible)
 * 2. Concrete value generation for PoCs
 * 3. Exploit path discovery
 */
public class Z3Solver {

    private final Context z3Context;
    private final Solver z3Solver;
    private final Map<String, Expr> declaredVariables;

    private static final long SOLVER_TIMEOUT = 30000; // 30 seconds

    // ============================================
    // CONSTRUCTORS
    // ============================================

    public Z3Solver() {
        // Initialize Z3 context
        Map<String, String> cfg = new HashMap<>();
        cfg.put("model", "true");
        cfg.put("timeout", String.valueOf(SOLVER_TIMEOUT));

        this.z3Context = new Context(cfg);
        this.z3Solver = z3Context.mkSolver();
        this.declaredVariables = new HashMap<>();
    }

    // ============================================
    // 1. CONSTRAINT MANAGEMENT
    // ============================================

    /**
     * Add constraint to solver
     *
     * Constraint format (SMT-LIB):
     * (declare-const x Int)
     * (assert (> x 0))
     * etc.
     */
    public void addConstraint(Constraint constraint) {
        if (constraint == null || constraint.getExpression() == null) {
            return;
        }
        String constraintExpr = constraint.getExpression().trim();
        if (constraintExpr.isEmpty()) {
            return;
        }

        // Convert constraint to Z3 expression(s)
        BoolExpr[] expressions = z3Context.parseSMTLIB2String(
            constraintExpr,
            new Symbol[0],
            new Sort[0],
            new Symbol[0],
            new FuncDecl[0]
        );
        for (BoolExpr expr : expressions) {
            z3Solver.add(expr);
        }
    }

    /**
     * Add multiple constraints
     */
    public void addConstraints(List<Constraint> constraints) {
        if (constraints == null) {
            return;
        }
        for (Constraint constraint : constraints) {
            addConstraint(constraint);
        }
    }

    /**
     * Clear all constraints
     */
    public void reset() {
        z3Solver.reset();
        declaredVariables.clear();
    }

    // ============================================
    // 2. SATISFIABILITY CHECKING
    // ============================================

    /**
     * Check if constraint set is satisfiable (SAT)
     *
     * Returns:
     * - SAT: Constraints can be satisfied
     * - UNSAT: Constraints are contradictory
     * - UNKNOWN: Could not determine (timeout)
     *
     * @param constraints List of constraints
     * @return true if SAT, false if UNSAT
     */
    public boolean isSatisfiable(List<Constraint> constraints) {
        // Save current state
        z3Solver.push();

        // Add constraints
        addConstraints(constraints);

        // Check satisfiability
        Status status = z3Solver.check();

        // Restore state
        z3Solver.pop();

        return status == Status.SATISFIABLE;
    }

    /**
     * Check satisfiability and return status
     */
    public SolverStatus checkSatisfiability(List<Constraint> constraints) {
        z3Solver.push();

        addConstraints(constraints);

        Status status = z3Solver.check();

        z3Solver.pop();

        switch (status) {
            case SATISFIABLE:
                return SolverStatus.SAT;
            case UNSATISFIABLE:
                return SolverStatus.UNSAT;
            case UNKNOWN:
                return SolverStatus.UNKNOWN;
            default:
                return SolverStatus.UNKNOWN;
        }
    }

    // ============================================
    // 3. MODEL GENERATION (CONCRETE VALUES)
    // ============================================

    /**
     * Generate concrete values (model) that satisfy constraints
     *
     * @param constraints Constraint set
     * @return Map of variable names to concrete values
     */
    public Map<String, Object> generateConcreteValues(List<Constraint> constraints) {
        Map<String, Object> concreteValues = new HashMap<>();

        z3Solver.push();

        // Add constraints
        addConstraints(constraints);

        // Check satisfiability
        Status status = z3Solver.check();

        if (status == Status.SATISFIABLE) {
            // Get model
            Model model = z3Solver.getModel();
            concreteValues.putAll(extractModel(model));
        }

        z3Solver.pop();

        return concreteValues;
    }

    private Map<String, Object> extractModel(Model model) {
        Map<String, Object> concreteValues = new HashMap<>();
        for (String varName : declaredVariables.keySet()) {
            Expr varExpr = declaredVariables.get(varName);
            Expr value = model.eval(varExpr, false);
            concreteValues.put(varName, z3ValueToJava(value));
        }
        return concreteValues;
    }

    /**
     * Convert Z3 expression to Java object
     */
    private Object z3ValueToJava(Expr expr) {
        if (expr instanceof IntNum) {
            String raw = expr.toString();
            try {
                return Long.parseLong(raw);
            } catch (NumberFormatException ignored) {
                return raw;
            }
        } else if (expr instanceof SeqExpr) {
            return expr.toString().replace("\"", "");
        } else if (expr instanceof BoolExpr) {
            String raw = expr.toString();
            if ("true".equals(raw) || "false".equals(raw)) {
                return Boolean.parseBoolean(raw);
            }
            return raw;
        } else {
            return expr.toString();
        }
    }

    // ============================================
    // 4. MULTI-SOLUTION FINDING
    // ============================================

    /**
     * Find multiple solutions to constraint set
     *
     * Useful for:
     * - Generating diverse PoCs
     * - Testing different input combinations
     *
     * @param constraints Constraint set
     * @param maxSolutions Max number of solutions to find
     * @return List of solution maps
     */
    public List<Map<String, Object>> findMultipleSolutions(
        List<Constraint> constraints,
        int maxSolutions) {

        List<Map<String, Object>> solutions = new ArrayList<>();

        z3Solver.push();

        // Add constraints
        addConstraints(constraints);

        // Find solutions iteratively
        for (int i = 0; i < maxSolutions; i++) {
            Status status = z3Solver.check();

            if (status != Status.SATISFIABLE) {
                break; // No more solutions
            }

            // Get model
            Model model = z3Solver.getModel();
            Map<String, Object> solution = extractModel(model);
            solutions.add(solution);

            if (declaredVariables.isEmpty()) {
                break;
            }

            // Add negation to find next solution
            BoolExpr[] exclusion = new BoolExpr[declaredVariables.size()];
            int idx = 0;
            for (String varName : declaredVariables.keySet()) {
                Expr varExpr = declaredVariables.get(varName);
                Expr value = model.eval(varExpr, false);
                exclusion[idx++] = z3Context.mkNot(z3Context.mkEq(varExpr, value));
            }

            // Add disjunction (at least one variable must differ)
            z3Solver.add(z3Context.mkOr(exclusion));
        }

        z3Solver.pop();

        return solutions;
    }

    // ============================================
    // 5. VARIABLE DECLARATION
    // ============================================

    /**
     * Declare integer variable
     */
    public void declareIntVariable(String varName) {
        Expr varExpr = z3Context.mkConst(varName, z3Context.getIntSort());
        declaredVariables.put(varName, varExpr);
    }

    /**
     * Declare string variable
     */
    public void declareStringVariable(String varName) {
        SeqSort stringSort = z3Context.getStringSort();
        Expr varExpr = z3Context.mkConst(varName, stringSort);
        declaredVariables.put(varName, varExpr);
    }

    /**
     * Declare boolean variable
     */
    public void declareBoolVariable(String varName) {
        Expr varExpr = z3Context.mkConst(varName, z3Context.getBoolSort());
        declaredVariables.put(varName, varExpr);
    }

    // ============================================
    // 6. PUBLIC API
    // ============================================

    /**
     * Solve constraints and return result
     */
    public SolverResult solve(List<Constraint> constraints) {
        SolverResult result = new SolverResult();

        z3Solver.push();

        // Add constraints
        addConstraints(constraints);

        // Check satisfiability
        Status status = z3Solver.check();
        if (status == Status.SATISFIABLE) {
            result.setStatus(SolverStatus.SAT);
            result.setModel(extractModel(z3Solver.getModel()));
        } else if (status == Status.UNSATISFIABLE) {
            result.setStatus(SolverStatus.UNSAT);
        } else {
            result.setStatus(SolverStatus.UNKNOWN);
        }

        z3Solver.pop();

        return result;
    }

    /**
     * Close Z3 context
     */
    public void close() {
        z3Context.close();
    }
}
