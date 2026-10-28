import com.sun.source.tree.*;
import com.sun.source.util.*;
import javax.tools.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/**
 * Genuine OpenJDK 17 Compiler Tree API (JavacTask) AST & Scope Extractor for NTK/IRIS.
 * Parses .java source files into CompilationUnitTree ASTs without executing user code
 * or requiring external Maven/Gradle classpath dependencies.
 * Emits deterministic JSON containing package, imports, classes, fields, methods,
 * lexical block scopes, variable declarations (including try-with-resources),
 * assignments/reassignments, dominating if-guards, and method/constructor invocations.
 */
public class NtkJavacAstExtractor {

    private static String esc(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\': sb.append("\\\\"); break;
                case '"': sb.append("\\\""); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    private static boolean blockTerminates(StatementTree stmt) {
        if (stmt == null) return false;
        if (stmt instanceof ThrowTree || stmt instanceof ReturnTree) {
            return true;
        }
        if (stmt instanceof BlockTree) {
            List<? extends StatementTree> stmts = ((BlockTree) stmt).getStatements();
            if (stmts.isEmpty()) return false;
            for (StatementTree s : stmts) {
                if (s instanceof ThrowTree || s instanceof ReturnTree) {
                    return true;
                }
            }
            return blockTerminates(stmts.get(stmts.size() - 1));
        }
        return false;
    }

    private static String classifyExprKind(Tree expr, Set<String> staticFinalConsts) {
        if (expr == null) return "NULL";
        if (expr instanceof ParenthesizedTree) {
            return classifyExprKind(((ParenthesizedTree) expr).getExpression(), staticFinalConsts);
        }
        if (expr instanceof LiteralTree) {
            Tree.Kind k = expr.getKind();
            if (k == Tree.Kind.STRING_LITERAL) return "STRING_LITERAL";
            if (k == Tree.Kind.NULL_LITERAL) return "NULL_LITERAL";
            return "PRIMITIVE_LITERAL";
        }
        if (expr instanceof IdentifierTree) {
            String name = ((IdentifierTree) expr).getName().toString();
            if (staticFinalConsts.contains(name)) {
                return "STATIC_FINAL_CONST_IDENT";
            }
            return "IDENTIFIER";
        }
        if (expr instanceof BinaryTree) {
            BinaryTree bt = (BinaryTree) expr;
            if (bt.getKind() == Tree.Kind.PLUS) {
                String lk = classifyExprKind(bt.getLeftOperand(), staticFinalConsts);
                String rk = classifyExprKind(bt.getRightOperand(), staticFinalConsts);
                boolean lConst = lk.equals("STRING_LITERAL") || lk.equals("PRIMITIVE_LITERAL") || lk.equals("STATIC_FINAL_CONST_IDENT") || lk.equals("CONSTANT_CONCAT_EXPR");
                boolean rConst = rk.equals("STRING_LITERAL") || rk.equals("PRIMITIVE_LITERAL") || rk.equals("STATIC_FINAL_CONST_IDENT") || rk.equals("CONSTANT_CONCAT_EXPR");
                if (lConst && rConst) {
                    return "CONSTANT_CONCAT_EXPR";
                }
                return "DYNAMIC_CONCAT_EXPR";
            }
            return "BINARY_" + bt.getKind().name();
        }
        if (expr instanceof MethodInvocationTree) {
            return "METHOD_INVOCATION";
        }
        if (expr instanceof NewClassTree) {
            return "NEW_CLASS";
        }
        if (expr instanceof NewArrayTree) {
            return "NEW_ARRAY";
        }
        if (expr instanceof MemberSelectTree) {
            return "MEMBER_SELECT";
        }
        if (expr instanceof ConditionalExpressionTree) {
            return "CONDITIONAL_EXPR";
        }
        return expr.getKind().name();
    }

    private static void collectIdentifiers(Tree node, List<String> out) {
        if (node == null) return;
        new TreeScanner<Void, Void>() {
            @Override
            public Void visitIdentifier(IdentifierTree t, Void p) {
                out.add(t.getName().toString());
                return super.visitIdentifier(t, p);
            }
        }.scan(node, null);
    }

    private static void collectStringLiterals(Tree node, List<String> out) {
        if (node == null) return;
        new TreeScanner<Void, Void>() {
            @Override
            public Void visitLiteral(LiteralTree t, Void p) {
                if (t.getKind() == Tree.Kind.STRING_LITERAL && t.getValue() != null) {
                    out.add(t.getValue().toString());
                }
                return super.visitLiteral(t, p);
            }
        }.scan(node, null);
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.out.println("{\"files\":[]}");
            return;
        }
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        StandardJavaFileManager fm = compiler.getStandardFileManager(diagnostics, null, StandardCharsets.UTF_8);

        List<File> fileList = new ArrayList<>();
        for (String a : args) {
            File f = new File(a);
            if (f.exists() && f.isFile()) {
                fileList.add(f);
            }
        }
        if (fileList.isEmpty()) {
            System.out.println("{\"files\":[]}");
            return;
        }

        Iterable<? extends JavaFileObject> fileObjects = fm.getJavaFileObjectsFromFiles(fileList);
        List<String> options = Arrays.asList("-proc:none");
        JavacTask task = (JavacTask) compiler.getTask(null, fm, diagnostics, options, null, fileObjects);
        SourcePositions srcPos = Trees.instance(task).getSourcePositions();
        Iterable<? extends CompilationUnitTree> units = task.parse();

        StringBuilder sb = new StringBuilder(16384);
        sb.append("{\"parser_engine\":\"OPENJDK17_JAVAC_TASK_AST\",\"files\":[");
        boolean firstFile = true;

        for (CompilationUnitTree cu : units) {
            if (!firstFile) sb.append(",");
            firstFile = false;

            String filePath = new File(cu.getSourceFile().toUri()).getPath();
            LineMap lineMap = cu.getLineMap();
            ExpressionTree pkgTree = cu.getPackageName();
            String pkgName = pkgTree != null ? pkgTree.toString() : "";

            sb.append("{\"file_path\":\"").append(esc(filePath)).append("\",");
            sb.append("\"package_name\":\"").append(esc(pkgName)).append("\",");

            sb.append("\"imports\":[");
            boolean firstImp = true;
            for (ImportTree imp : cu.getImports()) {
                if (!firstImp) sb.append(",");
                firstImp = false;
                sb.append("\"").append(esc(imp.getQualifiedIdentifier().toString())).append("\"");
            }
            sb.append("],");

            sb.append("\"classes\":[");
            final boolean[] firstClass = {true};

            new TreeScanner<Void, Void>() {
                @Override
                public Void visitClass(ClassTree ct, Void p) {
                    if (!firstClass[0]) sb.append(",");
                    firstClass[0] = false;

                    long cStartPos = srcPos.getStartPosition(cu, ct);
                    long cEndPos = srcPos.getEndPosition(cu, ct);
                    long cStartLine = cStartPos >= 0 ? lineMap.getLineNumber(cStartPos) : 1;
                    long cEndLine = cEndPos >= 0 ? lineMap.getLineNumber(cEndPos) : cStartLine;

                    Set<String> staticFinalConsts = new HashSet<>();
                    List<String> fieldsJson = new ArrayList<>();

                    for (Tree member : ct.getMembers()) {
                        if (member instanceof VariableTree) {
                            VariableTree vt = (VariableTree) member;
                            String fName = vt.getName().toString();
                            String fType = vt.getType() != null ? vt.getType().toString() : "";
                            Set<javax.lang.model.element.Modifier> mods = vt.getModifiers().getFlags();
                            boolean isStatic = mods.contains(javax.lang.model.element.Modifier.STATIC);
                            boolean isFinal = mods.contains(javax.lang.model.element.Modifier.FINAL);
                            ExpressionTree init = vt.getInitializer();
                            String initStr = init != null ? init.toString() : "";
                            String initKind = classifyExprKind(init, staticFinalConsts);
                            if (isStatic && isFinal && (initKind.equals("STRING_LITERAL") || initKind.equals("PRIMITIVE_LITERAL") || initKind.equals("CONSTANT_CONCAT_EXPR"))) {
                                staticFinalConsts.add(fName);
                            }
                            fieldsJson.add(
                                "{\"name\":\"" + esc(fName) + "\"," +
                                "\"type\":\"" + esc(fType) + "\"," +
                                "\"is_static\":" + isStatic + "," +
                                "\"is_final\":" + isFinal + "," +
                                "\"init_expr\":\"" + esc(initStr) + "\"," +
                                "\"init_kind\":\"" + esc(initKind) + "\"}"
                            );
                        }
                    }

                    sb.append("{\"class_name\":\"").append(esc(ct.getSimpleName().toString())).append("\",");
                    sb.append("\"start_line\":").append(cStartLine).append(",");
                    sb.append("\"end_line\":").append(cEndLine).append(",");
                    sb.append("\"fields\":[").append(String.join(",", fieldsJson)).append("],");
                    sb.append("\"methods\":[");

                    boolean firstMethod = true;
                    for (Tree member : ct.getMembers()) {
                        if (member instanceof MethodTree) {
                            MethodTree mt = (MethodTree) member;
                            if (!firstMethod) sb.append(",");
                            firstMethod = false;
                            emitMethodJson(cu, lineMap, srcPos, mt, staticFinalConsts, sb);
                        }
                    }
                    sb.append("]}");
                    return super.visitClass(ct, p);
                }
            }.scan(cu, null);

            sb.append("]}");
        }
        sb.append("]}");
        System.out.println(sb.toString());
        fm.close();
    }

    private static void emitMethodJson(
        CompilationUnitTree cu,
        LineMap lineMap,
        SourcePositions srcPos,
        MethodTree mt,
        Set<String> staticFinalConsts,
        StringBuilder sb
    ) {
        long mStartPos = srcPos.getStartPosition(cu, mt);
        long mEndPos = srcPos.getEndPosition(cu, mt);
        long mStartLine = mStartPos >= 0 ? lineMap.getLineNumber(mStartPos) : 1;
        long mEndLine = mEndPos >= 0 ? lineMap.getLineNumber(mEndPos) : mStartLine;

        String mName = mt.getName().toString();
        String retType = mt.getReturnType() != null ? mt.getReturnType().toString() : "void";

        List<String> paramStrings = new ArrayList<>();
        List<String> paramJson = new ArrayList<>();
        for (VariableTree pt : mt.getParameters()) {
            String pType = pt.getType() != null ? pt.getType().toString() : "Object";
            String pName = pt.getName().toString();
            paramStrings.add(pType + " " + pName);
            List<String> annos = new ArrayList<>();
            if (pt.getModifiers() != null && pt.getModifiers().getAnnotations() != null) {
                for (AnnotationTree at : pt.getModifiers().getAnnotations()) {
                    annos.add("\"" + esc(at.getAnnotationType().toString()) + "\"");
                }
            }
            paramJson.add(
                "{\"name\":\"" + esc(pName) + "\"," +
                "\"type\":\"" + esc(pType) + "\"," +
                "\"annotations\":[" + String.join(",", annos) + "]}"
            );
        }
        String signature = retType + " " + mName + "(" + String.join(", ", paramStrings) + ")";

        List<String> localVarsJson = new ArrayList<>();
        List<String> assignmentsJson = new ArrayList<>();
        List<String> ifGuardsJson = new ArrayList<>();
        List<String> invocationsJson = new ArrayList<>();
        List<String> newClassesJson = new ArrayList<>();
        List<String> returnsJson = new ArrayList<>();
        List<String> switchesJson = new ArrayList<>();

        final int[] nextScopeId = {1};
        final int[] stmtOrder = {0};

        class MethodBodyVisitor extends TreeScanner<Void, Integer> {
            private final Map<Integer, Integer> parentScopeMap = new HashMap<>();

            MethodBodyVisitor() {
                parentScopeMap.put(0, -1);
            }

            private List<Integer> getAncestorScopes(int scopeId) {
                List<Integer> chain = new ArrayList<>();
                Integer cur = scopeId;
                while (cur != null && cur >= 0) {
                    chain.add(cur);
                    cur = parentScopeMap.get(cur);
                }
                return chain;
            }

            private String intListJson(List<Integer> list) {
                StringBuilder b = new StringBuilder("[");
                for (int i = 0; i < list.size(); i++) {
                    if (i > 0) b.append(",");
                    b.append(list.get(i));
                }
                b.append("]");
                return b.toString();
            }

            private String strListJson(List<String> list) {
                StringBuilder b = new StringBuilder("[");
                for (int i = 0; i < list.size(); i++) {
                    if (i > 0) b.append(",");
                    b.append("\"").append(esc(list.get(i))).append("\"");
                }
                b.append("]");
                return b.toString();
            }

            @Override
            public Void visitClass(ClassTree ct, Integer parentScope) {
                return null;
            }

            @Override
            public Void visitBlock(BlockTree bt, Integer parentScope) {
                int myScope = nextScopeId[0]++;
                parentScopeMap.put(myScope, parentScope);
                return super.visitBlock(bt, myScope);
            }

            @Override
            public Void visitEnhancedForLoop(EnhancedForLoopTree eflt, Integer parentScope) {
                int loopScope = nextScopeId[0]++;
                parentScopeMap.put(loopScope, parentScope);
                ExpressionTree iterExpr = eflt.getExpression();
                scan(iterExpr, parentScope);
                VariableTree vt = eflt.getVariable();
                if (vt != null) {
                    stmtOrder[0]++;
                    long sPos = srcPos.getStartPosition(cu, vt);
                    long ePos = srcPos.getEndPosition(cu, vt);
                    long sLine = sPos >= 0 ? lineMap.getLineNumber(sPos) : mStartLine;
                    long eLine = ePos >= 0 ? lineMap.getLineNumber(ePos) : sLine;
                    String vName = vt.getName().toString();
                    String vType = vt.getType() != null ? vt.getType().toString() : "";
                    String initStr = iterExpr != null ? iterExpr.toString() : "";
                    String initKind = classifyExprKind(iterExpr, staticFinalConsts);
                    List<String> idents = new ArrayList<>();
                    List<String> lits = new ArrayList<>();
                    collectIdentifiers(iterExpr, idents);
                    collectStringLiterals(iterExpr, lits);
                    localVarsJson.add(
                        "{\"stmt_order\":" + stmtOrder[0] + "," +
                        "\"name\":\"" + esc(vName) + "\"," +
                        "\"type\":\"" + esc(vType) + "\"," +
                        "\"is_final\":false," +
                        "\"is_try_resource\":false," +
                        "\"init_expr\":\"" + esc(initStr) + "\"," +
                        "\"init_kind\":\"" + esc(initKind) + "\"," +
                        "\"identifiers\":" + strListJson(idents) + "," +
                        "\"string_literals\":" + strListJson(lits) + "," +
                        "\"scope_id\":" + loopScope + "," +
                        "\"ancestor_scopes\":" + intListJson(getAncestorScopes(loopScope)) + "," +
                        "\"start_line\":" + sLine + "," +
                        "\"end_line\":" + eLine + "}"
                    );
                }
                scan(eflt.getStatement(), loopScope);
                return null;
            }

            @Override
            public Void visitSwitch(SwitchTree st, Integer parentScope) {
                stmtOrder[0]++;
                long sPos = srcPos.getStartPosition(cu, st);
                long ePos = srcPos.getEndPosition(cu, st);
                long sLine = sPos >= 0 ? lineMap.getLineNumber(sPos) : mStartLine;
                long eLine = ePos >= 0 ? lineMap.getLineNumber(ePos) : sLine;
                ExpressionTree selExpr = st.getExpression();
                String selStr = selExpr != null ? selExpr.toString() : "";
                List<String> selIdents = new ArrayList<>();
                collectIdentifiers(selExpr, selIdents);
                List<String> casesJson = new ArrayList<>();
                List<? extends CaseTree> cases = st.getCases();
                if (cases != null) {
                    int nCases = cases.size();
                    List<String> pendingLabels = new ArrayList<>();
                    long groupStartLine = -1;
                    for (int i = 0; i < nCases; i++) {
                        CaseTree ct = cases.get(i);
                        long cStart = srcPos.getStartPosition(cu, ct);
                        long cStartLine = cStart >= 0 ? lineMap.getLineNumber(cStart) : sLine;
                        if (groupStartLine < 0) groupStartLine = cStartLine;
                        ExpressionTree pat = ct.getExpression();
                        pendingLabels.add(pat != null ? pat.toString() : "default");
                        List<? extends StatementTree> stmts = ct.getStatements();
                        if (stmts != null && !stmts.isEmpty()) {
                            StatementTree lastStmt = stmts.get(stmts.size() - 1);
                            long cEnd = srcPos.getEndPosition(cu, lastStmt);
                            long cEndLine = cEnd >= 0 ? lineMap.getLineNumber(cEnd) : cStartLine;
                            casesJson.add(
                                "{\"labels\":" + strListJson(pendingLabels) + "," +
                                "\"start_line\":" + groupStartLine + "," +
                                "\"end_line\":" + cEndLine + "}"
                            );
                            pendingLabels = new ArrayList<>();
                            groupStartLine = -1;
                        }
                    }
                }
                switchesJson.add(
                    "{\"stmt_order\":" + stmtOrder[0] + "," +
                    "\"selector_expr\":\"" + esc(selStr) + "\"," +
                    "\"selector_identifiers\":" + strListJson(selIdents) + "," +
                    "\"scope_id\":" + parentScope + "," +
                    "\"start_line\":" + sLine + "," +
                    "\"end_line\":" + eLine + "," +
                    "\"cases\":[" + String.join(",", casesJson) + "]}"
                );
                return super.visitSwitch(st, parentScope);
            }

            @Override
            public Void visitReturn(ReturnTree rt, Integer scopeId) {
                stmtOrder[0]++;
                long sPos = srcPos.getStartPosition(cu, rt);
                long ePos = srcPos.getEndPosition(cu, rt);
                long sLine = sPos >= 0 ? lineMap.getLineNumber(sPos) : mStartLine;
                long eLine = ePos >= 0 ? lineMap.getLineNumber(ePos) : sLine;
                ExpressionTree expr = rt.getExpression();
                String valStr = expr != null ? expr.toString() : "";
                String valKind = classifyExprKind(expr, staticFinalConsts);
                List<String> idents = new ArrayList<>();
                List<String> lits = new ArrayList<>();
                collectIdentifiers(expr, idents);
                collectStringLiterals(expr, lits);
                returnsJson.add(
                    "{\"stmt_order\":" + stmtOrder[0] + "," +
                    "\"expr\":\"" + esc(valStr) + "\"," +
                    "\"kind\":\"" + esc(valKind) + "\"," +
                    "\"identifiers\":" + strListJson(idents) + "," +
                    "\"string_literals\":" + strListJson(lits) + "," +
                    "\"scope_id\":" + scopeId + "," +
                    "\"ancestor_scopes\":" + intListJson(getAncestorScopes(scopeId)) + "," +
                    "\"start_line\":" + sLine + "," +
                    "\"end_line\":" + eLine + "}"
                );
                return super.visitReturn(rt, scopeId);
            }

            @Override
            public Void visitTry(TryTree tt, Integer parentScope) {
                int tryResourceScope = nextScopeId[0]++;
                parentScopeMap.put(tryResourceScope, parentScope);
                if (tt.getResources() != null) {
                    for (Tree res : tt.getResources()) {
                        if (res instanceof VariableTree) {
                            recordVariable((VariableTree) res, tryResourceScope, true);
                            scan(((VariableTree) res).getInitializer(), tryResourceScope);
                        } else {
                            scan(res, tryResourceScope);
                        }
                    }
                }
                scan(tt.getBlock(), tryResourceScope);
                if (tt.getCatches() != null) {
                    for (CatchTree ct : tt.getCatches()) {
                        int catchScope = nextScopeId[0]++;
                        parentScopeMap.put(catchScope, parentScope);
                        scan(ct.getBlock(), catchScope);
                    }
                }
                if (tt.getFinallyBlock() != null) {
                    scan(tt.getFinallyBlock(), parentScope);
                }
                return null;
            }

            private void recordVariable(VariableTree vt, int scopeId, boolean isTryResource) {
                stmtOrder[0]++;
                long sPos = srcPos.getStartPosition(cu, vt);
                long ePos = srcPos.getEndPosition(cu, vt);
                long sLine = sPos >= 0 ? lineMap.getLineNumber(sPos) : mStartLine;
                long eLine = ePos >= 0 ? lineMap.getLineNumber(ePos) : sLine;
                String vName = vt.getName().toString();
                String vType = vt.getType() != null ? vt.getType().toString() : "";
                boolean isFinal = vt.getModifiers() != null &&
                    vt.getModifiers().getFlags().contains(javax.lang.model.element.Modifier.FINAL);
                ExpressionTree init = vt.getInitializer();
                String initStr = init != null ? init.toString() : "";
                String initKind = classifyExprKind(init, staticFinalConsts);
                List<String> idents = new ArrayList<>();
                List<String> lits = new ArrayList<>();
                collectIdentifiers(init, idents);
                collectStringLiterals(init, lits);

                localVarsJson.add(
                    "{\"stmt_order\":" + stmtOrder[0] + "," +
                    "\"name\":\"" + esc(vName) + "\"," +
                    "\"type\":\"" + esc(vType) + "\"," +
                    "\"is_final\":" + isFinal + "," +
                    "\"is_try_resource\":" + isTryResource + "," +
                    "\"init_expr\":\"" + esc(initStr) + "\"," +
                    "\"init_kind\":\"" + esc(initKind) + "\"," +
                    "\"identifiers\":" + strListJson(idents) + "," +
                    "\"string_literals\":" + strListJson(lits) + "," +
                    "\"scope_id\":" + scopeId + "," +
                    "\"ancestor_scopes\":" + intListJson(getAncestorScopes(scopeId)) + "," +
                    "\"start_line\":" + sLine + "," +
                    "\"end_line\":" + eLine + "}"
                );
            }

            @Override
            public Void visitVariable(VariableTree vt, Integer scopeId) {
                recordVariable(vt, scopeId, false);
                return super.visitVariable(vt, scopeId);
            }

            @Override
            public Void visitAssignment(AssignmentTree at, Integer scopeId) {
                stmtOrder[0]++;
                long sPos = srcPos.getStartPosition(cu, at);
                long ePos = srcPos.getEndPosition(cu, at);
                long sLine = sPos >= 0 ? lineMap.getLineNumber(sPos) : mStartLine;
                long eLine = ePos >= 0 ? lineMap.getLineNumber(ePos) : sLine;
                String target = at.getVariable().toString();
                ExpressionTree expr = at.getExpression();
                String valStr = expr != null ? expr.toString() : "";
                String valKind = classifyExprKind(expr, staticFinalConsts);
                List<String> idents = new ArrayList<>();
                List<String> lits = new ArrayList<>();
                collectIdentifiers(expr, idents);
                collectStringLiterals(expr, lits);

                assignmentsJson.add(
                    "{\"stmt_order\":" + stmtOrder[0] + "," +
                    "\"target\":\"" + esc(target) + "\"," +
                    "\"operator\":\"=\"," +
                    "\"value_expr\":\"" + esc(valStr) + "\"," +
                    "\"value_kind\":\"" + esc(valKind) + "\"," +
                    "\"identifiers\":" + strListJson(idents) + "," +
                    "\"string_literals\":" + strListJson(lits) + "," +
                    "\"scope_id\":" + scopeId + "," +
                    "\"ancestor_scopes\":" + intListJson(getAncestorScopes(scopeId)) + "," +
                    "\"start_line\":" + sLine + "," +
                    "\"end_line\":" + eLine + "}"
                );
                return super.visitAssignment(at, scopeId);
            }

            @Override
            public Void visitCompoundAssignment(CompoundAssignmentTree cat, Integer scopeId) {
                stmtOrder[0]++;
                long sPos = srcPos.getStartPosition(cu, cat);
                long ePos = srcPos.getEndPosition(cu, cat);
                long sLine = sPos >= 0 ? lineMap.getLineNumber(sPos) : mStartLine;
                long eLine = ePos >= 0 ? lineMap.getLineNumber(ePos) : sLine;
                String target = cat.getVariable().toString();
                ExpressionTree expr = cat.getExpression();
                String valStr = expr != null ? expr.toString() : "";
                String valKind = classifyExprKind(expr, staticFinalConsts);
                List<String> idents = new ArrayList<>();
                List<String> lits = new ArrayList<>();
                collectIdentifiers(expr, idents);
                collectStringLiterals(expr, lits);

                assignmentsJson.add(
                    "{\"stmt_order\":" + stmtOrder[0] + "," +
                    "\"target\":\"" + esc(target) + "\"," +
                    "\"operator\":\"+=\"," +
                    "\"value_expr\":\"" + esc(valStr) + "\"," +
                    "\"value_kind\":\"" + esc(valKind) + "\"," +
                    "\"identifiers\":" + strListJson(idents) + "," +
                    "\"string_literals\":" + strListJson(lits) + "," +
                    "\"scope_id\":" + scopeId + "," +
                    "\"ancestor_scopes\":" + intListJson(getAncestorScopes(scopeId)) + "," +
                    "\"start_line\":" + sLine + "," +
                    "\"end_line\":" + eLine + "}"
                );
                return super.visitCompoundAssignment(cat, scopeId);
            }

            @Override
            public Void visitIf(IfTree it, Integer scopeId) {
                stmtOrder[0]++;
                long sPos = srcPos.getStartPosition(cu, it);
                long ePos = srcPos.getEndPosition(cu, it);
                long sLine = sPos >= 0 ? lineMap.getLineNumber(sPos) : mStartLine;
                long eLine = ePos >= 0 ? lineMap.getLineNumber(ePos) : sLine;

                StatementTree thenStmt = it.getThenStatement();
                StatementTree elseStmt = it.getElseStatement();
                long tStart = thenStmt != null ? lineMap.getLineNumber(Math.max(0, srcPos.getStartPosition(cu, thenStmt))) : sLine;
                long tEnd = thenStmt != null ? lineMap.getLineNumber(Math.max(0, srcPos.getEndPosition(cu, thenStmt))) : eLine;
                long elStart = elseStmt != null ? lineMap.getLineNumber(Math.max(0, srcPos.getStartPosition(cu, elseStmt))) : -1;
                long elEnd = elseStmt != null ? lineMap.getLineNumber(Math.max(0, srcPos.getEndPosition(cu, elseStmt))) : -1;

                boolean thenTerm = blockTerminates(thenStmt);
                boolean elseTerm = blockTerminates(elseStmt);

                ifGuardsJson.add(
                    "{\"stmt_order\":" + stmtOrder[0] + "," +
                    "\"condition\":\"" + esc(it.getCondition().toString()) + "\"," +
                    "\"scope_id\":" + scopeId + "," +
                    "\"ancestor_scopes\":" + intListJson(getAncestorScopes(scopeId)) + "," +
                    "\"start_line\":" + sLine + "," +
                    "\"end_line\":" + eLine + "," +
                    "\"then_start_line\":" + tStart + "," +
                    "\"then_end_line\":" + tEnd + "," +
                    "\"then_terminates\":" + thenTerm + "," +
                    "\"else_start_line\":" + elStart + "," +
                    "\"else_end_line\":" + elEnd + "," +
                    "\"else_terminates\":" + elseTerm + "}"
                );
                return super.visitIf(it, scopeId);
            }

            @Override
            public Void visitMethodInvocation(MethodInvocationTree mit, Integer scopeId) {
                stmtOrder[0]++;
                long sPos = srcPos.getStartPosition(cu, mit);
                long ePos = srcPos.getEndPosition(cu, mit);
                long sLine = sPos >= 0 ? lineMap.getLineNumber(sPos) : mStartLine;
                long eLine = ePos >= 0 ? lineMap.getLineNumber(ePos) : sLine;

                ExpressionTree sel = mit.getMethodSelect();
                String receiver = "";
                String methodName = sel.toString();
                if (sel instanceof MemberSelectTree) {
                    MemberSelectTree mst = (MemberSelectTree) sel;
                    receiver = mst.getExpression().toString();
                    methodName = mst.getIdentifier().toString();
                }

                List<String> argsStr = new ArrayList<>();
                List<String> argsKind = new ArrayList<>();
                List<String> idents = new ArrayList<>();
                List<String> lits = new ArrayList<>();
                for (ExpressionTree arg : mit.getArguments()) {
                    argsStr.add(arg.toString());
                    argsKind.add(classifyExprKind(arg, staticFinalConsts));
                    collectIdentifiers(arg, idents);
                    collectStringLiterals(arg, lits);
                }

                invocationsJson.add(
                    "{\"stmt_order\":" + stmtOrder[0] + "," +
                    "\"call_expr\":\"" + esc(mit.toString()) + "\"," +
                    "\"receiver\":\"" + esc(receiver) + "\"," +
                    "\"method_name\":\"" + esc(methodName) + "\"," +
                    "\"arguments\":" + strListJson(argsStr) + "," +
                    "\"arg_kinds\":" + strListJson(argsKind) + "," +
                    "\"arg_identifiers\":" + strListJson(idents) + "," +
                    "\"arg_string_literals\":" + strListJson(lits) + "," +
                    "\"scope_id\":" + scopeId + "," +
                    "\"ancestor_scopes\":" + intListJson(getAncestorScopes(scopeId)) + "," +
                    "\"start_line\":" + sLine + "," +
                    "\"end_line\":" + eLine + "}"
                );
                return super.visitMethodInvocation(mit, scopeId);
            }

            @Override
            public Void visitNewClass(NewClassTree nct, Integer scopeId) {
                stmtOrder[0]++;
                long sPos = srcPos.getStartPosition(cu, nct);
                long ePos = srcPos.getEndPosition(cu, nct);
                long sLine = sPos >= 0 ? lineMap.getLineNumber(sPos) : mStartLine;
                long eLine = ePos >= 0 ? lineMap.getLineNumber(ePos) : sLine;

                String clsType = nct.getIdentifier().toString();
                List<String> argsStr = new ArrayList<>();
                List<String> argsKind = new ArrayList<>();
                List<String> idents = new ArrayList<>();
                List<String> lits = new ArrayList<>();
                for (ExpressionTree arg : nct.getArguments()) {
                    argsStr.add(arg.toString());
                    argsKind.add(classifyExprKind(arg, staticFinalConsts));
                    collectIdentifiers(arg, idents);
                    collectStringLiterals(arg, lits);
                }

                newClassesJson.add(
                    "{\"stmt_order\":" + stmtOrder[0] + "," +
                    "\"new_expr\":\"" + esc(nct.toString()) + "\"," +
                    "\"class_type\":\"" + esc(clsType) + "\"," +
                    "\"arguments\":" + strListJson(argsStr) + "," +
                    "\"arg_kinds\":" + strListJson(argsKind) + "," +
                    "\"arg_identifiers\":" + strListJson(idents) + "," +
                    "\"arg_string_literals\":" + strListJson(lits) + "," +
                    "\"scope_id\":" + scopeId + "," +
                    "\"ancestor_scopes\":" + intListJson(getAncestorScopes(scopeId)) + "," +
                    "\"start_line\":" + sLine + "," +
                    "\"end_line\":" + eLine + "}"
                );
                return super.visitNewClass(nct, scopeId);
            }
        }

        if (mt.getBody() != null) {
            new MethodBodyVisitor().scan(mt.getBody(), 0);
        }

        sb.append("{\"name\":\"").append(esc(mName)).append("\",");
        sb.append("\"return_type\":\"").append(esc(retType)).append("\",");
        sb.append("\"signature\":\"").append(esc(signature)).append("\",");
        sb.append("\"start_line\":").append(mStartLine).append(",");
        sb.append("\"end_line\":").append(mEndLine).append(",");
        sb.append("\"parameters\":[").append(String.join(",", paramJson)).append("],");
        sb.append("\"local_variables\":[").append(String.join(",", localVarsJson)).append("],");
        sb.append("\"assignments\":[").append(String.join(",", assignmentsJson)).append("],");
        sb.append("\"if_guards\":[").append(String.join(",", ifGuardsJson)).append("],");
        sb.append("\"invocations\":[").append(String.join(",", invocationsJson)).append("],");
        sb.append("\"new_classes\":[").append(String.join(",", newClassesJson)).append("],");
        sb.append("\"returns\":[").append(String.join(",", returnsJson)).append("],");
        sb.append("\"switches\":[").append(String.join(",", switchesJson)).append("]}");
    }
}
