/* Trusted analysis tool. Parses/type-checks source; never loads/runs uploaded classes.
 * A deliberately narrow proof of literal String.replace encoding at one write call.
 * NOT a Java sanitizer-name allowlist or a general HTML/JS sanitizer verifier.
 */
import com.sun.source.tree.*;
import com.sun.source.util.*;
import javax.lang.model.element.*;
import javax.tools.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

public final class NtkEncodingAudit {
    static Trees trees;
    static SourcePositions positions;
    static Path root;
    static final IdentityHashMap<Tree, TreePath> paths = new IdentityHashMap<>();
    static final Map<Element, MethodTree> methods = new HashMap<>();
    static final Map<Element, VariableTree> locals = new HashMap<>();
    static final Set<Element> mutated = new HashSet<>();
    static final Set<MethodTree> nonLinear = Collections.newSetFromMap(new IdentityHashMap<>());
    static final List<Map<String,Object>> results = new ArrayList<>();

    static Element element(Tree t) { return t == null || !paths.containsKey(t) ? null : trees.getElement(paths.get(t)); }
    static String owner(Element e) { return e == null ? "" : e.getEnclosingElement().toString(); }
    static Map<String,Object> obj(Object... v) {
        Map<String,Object> m = new LinkedHashMap<>();
        for(int i=0;i<v.length;i+=2) m.put((String)v[i],v[i+1]);
        return m;
    }
    static String hash(byte[] b) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b)); }
    static Map<String,Object> location(Tree t) {
        TreePath p=paths.get(t); CompilationUnitTree u=p.getCompilationUnit();
        long a=positions.getStartPosition(u,t), b=positions.getEndPosition(u,t);
        return obj("uri",root.relativize(Path.of(u.getSourceFile().toUri())).toString().replace('\\','/'),
          "start_line",u.getLineMap().getLineNumber(a),"start_column",u.getLineMap().getColumnNumber(a),
          "end_line",u.getLineMap().getLineNumber(b-1),"end_column",u.getLineMap().getColumnNumber(b-1));
    }
    static MethodTree enclosing(Tree t) {
        for(TreePath p=paths.get(t);p!=null;p=p.getParentPath()) if(p.getLeaf() instanceof MethodTree m) return m;
        return null;
    }
    static ExpressionTree unwrap(ExpressionTree e) {
        while(e instanceof ParenthesizedTree p) e=p.getExpression();
        return e;
    }
    static ExpressionTree resolve(ExpressionTree e, MethodTree scope, Set<Element> seen) {
        e=unwrap(e);
        if(e instanceof IdentifierTree) {
            Element v=element(e); VariableTree d=locals.get(v);
            if(d!=null && !mutated.contains(v) && enclosing(d)==scope && d.getInitializer()!=null && seen.add(v)) {
                return resolve(d.getInitializer(),scope,seen);
            }
        }
        return e;
    }
    static ExpressionTree resolve(ExpressionTree e,MethodTree scope) { return resolve(e,scope,new HashSet<>()); }
    static ExpressionTree qualifier(MethodInvocationTree m) {
        return m.getMethodSelect() instanceof MemberSelectTree s ? s.getExpression() : null;
    }
    static String literal(ExpressionTree e) {
        e=unwrap(e);
        return e instanceof LiteralTree l && l.getValue() instanceof String ? (String)l.getValue() : null;
    }
    static boolean named(MethodInvocationTree m,String type,String sig) {
        Element e=element(m);return e instanceof ExecutableElement && owner(e).equals(type) && e.toString().equals(sig);
    }
    static void flatten(ExpressionTree e,MethodTree scope,List<ExpressionTree> out,int depth) {
        if(depth>30) { out.add(e);return; }
        e=resolve(e,scope);
        if(e instanceof BinaryTree b && b.getKind()==Tree.Kind.PLUS) {
            flatten(b.getLeftOperand(),scope,out,depth+1);flatten(b.getRightOperand(),scope,out,depth+1);
        } else out.add(e);
    }
    static String outputContext(String prefix,String suffix) {
        for(String tag:List.of("p","div","span","h1","h2","b","section")) {
            if(prefix.startsWith("<"+tag+">") && suffix.equals("</"+tag+">") &&
              !prefix.substring(tag.length()+2).contains("<") && !prefix.substring(tag.length()+2).contains(">")) return "HTML_TEXT";
        }
        for(String attribute:List.of("title","data-note")) {
            if(prefix.equals("<div "+attribute+"=\"") && suffix.equals("\">x</div>")) return "HTML_DOUBLE_QUOTED_ATTRIBUTE";
            if(prefix.equals("<div "+attribute+"='") && suffix.equals("'>x</div>")) return "HTML_SINGLE_QUOTED_ATTRIBUTE";
        }
        if(prefix.equals("<input value=\"") && suffix.equals("\">")) return "HTML_DOUBLE_QUOTED_ATTRIBUTE";
        return "UNSUPPORTED_OUTPUT_CONTEXT";
    }
    static Map<String,Object> encoding(ExpressionTree expression,String context) {
        ExpressionTree e=unwrap(expression);
        Map<String,Object> proof=obj("assessment","NO_RECOGNIZED_ENCODER");
        if(!(e instanceof MethodInvocationTree invocation))return proof;
        Element method=element(invocation);
        MethodTree declaration=methods.get(method);
        if(declaration!=null) {
            if(!(method instanceof ExecutableElement x) || !x.getModifiers().contains(Modifier.STATIC) ||
              x.getParameters().size()!=1 || !x.getParameters().get(0).asType().toString().equals("java.lang.String") ||
              !x.getReturnType().toString().equals("java.lang.String") || declaration.getBody()==null ||
              declaration.getBody().getStatements().size()!=1 ||
              !(declaration.getBody().getStatements().get(0) instanceof ReturnTree r) || r.getExpression()==null)
                return obj("assessment","UNSUPPORTED_ENCODER_IMPLEMENTATION","method",method.toString());
            proof.put("declaration",location(declaration));proof.put("method",owner(method)+"."+method);
            e=unwrap(r.getExpression());
        }
        // Terminal identifier is checked against the resolved method parameter.
        List<List<String>> replacements=new ArrayList<>();
        while(e instanceof MethodInvocationTree call && named(call,"java.lang.String","replace(java.lang.CharSequence,java.lang.CharSequence)")) {
            if(call.getArguments().size()!=2 || qualifier(call)==null)return obj("assessment","UNSUPPORTED_ENCODER_IMPLEMENTATION");
            String a=literal(call.getArguments().get(0)),b=literal(call.getArguments().get(1));
            if(a==null || b==null)return obj("assessment","UNSUPPORTED_ENCODER_IMPLEMENTATION");
            replacements.add(List.of(a,b));e=unwrap(qualifier(call));
            if(replacements.size()>5)return obj("assessment","UNSUPPORTED_ENCODER_IMPLEMENTATION");
        }
        Collections.reverse(replacements);
        if(declaration!=null) {
            if(!(e instanceof IdentifierTree) || !Objects.equals(element(e),element(declaration.getParameters().get(0))))
              return obj("assessment","UNSUPPORTED_ENCODER_IMPLEMENTATION");
        }
        if(replacements.isEmpty()) {
            if(declaration!=null) proof.put("assessment","IDENTITY_ENCODER_NOT_PROTECTION");
            return proof;
        }
        Map<String,String> expected=Map.of("&","&amp;","<","&lt;",">","&gt;","\"","&quot;","'","&#39;");
        Set<String> covered=new HashSet<>();boolean valid=replacements.get(0).equals(List.of("&","&amp;"));
        for(List<String> pair:replacements) {
            if(!Objects.equals(expected.get(pair.get(0)),pair.get(1)) || !covered.add(pair.get(0)))valid=false;
        }
        Set<String> required=new HashSet<>(Set.of("&","<",">"));
        if(context.equals("HTML_DOUBLE_QUOTED_ATTRIBUTE"))required.add("\"");
        if(context.equals("HTML_SINGLE_QUOTED_ATTRIBUTE"))required.add("'");
        proof.put("replacements_in_execution_order",replacements);
        proof.put("required_characters",new TreeSet<>(required));
        proof.put("assessment",valid && covered.containsAll(required) && !context.equals("UNSUPPORTED_OUTPUT_CONTEXT") ?
          "VERIFIED_LITERAL_REPLACE_ENCODER_FOR_CONTEXT" : "INCOMPLETE_OR_UNSUPPORTED_ENCODER");
        // Exact chains only. Arbitrary method names, annotations, regex replacement, mutation,
        // or transformed data appended after an encoder never establish an exemption.
        return proof;
    }
    static void inspect(MethodInvocationTree call) {
        Element e=element(call);
        if(!(e instanceof ExecutableElement) || !owner(e).equals("java.io.OutputStream") ||
           !e.toString().equals("write(byte[])"))return;
        MethodTree scope=enclosing(call);
        Map<String,Object> r=obj("location",location(call),"compiler_owner",owner(e),"compiler_signature",e.toString(),
          "http_context_authority","CODEQL_REQUIRED_NOT_THIS_COMPILER_TOOL","output_context","UNKNOWN",
          "assessment","REVIEW_REQUIRED_UNSUPPORTED_SHAPE");
        results.add(r);
        if(scope==null || nonLinear.contains(scope)) { r.put("assessment","REVIEW_REQUIRED_CONTROL_FLOW");return; }
        ExpressionTree recv=unwrap(qualifier(call));
        if(!(recv instanceof MethodInvocationTree response) ||
          !named(response,"com.sun.net.httpserver.HttpExchange","getResponseBody()")) {
            r.put("assessment","REVIEW_REQUIRED_NON_DIRECT_HTTP_STREAM");return;
        }
        ExpressionTree bytes=resolve(call.getArguments().get(0),scope);
        if(!(bytes instanceof MethodInvocationTree gb) || !named(gb,"java.lang.String","getBytes(java.nio.charset.Charset)") || qualifier(gb)==null) return;
        Element charset=element(gb.getArguments().get(0));
        if(charset==null || !owner(charset).equals("java.nio.charset.StandardCharsets") || !charset.getSimpleName().contentEquals("UTF_8")) {
            r.put("assessment","REVIEW_REQUIRED_CHARSET");return;
        }
        List<ExpressionTree> parts=new ArrayList<>();flatten(qualifier(gb),scope,parts,0);
        List<Integer> dynamic=new ArrayList<>();StringBuilder before=new StringBuilder(),after=new StringBuilder();
        for(int i=0;i<parts.size();i++) {
            String s=literal(parts.get(i));if(s==null)dynamic.add(i);
            else if(dynamic.isEmpty())before.append(s);else after.append(s);
        }
        if(dynamic.isEmpty()) {r.put("assessment","CONSTANT_BODY_NO_SAFETY_VERDICT");return;}
        if(dynamic.size()!=1) {r.put("assessment","REVIEW_REQUIRED_MULTIPLE_DYNAMIC_SEGMENTS");return;}
        String ctx=outputContext(before.toString(),after.toString());r.put("output_context",ctx);
        Map<String,Object> enc=encoding(parts.get(dynamic.get(0)),ctx);r.put("encoder_proof",enc);
        if(ctx.equals("UNSUPPORTED_OUTPUT_CONTEXT")) {r.put("assessment","REVIEW_REQUIRED_OUTPUT_CONTEXT");return;}
        String a=(String)enc.get("assessment");
        r.put("assessment",a.equals("VERIFIED_LITERAL_REPLACE_ENCODER_FOR_CONTEXT") ? "ENCODING_VERIFIED_SCOPED" :
          a.equals("NO_RECOGNIZED_ENCODER") ? "UNENCODED_SUPPORTED_CONTEXT" : "REVIEW_REQUIRED_ENCODER");
    }
    static String json(Object x) {
        if(x==null)return "null";
        if(x instanceof String s) {
            StringBuilder b=new StringBuilder("\"");
            for(char c:s.toCharArray()) switch(c) {
                case '"': b.append("\\\"");break;case '\\':b.append("\\\\");break;case '\n':b.append("\\n");break;
                case '\r':b.append("\\r");break;case '\t':b.append("\\t");break;
                default:if(c<32)b.append(String.format("\\u%04x",(int)c));else b.append(c);
            }
            return b.append('"').toString();
        }
        if(x instanceof Number || x instanceof Boolean)return x.toString();
        if(x instanceof Map<?,?> m) {List<String> p=new ArrayList<>();for(var a:m.entrySet())p.add(json(a.getKey().toString())+":"+json(a.getValue()));return "{"+String.join(",",p)+"}";}
        if(x instanceof Iterable<?> a) {List<String> p=new ArrayList<>();for(Object v:a)p.add(json(v));return "["+String.join(",",p)+"]";}
        throw new IllegalArgumentException("Not JSON");
    }
    public static void main(String[] args)throws Exception {
        if(args.length!=1)throw new IllegalArgumentException("SOURCE_ROOT required");root=Path.of(args[0]).toRealPath();
        List<Path> sources;
        try(var walk=Files.walk(root)) {sources=walk.filter(p->p.toString().endsWith(".java")).sorted().toList();}
        if(sources.isEmpty() || sources.size()>24)throw new IllegalArgumentException("JDK source limit 1..24");
        Map<String,Object> hashes=new TreeMap<>();
        for(Path p:sources) {
            if(Files.isSymbolicLink(p) || !p.toRealPath().startsWith(root))throw new IllegalArgumentException("Unsafe source path");
            hashes.put(root.relativize(p).toString().replace('\\','/'),hash(Files.readAllBytes(p)));
        }
        JavaCompiler compiler=ToolProvider.getSystemJavaCompiler();if(compiler==null)throw new IllegalStateException("JDK compiler required");
        DiagnosticCollector<JavaFileObject> diagnostics=new DiagnosticCollector<>();
        try(StandardJavaFileManager fm=compiler.getStandardFileManager(diagnostics,null,StandardCharsets.UTF_8)) {
            JavacTask task=(JavacTask)compiler.getTask(null,fm,diagnostics,List.of("-proc:none","--release","21","-encoding","UTF-8"),null,fm.getJavaFileObjectsFromPaths(sources));
            List<CompilationUnitTree> units=new ArrayList<>();task.parse().forEach(units::add);task.analyze();
            if(diagnostics.getDiagnostics().stream().anyMatch(d->d.getKind()==Diagnostic.Kind.ERROR))throw new IllegalStateException(diagnostics.getDiagnostics().toString());
            trees=Trees.instance(task);positions=trees.getSourcePositions();
            for(var u:units)new TreePathScanner<Void,Void>() {
                @Override public Void scan(Tree t,Void v) {
                    if(t!=null)paths.put(t,getCurrentPath()==null ? new TreePath((CompilationUnitTree)t) : new TreePath(getCurrentPath(),t));
                    return super.scan(t,v);
                }
                @Override public Void visitMethod(MethodTree m,Void v) {
                    methods.put(trees.getElement(getCurrentPath()),m);
                    if(m.getBody()!=null && m.getBody().getStatements().stream().anyMatch(s->!(s instanceof VariableTree || s instanceof ExpressionStatementTree || s instanceof ReturnTree)))nonLinear.add(m);
                    return super.visitMethod(m,v);
                }
                @Override public Void visitVariable(VariableTree d,Void v) {Element e=trees.getElement(getCurrentPath());if(e!=null && e.getKind()==ElementKind.LOCAL_VARIABLE)locals.put(e,d);return super.visitVariable(d,v);}
                @Override public Void visitAssignment(AssignmentTree a,Void v) {mutated.add(trees.getElement(new TreePath(getCurrentPath(),a.getVariable())));return super.visitAssignment(a,v);}
                @Override public Void visitCompoundAssignment(CompoundAssignmentTree a,Void v) {mutated.add(trees.getElement(new TreePath(getCurrentPath(),a.getVariable())));return super.visitCompoundAssignment(a,v);}
                @Override public Void visitUnary(UnaryTree a,Void v) {if(Set.of(Tree.Kind.PREFIX_INCREMENT,Tree.Kind.POSTFIX_INCREMENT,Tree.Kind.PREFIX_DECREMENT,Tree.Kind.POSTFIX_DECREMENT).contains(a.getKind()))mutated.add(trees.getElement(new TreePath(getCurrentPath(),a.getExpression())));return super.visitUnary(a,v);}
            }.scan(u,null);
            // A byte[] produced by getBytes is mutable. Certify only direct write/length uses;
            // array stores, aliases, mutation helpers and escapes invalidate the proof.
            for(var entry:paths.entrySet()) if(entry.getKey() instanceof IdentifierTree id) {
                Element v=element(id);
                if(v==null || !locals.containsKey(v) || !v.asType().toString().equals("byte[]"))continue;
                TreePath parentPath=entry.getValue().getParentPath();
                Tree parent=parentPath==null?null:parentPath.getLeaf();
                boolean permitted=parent instanceof MemberSelectTree ms && ms.getExpression()==id && ms.getIdentifier().contentEquals("length");
                if(parent instanceof MethodInvocationTree mc && named(mc,"java.io.OutputStream","write(byte[])"))
                    permitted=mc.getArguments().size()==1 && mc.getArguments().get(0)==id;
                if(!permitted)mutated.add(v);
            }
            for(var u:units)new TreeScanner<Void,Void>() {@Override public Void visitMethodInvocation(MethodInvocationTree m,Void v){inspect(m);return super.visitMethodInvocation(m,v);}}.scan(u,null);
        }
        System.out.println(json(obj("schema","NTK_C4_JAVAC_ENCODING_PROOF_V1","source_hashes",hashes,
          "source_application_executed",false,"annotation_processors","DISABLED","findings",results,
          "limits","Straight-line single dynamic slot; exact literal replace chain; fixed HTML text/quoted ordinary attribute; unsupported cases remain review.")));
    }
}
