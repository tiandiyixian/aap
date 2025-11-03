package io.shiftleft.dataflowengine {
  package object language extends io.joern.dataflowengineoss.language
}

import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.{Call, Identifier, Literal, Method, Return, StoredNode}
import io.joern.dataflowengineoss.language._
import io.shiftleft.semanticcpg.language._
import overflowdb.traversal.Traversal

case class RuleMetadata(
    id: String,
    title: String,
    cwe: Option[String],
    severity: String,
    description: String
)

case class Finding(ruleId: String, message: String, evidence: StoredNode, flow: Option[List[StoredNode]] = None)

trait JoernRule {
  def metadata: RuleMetadata

  def apply(cpg: Cpg): List[Finding]
}

object RuleDsl {
  implicit class StoredNodeOps(node: StoredNode) {
    def codeSnippet: String = node match {
      case call: Call        => call.code
      case ident: Identifier => ident.name
      case lit: Literal      => lit.code
      case method: Method    => method.signature
      case ret: Return       => ret.code
      case _                 => node.code
    }
  }

  def taintedArgv(cpg: Cpg): Traversal[StoredNode] =
    cpg.identifier
      .nameExact("argv")
      .cast[StoredNode]

  def taintedParameters(cpg: Cpg, keywords: String*): Traversal[StoredNode] = {
    if (keywords.isEmpty) {
      Traversal.from(List.empty[StoredNode])
    } else {
      val keywordRegex = keywords.mkString("(", "|", ")")
      cpg.method.parameter
        .filter(param => param.name.matches(s"(?i).*$keywordRegex.*"))
        .cast[StoredNode]
    }
  }

  def unionTraversals(traversals: Traversal[StoredNode]*): Traversal[StoredNode] = {
    val combined = traversals.toList.flatMap(_.l)
    Traversal.from(combined)
  }

  def formatFlow(flow: List[StoredNode]): String = {
    flow.map(_.codeSnippet).mkString(" -> ")
  }
}

import RuleDsl._

object UnsafeBufferCopyRule extends JoernRule {
  override val metadata: RuleMetadata = RuleMetadata(
    id = "C001",
    title = "Unsafe unbounded buffer copy",
    cwe = Some("CWE-120"),
    severity = "HIGH",
    description = "Detects calls to inherently unsafe string copy APIs writing into fixed-size buffers without bounds checks."
  )

  private val unsafeFunctions = "(strcpy|strcat|sprintf|vsprintf|gets)"

  override def apply(cpg: Cpg): List[Finding] = {
    val unsafeCalls = cpg.call
      .name(unsafeFunctions)
      .map { call =>
        Finding(
          metadata.id,
          s"Call to unsafe function '${call.name}' may overflow destination buffer",
          call
        )
      }
      .l

    val taintedSources = unionTraversals(
      cpg.call
        .name("(recv|read|fgets|gets|scanf|strcpy|strncpy|strcat)")
        .argument(1)
        .cast[StoredNode],
      taintedArgv(cpg)
    )

    val lengthControlledSinks = cpg.call
      .name("(memcpy|memmove|strncpy|snprintf)")
      .argument(3)

    val flows = lengthControlledSinks.reachableByFlows(taintedSources)
      .map { path =>
        val sinkCall = path.elements.last.node match {
          case call: Call => call
          case other      => other.parentExpression.collectFirst { case c: Call => c }.getOrElse(other)
        }
        Finding(
          metadata.id,
          s"User-controlled length influences '${sinkCall.codeSnippet}', risking overflow",
          sinkCall,
          Some(path.elements.map(_.node.asInstanceOf[StoredNode]))
        )
      }
      .l

    (unsafeCalls ++ flows).distinct
  }
}

object ArrayIndexTaintRule extends JoernRule {
  override val metadata: RuleMetadata = RuleMetadata(
    id = "C002",
    title = "Tainted array index",
    cwe = Some("CWE-129"),
    severity = "HIGH",
    description = "Flags tainted index expressions used in array accesses without guarding range checks."
  )

  override def apply(cpg: Cpg): List[Finding] = {
    val indexSources = unionTraversals(
      cpg.call
        .name("(recv|read|fgets|scanf|atoi|strtol)")
        .argument(1)
        .cast[StoredNode],
      taintedArgv(cpg)
    )

    val indexSinks = cpg.call.name("<operator>.indexAccess").argument(2)

    val flows = indexSinks.reachableByFlows(indexSources).map { path =>
      val indexNode = path.elements.last.node.asInstanceOf[StoredNode]
      val arrayAccess = indexNode.parentExpression.collectFirst { case c: Call => c }
      arrayAccess.map { call =>
        Finding(
          metadata.id,
          s"Tainted index '${indexNode.codeSnippet}' used in array access '${call.codeSnippet}'",
          call,
          Some(path.elements.map(_.node.asInstanceOf[StoredNode]))
        )
      }
    }.l.flatten

    flows.distinct
  }
}

object NullPointerDereferenceRule extends JoernRule {
  override val metadata: RuleMetadata = RuleMetadata(
    id = "C003",
    title = "Potential NULL dereference",
    cwe = Some("CWE-476"),
    severity = "MEDIUM",
    description = "Identifies dereferences of pointers returned from nullable APIs without preceding null-checks."
  )

  private val nullableFactories = "(malloc|calloc|realloc|fopen|freopen|dlsym|dlopen|LoadLibrary)"

  override def apply(cpg: Cpg): List[Finding] = {
    val nullableCalls = cpg.call.name(nullableFactories)

    val pointerDerefs = cpg.call.name("(<operator>.indirection|<operator>.fieldAccess|<operator>.indexAccess)")

    val flows = pointerDerefs.reachableByFlows(nullableCalls).flatMap { path =>
      val deref = path.elements.last.node.parentExpression.collectFirst { case c: Call => c }
      deref.map { derefCall =>
        val ptrExpr = path.elements.head.node.asInstanceOf[StoredNode]
        val guarded = derefCall.controlStructure.isCondition.exists { cond =>
          val code = cond.code
          val ptrCode = ptrExpr.codeSnippet
          code.contains(s"$ptrCode != NULL") || code.contains(s"$ptrCode == NULL")
        }
        if (!guarded) {
          Some(
            Finding(
              metadata.id,
              s"Pointer '${ptrExpr.codeSnippet}' from nullable allocation used without null-check",
              derefCall,
              Some(path.elements.map(_.node.asInstanceOf[StoredNode]))
            )
          )
        } else None
      }
    }.l.flatten

    flows.distinct
  }
}

object DoubleFreeRule extends JoernRule {
  override val metadata: RuleMetadata = RuleMetadata(
    id = "C004",
    title = "Double free detection",
    cwe = Some("CWE-415"),
    severity = "HIGH",
    description = "Detects multiple invocations of free/delete on the same pointer without re-allocation."
  )

  private val freeNames = "(free|delete|delete\\[\\])"

  override def apply(cpg: Cpg): List[Finding] = {
    val freesByPtr = cpg.call
      .name(freeNames)
      .flatMap { call =>
        call.argument(1).code.l.headOption.map(_ -> call)
      }
      .groupBy(_._1)

    freesByPtr.collect {
      case (ptr, calls) if calls.size > 1 =>
        calls.tail.map { case (_, call) =>
          Finding(
            metadata.id,
            s"Pointer '$ptr' is freed multiple times",
            call
          )
        }
    }.flatten.toList
  }
}

object UseAfterFreeRule extends JoernRule {
  override val metadata: RuleMetadata = RuleMetadata(
    id = "C005",
    title = "Use-after-free",
    cwe = Some("CWE-416"),
    severity = "HIGH",
    description = "Finds dereferences of pointers after they have been freed."
  )

  private val freePattern = "(free|delete|delete\\[\\])"

  override def apply(cpg: Cpg): List[Finding] = {
    val freeTargets = cpg.call.name(freePattern).argument(1)

    val derefSinks = cpg.call.name("(<operator>.indirection|<operator>.fieldAccess|<operator>.indexAccess)")

    val flows = derefSinks.reachableByFlows(freeTargets).map { path =>
      val derefCall = path.elements.last.node.parentExpression.collectFirst { case c: Call => c }
      Finding(
        metadata.id,
        s"Pointer '${path.elements.head.node.asInstanceOf[StoredNode].codeSnippet}' used after free",
        derefCall.getOrElse(path.elements.last.node.asInstanceOf[StoredNode]),
        Some(path.elements.map(_.node.asInstanceOf[StoredNode]))
      )
    }.l

    flows.distinct
  }
}

object FormatStringRule extends JoernRule {
  override val metadata: RuleMetadata = RuleMetadata(
    id = "C006",
    title = "Untrusted format string",
    cwe = Some("CWE-134"),
    severity = "HIGH",
    description = "Detects flows of tainted data into the format argument of printf-like functions."
  )

  private val formatFunctions = "(printf|fprintf|sprintf|snprintf|syslog|vprintf|vsnprintf)"

  override def apply(cpg: Cpg): List[Finding] = {
    val taintedSources = unionTraversals(
      cpg.call
        .name("(recv|read|fgets|gets|scanf)")
        .argument(1)
        .cast[StoredNode],
      taintedArgv(cpg)
    )

    val formatArguments = cpg.call
      .name(formatFunctions)
      .argument(1)

    val flows = formatArguments.reachableByFlows(taintedSources).map { path =>
      val callOpt = path.elements.last.node.parentExpression.collectFirst { case c: Call => c }
      val callNode = callOpt.map(_.asInstanceOf[StoredNode]).getOrElse(path.elements.last.node.asInstanceOf[StoredNode])
      Finding(
        metadata.id,
        s"Tainted data reaches format argument in '${callNode.codeSnippet}'",
        callNode,
        Some(path.elements.map(_.node.asInstanceOf[StoredNode]))
      )
    }.l

    val nonLiteralFormats = cpg.call
      .name(formatFunctions)
      .argument(1)
      .filterNot(arg => arg.isLiteral.nonEmpty)
      .map { arg =>
        val parent = arg.parentExpression.collectFirst { case c: Call => c }.getOrElse(arg.asInstanceOf[StoredNode])
        Finding(
          metadata.id,
          s"Non-literal format string in '${parent.codeSnippet}'",
          parent.asInstanceOf[StoredNode]
        )
      }
      .l

    (flows ++ nonLiteralFormats).distinct
  }
}

object CommandInjectionRule extends JoernRule {
  override val metadata: RuleMetadata = RuleMetadata(
    id = "C007",
    title = "Command injection",
    cwe = Some("CWE-78"),
    severity = "CRITICAL",
    description = "Tracks tainted inputs flowing into command execution APIs."
  )

  private val execFunctions = "(system|popen|execl|execlp|execle|execv|execvp|CreateProcessA|CreateProcessW)"

  override def apply(cpg: Cpg): List[Finding] = {
    val taintedSources = unionTraversals(
      cpg.call
        .name("(recv|read|fgets|gets|scanf|getenv|getline)")
        .argument(1)
        .cast[StoredNode],
      taintedArgv(cpg),
      taintedParameters(cpg, "cmd", "command", "input")
    )

    val execArgs = cpg.call
      .name(execFunctions)
      .argument
      .filterNot(arg => arg.argumentIndex == 1 && arg.isLiteral.nonEmpty)

    val flows = execArgs.reachableByFlows(taintedSources).map { path =>
      val callOpt = path.elements.last.node.parentExpression.collectFirst { case c: Call => c }
      val call = callOpt.map(_.asInstanceOf[StoredNode]).getOrElse(path.elements.last.node.asInstanceOf[StoredNode])
      Finding(
        metadata.id,
        s"User input flows into command execution '${call.codeSnippet}'",
        call,
        Some(path.elements.map(_.node.asInstanceOf[StoredNode]))
      )
    }.l

    flows.distinct
  }
}

object PathTraversalRule extends JoernRule {
  override val metadata: RuleMetadata = RuleMetadata(
    id = "C008",
    title = "Path traversal",
    cwe = Some("CWE-22"),
    severity = "HIGH",
    description = "Detects user-controlled file paths reaching filesystem APIs without sanitization."
  )

  private val fileApis = "(open|fopen|ifstream|ofstream|stat|mkdir|unlink|remove)"

  override def apply(cpg: Cpg): List[Finding] = {
    val taintedSources = unionTraversals(
      cpg.call
        .name("(recv|read|fgets|gets|scanf|getenv)")
        .argument(1)
        .cast[StoredNode],
      taintedArgv(cpg),
      taintedParameters(cpg, "path", "file", "filename")
    )

    val fileArgs = cpg.call
      .name(fileApis)
      .argument(1)

    val flows = fileArgs.reachableByFlows(taintedSources).map { path =>
      val callOpt = path.elements.last.node.parentExpression.collectFirst { case c: Call => c }
      val call = callOpt.map(_.asInstanceOf[StoredNode]).getOrElse(path.elements.last.node.asInstanceOf[StoredNode])
      Finding(
        metadata.id,
        s"Tainted path '${path.elements.last.node.asInstanceOf[StoredNode].codeSnippet}' used in file API '${call.codeSnippet}'",
        call,
        Some(path.elements.map(_.node.asInstanceOf[StoredNode]))
      )
    }.l

    flows.distinct
  }
}

object ResourceLeakRule extends JoernRule {
  override val metadata: RuleMetadata = RuleMetadata(
    id = "C009",
    title = "Resource leak",
    cwe = Some("CWE-772"),
    severity = "MEDIUM",
    description = "Highlights resources acquired without guaranteed release on all exit paths."
  )

  private val allocApis = "(fopen|open|socket|malloc|calloc|realloc|pthread_mutex_init)"
  private val releaseMap = Map(
    "fopen" -> "fclose",
    "open" -> "close",
    "socket" -> "close",
    "malloc" -> "free",
    "calloc" -> "free",
    "realloc" -> "free",
    "pthread_mutex_init" -> "pthread_mutex_destroy"
  )

  override def apply(cpg: Cpg): List[Finding] = {
    val acquisitions = cpg.call.name(allocApis)

    acquisitions.flatMap { call =>
      val targetVar = call.parentExpression.collectFirst { case assign: Call if assign.name == "<operator>.assignment" =>
        assign.argument(1).code.l.headOption
      }.flatten.getOrElse(call.codeSnippet)

      val releaseCandidate = releaseMap.getOrElse(call.name, "")

      val hasRelease = releaseCandidate.nonEmpty && cpg.method
        .fullNameExact(call.methodFullName)
        .call
        .name(releaseCandidate)
        .argument
        .codeExact(targetVar)
        .nonEmpty

      if (!hasRelease) {
        Some(
          Finding(
            metadata.id,
            s"Resource from '${call.codeSnippet}' may leak without '${releaseCandidate}'",
            call
          )
        )
      } else None
    }.l.distinct
  }
}

object HardcodedSecretRule extends JoernRule {
  override val metadata: RuleMetadata = RuleMetadata(
    id = "C010",
    title = "Hardcoded secret literal",
    cwe = Some("CWE-798"),
    severity = "MEDIUM",
    description = "Detects suspicious string literals that look like secrets embedded in the binary."
  )

  private val secretPattern = "(?i)(password|passwd|api[_-]?key|secret|token|aws|private[_-]?key)"

  override def apply(cpg: Cpg): List[Finding] = {
    cpg.literal
      .code(secretPattern)
      .map { lit =>
        Finding(
          metadata.id,
          s"Literal '${lit.codeSnippet}' resembles a hardcoded secret",
          lit
        )
      }
      .l
  }
}

object CppSecurityRuleSet {
  val rules: List[JoernRule] = List(
    UnsafeBufferCopyRule,
    ArrayIndexTaintRule,
    NullPointerDereferenceRule,
    DoubleFreeRule,
    UseAfterFreeRule,
    FormatStringRule,
    CommandInjectionRule,
    PathTraversalRule,
    ResourceLeakRule,
    HardcodedSecretRule
  )

  def runAll()(implicit cpg: Cpg): List[Finding] = {
    rules.flatMap { rule =>
      val findings = rule.apply(cpg)
      if (findings.nonEmpty) {
        println(s"[${rule.metadata.id}] ${rule.metadata.title} -> ${findings.size} findings")
      } else {
        println(s"[${rule.metadata.id}] ${rule.metadata.title} -> no findings")
      }
      findings
    }
  }

  def report(findings: List[Finding]): Unit = {
    findings.groupBy(_.ruleId).foreach { case (ruleId, ruleFindings) =>
      val header = rules.find(_.metadata.id == ruleId).map(_.metadata).get
      println(s"\n== ${header.id} | ${header.title} | severity=${header.severity} | CWE=${header.cwe.getOrElse("-")} ==")
      println(header.description)
      ruleFindings.foreach { finding =>
        println(s"  - ${finding.message}")
        println(s"    evidence: ${finding.evidence.codeSnippet}")
        finding.flow.foreach { nodes =>
          println(s"    flow: ${formatFlow(nodes)}")
        }
      }
    }
  }
}

// Usage example inside joern console:
// import io.shiftleft.codepropertygraph.generated.Cpg
// val findings = CppSecurityRuleSet.runAll()(cpg)
// CppSecurityRuleSet.report(findings)
