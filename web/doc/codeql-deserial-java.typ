#import "@preview/touying:0.6.1": *
#import themes.simple: *
#import "@preview/cetz:0.3.2"
#import "@preview/fletcher:0.5.5" as fletcher: edge, node
#import "@preview/numbly:0.1.0": numbly
#import "@preview/theorion:0.3.2": *
#import cosmos.clouds: *
#show: show-theorion

// Link styling - blue with underline
#show link: it => underline(text(fill: blue, it))

// cetz and fletcher bindings for touying
#let cetz-canvas = touying-reducer.with(reduce: cetz.canvas, cover: cetz.draw.hide.with(bounds: true))
#let fletcher-diagram = touying-reducer.with(reduce: fletcher.diagram, cover: fletcher.hide)

// Color shorthand functions
#let redt(content) = text(fill: red, content)
#let bluet(content) = text(fill: blue, content)
#let greent(content) = text(fill: green, content)
#let yellowt(content) = text(fill: yellow, content)
#let oranget(content) = text(fill: orange, content)
#let purplet(content) = text(fill: purple, content)
#let greyt(content) = text(fill: gray, content)
#let grayt(content) = text(fill: gray, content)

#show: simple-theme.with(aspect-ratio: "16-9", footer: [Finding Java Deserialization Gadgets with CodeQL])

#title-slide[
  = Finding Java Deserialization Gadgets with CodeQL
  == Automating Security Analysis for Gadget Chain Discovery
  #v(1em)

  isomo #footnote[github/jiahaoxiang2000]

  #v(1em)
  #datetime.today().display()
]

= Background

== What is Java Deserialization?

*Java Serialization* converts objects to byte streams for storage or transmission

#pause

```java
ObjectOutputStream out = new ObjectOutputStream(fileOut);
out.writeObject(myObject);  // Serialize
```

#pause

*Java Deserialization* reconstructs objects from byte streams

```java
ObjectInputStream in = new ObjectInputStream(fileIn);
MyClass obj = (MyClass) in.readObject();  // Deserialize
```

#pause

#redt[*Security Issue:*] Untrusted data can trigger #redt[arbitrary code execution]


== The Gadget Chain Concept

A #bluet[*gadget chain*] is a sequence of method calls that leads from a safe entry point to a dangerous operation

#pause

#fletcher-diagram(
  node-stroke: .1em,
  node-fill: gradient.radial(blue.lighten(80%), blue, center: (30%, 20%), radius: 80%),
  spacing: 2em,
  edge((0, 0), "r", "-|>", `readObject()`, label-pos: 0, label-side: center),
  node((1, 0), `Source`, radius: 2em),
  pause,
  edge(`G1`, "-|>"),
  node((2, 0), `Chain`, radius: 2em),
  pause,
  edge(`G2`, "-|>"),
  node((3, 0), `Chain`, radius: 2em),
  pause,
  edge(`exec()`, "-|>"),
  node((5, 0), [#redt[*Sink*]], radius: 2em),
)

#pause

- Leverages #oranget[existing classes] on the classpath
- No need to inject new code - just arranges existing functionality
- Property-Oriented Programming (POP)


== Why This Matters


*Critical Security Impact:*

- CVSS scores often #redt[9.0+ (Critical)]
- Remote Code Execution (RCE) without authentication

#pause

*Wide Attack Surface:*

- Java RMI (Remote Method Invocation)
- JMX (Java Management Extensions)
- Message queues (JMS, Spring AMQP)
- Web frameworks (Spring, Struts)


== Famous Vulnerabilities


*Apache Commons Collections*
- CVE-2015-7450, CVE-2015-7501
- InvokerTransformer gadget
- #redt[CVSS: 9.8 Critical]


#pause

*Spring Framework*
- CVE-2016-1000027 - HttpInvoker
- CVE-2023-34040 - Spring-Kafka
- Multiple gadget chains discovered


== The Challenge


*Manual Analysis is Hard:*

#pause

- Large codebases with thousands of classes
- Reflection-based method invocations

#pause

*Traditional Tools:*

#pause

- `ysoserial` - Payload generator (requires known gadgets)
- Manual code review (time-consuming, error-prone)
- Dynamic testing (limited coverage)

#pause

#bluet[*Solution: CodeQL - Automated semantic code analysis*]


= CodeQL Introduction

== What is CodeQL?

*A semantic code analysis engine by GitHub*

#pause

- Treats #bluet[code as data] - creates queryable database
- Uses #greent[declarative query language] (similar to SQL/Datalog)
- Performs deep #oranget[semantic analysis], not just pattern matching

#pause

```ql
from MethodAccess call
where call.getMethod().hasName("readObject")
select call, "Potential deserialization"
```

#pause

*Think of it as:* SQL for code, but with understanding of program semantics


== Key Capabilities


*1. Data Flow Analysis*
- Track how data moves through the program
- Identify sources (input) and sinks (dangerous operations)


*2. Taint Tracking*
- Follow untrusted data from entry points to sensitive operations
- Understand data transformations

#pagebreak()

*3. Control Flow Analysis*
- Understand execution paths
- Identify reachable code

*4. Cross-Project Analysis*
- Analyze entire dependency trees
- Find vulnerabilities in third-party libraries


== CodeQL Architecture

*Three-Step Process:*

#pause

1. #bluet[*Create Database*] - Extract semantic information from source code

```bash
codeql database create myapp-db --language=java
```

#pause

2. #greent[*Write/Run Queries*] - Query the database for patterns

```bash
codeql database analyze myapp-db query.ql
```

#pause

3. #oranget[*Analyze Results*] - Review findings and validate

```bash
# Results in SARIF format for integration
```

= CodeQL for Deserialization

== Built-in Deserialization Detection


CodeQL includes #bluet[`java/unsafe-deserialization`] query


```ql
/**
 * @name Unsafe deserialization
 * @description Deserializing user-controlled data may allow
 *              attackers to execute arbitrary code
 * @kind path-problem
 * @id java/unsafe-deserialization
 */
import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.UnsafeDeserializationQuery
```


== Understanding Sources and Sinks

#only(1)[
  *Source:* Where untrusted data enters the system

  ```ql
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
    // HTTP requests, socket input, etc.
  }
  ```
]

#only(2)[
  *Sink:* Dangerous operation that should not receive untrusted data

  ```ql
  predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      ma.getMethod().hasName("readObject") and
      ma.getMethod().getDeclaringType()
        .hasQualifiedName("java.io", "ObjectInputStream") and
      sink.asExpr() = ma.getQualifier()
    )
  }
  ```
]


== Taint Tracking Configuration



```ql
import java
import semmle.code.java.dataflow.TaintTracking
module DeserializationConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource}
  predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      ma.getMethod().hasName("readObject") and
      sink.asExpr() = ma.getQualifier()
    )}}
```


== Finding Gadget Chains


*QLinspector* - Advanced CodeQL queries by Synacktiv


GitHub: #link("https://github.com/synacktiv/QLinspector")[github.com/synacktiv/QLinspector]

#pause

*Available Queries:*


- `QLinspector.ql` - Main gadget chain finder
- `BeanFactoryGadgetFinder.ql` - JNDI injection chains
- `CommonsBeanutilsGadgetFinder.ql` - Alternative gadgets
- `ObjectFactoryFinder.ql` - BeanFactory alternatives



== QLinspector Usage


*Step 1: Create CodeQL Database*

```bash
codeql database create target-app-db --language=java
```

*Step 2: Run QLinspector Query*

```bash
codeql database analyze target-app-db \
  --format=sarif-latest \
  --output=results.sarif \
  ./QLinspector/QLinspector.ql
```

*Step 3: Review Results*


== Finding Runtime.exec Sinks

*Track execution sinks reachable from deserialization:*

```ql
import java
class RuntimeExecCall extends MethodAccess {
  RuntimeExecCall() {
    this.getMethod().hasName("exec") and
    this.getMethod().getDeclaringType()
      .hasQualifiedName("java.lang", "Runtime")
  }
}
```

#pagebreak()

```ql
from RuntimeExecCall exec
where exists(Method m |
  m.hasName("readObject") and
  exec.getEnclosingCallable().calls*(m)
)
select exec, "Potential gadget chain to Runtime.exec"
```


= Real Example: CommonsCollections1

== The CommonsCollections1 Gadget Chain

#fletcher-diagram(
  node-stroke: .08em,
  spacing: (2em, 1em),
  node((0, 0), [`ObjectInputStream.readObject()`], shape: rect),
  edge((0, 0), (0, 1), "-|>", `magic method`),
  node((0, 1), [`AnnotationInvocationHandler.readObject()`], shape: rect),
  edge((0, 1), (0, 2), "-|>", `memberValues.entrySet()`),
  node((0, 2), [`LazyMap.get()`], shape: rect),
  edge((0, 2), (0, 3), "-|>", `factory.transform()`),
  node((0, 3), [`ChainedTransformer.transform()`], shape: rect),
  edge((0, 3), (0, 4), "-|>", `iTransformers[i].transform()`),
  node((0, 4), [`InvokerTransformer.transform()`], shape: rect),
  edge((0, 4), (0, 5), "-|>", `method.invoke()`),
  node((0, 5), [#redt[`Runtime.getRuntime().exec("cmd")`]], shape: rect),
)


== The Gadget Chain Explained


*Step 1:* Deserialize malicious `AnnotationInvocationHandler`

*Step 2:* `readObject()` iterates over `memberValues` (a `LazyMap`)

*Step 3:* `LazyMap.get()` calls `factory.transform()` on missing keys

*Step 4:* `ChainedTransformer` chains multiple transformations

*Step 5:* `InvokerTransformer` uses reflection to call methods

*Step 6:* Chain leads to `Runtime.getRuntime().exec()`



== CodeQL Query for CommonsCollections1

```ql
import java
import semmle.code.java.dataflow.TaintTracking

class CommonsCollectionsGadget extends TaintTracking::Configuration {
  CommonsCollectionsGadget() { this = "CommonsCollectionsGadget" }

  override predicate isSource(DataFlow::Node source) {
    exists(Method m |
      m.hasName("readObject") and
      m.getDeclaringType().hasQualifiedName("java.io",
                                            "ObjectInputStream") and
      source.asParameter() = m.getAParameter()
    )
  }
  override predicate isSink(DataFlow::Node sink) {
    exists(MethodAccess ma |
      ma.getMethod().hasName("exec") and
      ma.getMethod().getDeclaringType()
        .hasQualifiedName("java.lang", "Runtime") and
      sink.asExpr() = ma.getAnArgument()
    )
  }

  override predicate isAdditionalTaintStep(
    DataFlow::Node node1, DataFlow::Node node2
  ) {
    // Track through InvokerTransformer.transform()
    exists(MethodAccess ma |
      ma.getMethod().hasName("transform") and
      node1.asExpr() = ma.getQualifier() and
      node2.asExpr() = ma
    )
  }
}
```

= Practical Workflow

== Complete Analysis Workflow


*1. Reconnaissance*
- Identify Java applications in scope
- Check dependencies (pom.xml, build.gradle)

#pause

*2. Database Creation*
```bash
codeql database create app-db --language=java \
  --command="mvn clean compile"
```

#pause

*3. Query Selection*
- Run QLinspector for gadget discovery
- Custom queries for specific patterns


#pagebreak()

*4. Analysis*
```bash
codeql database analyze app-db \
  codeql/java-queries:Security \
```

#pause

*5. Validation*
- Review identified paths
- Check if gadget chain is exploitable

= Learning Resources

== Official CodeQL Resources

*Documentation & Guides:*

- #link("https://codeql.github.com/docs/")[CodeQL Documentation] - Comprehensive reference
- #link("https://codeql.github.com/docs/codeql-language-guides/codeql-for-java/")[CodeQL for Java] - Java-specific guide
- #link("https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-java/")[Data Flow Analysis] - Taint tracking guide

#pause

*Learning Series:*

- #link("https://github.blog/developer-skills/github/codeql-zero-to-hero-part-1-the-fundamentals-of-static-analysis-for-vulnerability-research/")[Zero to Hero Part 1] - Fundamentals
- #link("https://github.blog/2023-06-15-codeql-zero-to-hero-part-2-getting-started-with-codeql/")[Zero to Hero Part 2] - Getting started
- #link("https://github.blog/security/vulnerability-research/codeql-zero-to-hero-part-3-security-research-with-codeql/")[Zero to Hero Part 3] - Security research


== Java Deserialization Resources

*Essential Reading:*

- #link("https://www.synacktiv.com/en/publications/finding-gadgets-like-its-2015-part-1")[Synacktiv: Finding Gadgets Part 1 & 2] - Deep dive into gadget discovery
- #link("https://www.synacktiv.com/en/publications/finding-gadgets-like-its-2022")[Synacktiv: Finding Gadgets 2022] - Modern techniques
- #link("https://github.com/frohoff/ysoserial")[ysoserial] - Essential payload generator tool

#pause

*Tutorials & Guides:*

- #link("https://portswigger.net/web-security/deserialization/exploiting")[PortSwigger Web Security Academy] - Interactive learning
- #link("https://medium.com/@dub-flow/deserialization-what-the-heck-actually-is-a-gadget-chain-1ea35e32df69")[Understanding Gadget Chains] - Beginner-friendly


== Advanced Resources

*Research & Tools:*

- #link("https://github.com/synacktiv/QLinspector")[QLinspector] - CodeQL queries for gadget finding
- #link("https://securitylab.github.com/research/insecure-deserialization/")[GitHub Security Lab Research] - Real vulnerability findings
- #link("https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet")[Java Deserialization Cheat Sheet] - Comprehensive catalog

#pause

*Community Resources:*

- #link("https://github.com/advanced-security/awesome-codeql")[Awesome CodeQL] - Curated resource list
- #link("https://github.com/GitHubSecurityLab/codeql-zero-to-hero")[CodeQL Zero to Hero Exercises] - Hands-on challenges


= Conclusion

== Key Takeaways


*1. Deserialization is Critical*
- CVSS scores typically 9.0+
- Wide attack surface in enterprise Java
- Affects many popular frameworks


*2. CodeQL Enables Automation*
- Scales to millions of lines of code
- Finds complex gadget chains automatically
- Low false positive rate with proper queries


== Questions?


*Thank you for your attention!*

#v(1em)

*Resources:*
- GitHub: #link("https://github.com/github/codeql")[github/codeql]
- QLinspector: #link("https://github.com/synacktiv/QLinspector")[synacktiv/QLinspector]
- ysoserial: #link("https://github.com/frohoff/ysoserial")[frohoff/ysoserial]

#v(2em)

#align(center)[
  #text(size: 1.2em)[
    #bluet[Happy Hunting! 🔍]
  ]
]

