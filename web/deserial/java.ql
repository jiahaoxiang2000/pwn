/**
 * @name Basic ObjectInputStream Detection
 * @description Detects all calls to ObjectInputStream.readObject()
 * @kind problem
 * @problem.severity warning
 * @id java/unsafe-deserialization
 */

import java
import semmle.code.java.Member

class ObjectInputStreamReadObject extends Method {
  ObjectInputStreamReadObject() {
    this.getDeclaringType().hasQualifiedName("java.io", "ObjectInputStream") and
    this.hasName("readObject")
  }
}

from Call call
where call.getCallee() instanceof ObjectInputStreamReadObject
select call, "Potentially unsafe deserialization via ObjectInputStream.readObject()"
