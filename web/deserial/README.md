# Deserialization Vulnerabilities

## Introduction

Deserialization vulnerabilities occur when untrusted data is used to reconstruct objects in memory, potentially allowing attackers to execute arbitrary code, manipulate application logic, or perform other malicious actions. In Java applications, insecure deserialization is a critical security concern, particularly when handling serialized objects from untrusted sources.

## Resources

### OWASP Stuttgart - Exploiting Deserialization Vulnerabilities

An excellent comprehensive resource on exploiting deserialization vulnerabilities in recent Java versions:

- **Title**: Exploiting Deserialization Vulnerabilities in Recent Java Versions
- **Source**: OWASP Stuttgart Chapter
- **Date**: December 10, 2024
- **Link**: [PDF Presentation](https://owasp.org/www-chapter-stuttgart/assets/slides/2024-12-10_Exploiting_deserialization_vulnerabilities_in_recent_Java_versions.pdf)

This presentation covers modern techniques for exploiting Java deserialization flaws, including:

- Understanding Java serialization mechanisms
- Gadget chains and how they work
- Exploitation techniques for recent Java versions
- Defense mechanisms and mitigations

## Key Concepts

Java deserialization attacks typically rely on:

- **Gadget Chains**: Sequences of method calls that can be triggered during deserialization
- **Magic Methods**: Special methods like `readObject()` that are automatically invoked
- **Library Dependencies**: Common libraries (Apache Commons, Spring, etc.) that contain exploitable gadgets

## Common Tools

- **ysoserial**: Java deserialization payload generator
- **Java Unmarshaller Security**: Tools for testing deserialization endpoints

## Reference

- [finding gadgets like its 2022](https://www.synacktiv.com/publications/finding-gadgets-like-its-2022.html)
