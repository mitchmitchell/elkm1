# Testing Decision Records (TDRs)

Purpose

Testing Decision Records (TDRs) document binding decisions about testing,
verification, and validation strategy for this project.

They serve the same role for testing that:
- ADRs serve for architecture
- DDRs serve for development and implementation

TDRs answer the question:

“How do we prove the system works, and how do we keep it working?”

Scope

TDRs apply to:
- Test structure and responsibilities
- Required test artifacts and evidence
- CI integration strategy
- Live hardware testing policies
- Debugging and diagnostics requirements

TDRs do not:
- Specify architecture (ADR responsibility)
- Specify implementation details (DDR responsibility)
- Contain executable code

When a TDR Is Required

A TDR MUST be written when a decision:
- Affects how correctness is validated
- Changes required test outputs or artifacts
- Introduces or restricts live hardware testing
- Impacts CI behavior or artifact retention
- Would otherwise be re-debated or rediscovered later

Relationship to ADRs and DDRs

Record Type | Focus
ADR         | What is built and why
DDR         | How it is implemented
TDR         | How correctness is verified and preserved

TDRs may reference ADRs and DDRs.
ADRs and DDRs may reference TDRs when testing implications are significant.

Structure

Each TDR follows this structure:

TDR-XXXX: <Title>
Status: Accepted | Proposed | Deprecated
Date: YYYY-MM-DD
Applies to: <Scope>

Context
Decision
Rationale
Consequences
References

Once a TDR is Accepted, it is considered binding unless explicitly
superseded by a newer TDR.

Current TDRs

TDR-0001: E27 Test Evidence Capture Contract  
TDR-0002: Test Artifact Formats and CI Integration  
TDR-0003: Dual-Format Test Reporting (JSONL and YAML)  
TDR-0004: Live Hardware Testing Policy for E27  

Guiding Principle

“A failure that cannot be diagnosed from its artifacts is a failed test.”

All tests should be written with this principle in mind.
