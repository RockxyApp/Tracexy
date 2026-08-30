# Tracexy Contributor Agreement Policy

## Current agreements

- Individual contributors: [ICLA v1.0](ICLA-v1.0.md)
- Organizations that own or control Contributions:
  [CCLA v1.0](CCLA-v1.0.md) plus an ICLA from each contributor

The ICLA is a broad license, not a copyright assignment. Contributors retain
their copyright. The Project Owner receives transferable and sublicensable
rights needed for the public AGPL source edition and separately licensed
Tracexy distributions. Contributions incorporated into the public source
edition remain available there under its public source license.

## Version and acceptance policy

The ICLA v1.0 document path is immutable. A material change requires a new
versioned document and a new signature store. Acceptance of one version never
counts as acceptance of a later version.

For ICLA v1.0, the exact GitHub acceptance statement is:

> I have read and agree to the Tracexy ICLA v1.0

The version-specific signature store path is `signatures/icla-v1.0.json`. On
the default branch it should be an empty example store; live acceptance records
belong on a dedicated `cla-signatures` branch, never on protected `main` or
`develop`.

Each record should be read together with the versioned document, the signature
comment, the recorded document SHA-256, and the immutable Git commit containing
those exact document bytes. The current document digest is recorded in
[ICLA-v1.0.sha256](ICLA-v1.0.sha256). A CLA gate should fail closed for any
contributor whose acceptance cannot be resolved to the exact agreement version.

## Organizational contributions

An employee must determine whether an employer owns or controls the proposed
Contribution. When it does, an authorized representative must execute the CCLA
and identify the authorized contributors. The executed CCLA and its changes are
kept privately by the Project Owner; the public repository should record only a
non-sensitive reference needed for merge review.

## Legal review note

These agreements are project-maintained legal drafts based on established CLA
structures. They have not been represented as advice from Tracexy's attorney.
Before relying on them for a material transaction, company formation, or a
disputed contribution, the Project Owner should obtain advice for the relevant
jurisdiction and confirm the public contracting identity.
