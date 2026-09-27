# Changelog

## 0.1.0 — 2026-09-26

First reference resolver release for OpenIdentity Protocol v0.1.1.

- Immutable PostgreSQL identity-state and operation history.
- Current-state and exact historical-StateHash resolution.
- Full operation submission: CREATE, ROTATE_CONTROLLER, SET_ASSERTION_POLICY, DEACTIVATE, and RECOVER.
- Canonical operation decoding and transition verification delegated to openidentity-java 0.1.2.
- Controller authorization, proof-of-possession, recovery commitment/reveal, sequence, and predecessor enforcement.
- IdentityState v1/v2 persistence and assertion-authority evolution.
- Normative V02 CREATE and V04 ROTATE_CONTROLLER interoperability.
- End-to-end historical OI-003 credential verification after assertion-key replacement.
- PostgreSQL-backed integration tests and local development lifecycle tools.
