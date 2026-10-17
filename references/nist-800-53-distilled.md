<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->
# NIST SP 800-53 distillation

Source: NIST SP 800-53 rev5, OSCAL catalog oscal-content v1.5.0, public domain.

The nist specialist maps each changed resource or code path in a diff to the rows below and gives PASS, FAIL or N/A per row. Titles are the catalog's; requirements and diff hints are Daedalus's own words. The catalog in the frameworks cache stays the authority for control text.

| Control | Title | Requirement (plain words) | Look for in a diff |
|---|---|---|---|
| AC-2 | Account Management | Every account, role and service identity is created for a named purpose, owned, and removed when the purpose ends. | New users, roles or service accounts; accounts with no owner or expiry; shared or generic identities. |
| AC-3 | Access Enforcement | Every request is checked against an explicit authorization decision before it touches a protected resource. | Handlers or routes without an authorization check; checks done only in the client; allow-by-default branches. |
| AC-4 | Information Flow Enforcement | Data moves only along flows that are declared and enforced, including between tenants and trust zones. | Cross-tenant queries without a tenant key; new egress paths; data copied across accounts, regions or buckets. |
| AC-6 | Least Privilege | Each identity holds only the permissions its task needs, scoped to the resources it touches. | Wildcard actions or resources in policies; admin or root grants; permissions broader than the code path uses. |
| AC-17 | Remote Access | Remote and administrative access goes through an authenticated, encrypted and monitored path. | Open SSH or RDP ports; bastion or console access without MFA; debug endpoints reachable from outside. |
| AU-2 | Event Logging | The system decides which security events it records, and records them. | Auth, authorization, key use and admin actions with no log call; logging disabled on a new resource. |
| AU-3 | Content of Audit Records | Each audit record says what happened, when, where, who did it and what the outcome was. | Log lines missing actor, timestamp, resource or result; free-text logs where a structured record is needed. |
| AU-6 | Audit Record Review, Analysis, and Reporting | Audit records are reviewed and suspicious activity is reported to someone who acts on it. | New log groups with no alarm, metric filter or subscription; findings routed nowhere. |
| AU-9 | Protection of Audit Information | Audit records and logging settings are protected from change and deletion by the identities they record. | Log stores writable or deletable by application roles; missing retention or immutability; logging that the app can turn off. |
| AU-12 | Audit Record Generation | Every component that handles a security event generates the audit record itself. | New services, functions or queues without logging configured; trails or flow logs not enabled. |
| CM-2 | Baseline Configuration | The approved configuration is kept under version control and deployments come from it. | Resources created outside code; manual console steps in docs; drift-prone defaults left implicit. |
| CM-6 | Configuration Settings | Security-relevant settings are set explicitly to their hardened values. | Insecure defaults left in place; TLS, encryption or public-access flags unset; debug modes on. |
| CM-7 | Least Functionality | Only the ports, services, features and packages the system needs are enabled. | New open ports; unused services or packages; broad CORS; features enabled for convenience. |
| IA-2 | Identification and Authentication (Organizational Users) | Staff and operators are uniquely identified and authenticated, with MFA for privileged and network access. | Shared logins; privileged paths without MFA; authentication bypass flags. |
| IA-5 | Authenticator Management | Passwords, keys, tokens and certificates are generated, stored, rotated and revoked safely. | Hardcoded secrets; tokens in config or logs; weak hashing; no rotation or expiry on keys and tokens. |
| IA-8 | Identification and Authentication (Non-organizational Users) | Customers and external callers are uniquely identified and authenticated before they get access. | Anonymous endpoints that return tenant data; API keys with no caller binding; trust in caller-supplied identity headers. |
| SC-7 | Boundary Protection | Traffic crossing a trust boundary passes through a controlled interface that allows only what is declared. | Security groups or firewalls open to 0.0.0.0/0; public subnets for private services; missing WAF or gateway in front of an API. |
| SC-8 | Transmission Confidentiality and Integrity | Data in transit is encrypted and integrity protected, including inside the network. | Plain HTTP; TLS below 1.2; certificate verification turned off; unencrypted internal hops. |
| SC-12 | Cryptographic Key Establishment and Management | Keys are generated, distributed, stored, rotated and destroyed under a defined process, separated per tenant where data is. | Key material in code or env vars; keys shared across tenants; rotation disabled; key policies broader than their users. |
| SC-13 | Cryptographic Protection | Only approved algorithms, modes and key sizes protect data. | MD5, SHA-1, DES or ECB; custom crypto; short keys; random values from a non-cryptographic generator. |
| SC-17 | Public Key Infrastructure Certificates | Certificates come from an approved authority under a defined issuance and revocation policy. | Self-signed certificates in production paths; skipped chain or revocation checks; long-lived certificates with no renewal. |
| SC-28 | Protection of Information at Rest | Stored data is protected, normally by encryption, wherever it rests. | Buckets, databases, volumes, queues or backups without encryption at rest; plaintext sensitive fields. |
| SI-2 | Flaw Remediation | Known flaws are found, fixed and the fix is tested and shipped within a set time. | Pinned dependencies with published advisories; suppressed scanner findings with no tracked reason. |
| SI-4 | System Monitoring | The system is monitored for attacks and unauthorized use, and alerts reach someone. | New entry points with no monitoring; detection services disabled; alerts with no destination. |
| SI-10 | Information Input Validation | Input is validated for type, length, range and format at the point it enters. | Unvalidated request fields; string-built SQL, shell or paths; unsafe deserialization of caller data. |
| SA-11 | Developer Testing and Evaluation | Changes ship with security tests and analysis whose findings are fixed or tracked. | Security-relevant code without tests; scanners removed from CI; tests weakened to pass. |
| SA-15 | Development Process, Standards, and Tools | Development follows a documented process with defined standards and pinned tools. | Unpinned build tools or actions; process steps skipped; standards sources not declared. |
