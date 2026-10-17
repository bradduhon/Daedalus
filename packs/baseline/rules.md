<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->
# Daedalus baseline pack

Opt-in: these rules apply only to a project that declares `{"kind": "pack", "name": "baseline"}` in `standards_sources`.
Written in Daedalus's own words; each `Maps:` cites NIST SP 800-53 rev5 control ids and OWASP ASVS 5.0.0 requirement ids, never their text.
CIS section numbers are cited only after a check against a licensed CIS copy; none are cited yet.

## Baseline

- DB-1: Secrets, tokens, passwords and private keys never appear in source, config files or commit history; code reads them at run time from a secret store. Maps: NIST IA-5(7), SC-12; ASVS V13.3.1
- DB-2: Access policies name the exact actions and resources a principal needs; a wildcard in an action or resource field is a violation. Maps: NIST AC-3, AC-6; ASVS V8.2.1, V8.2.2
- DB-3: Every network connection that carries data uses TLS 1.2 or newer with certificate validation on, and never falls back to plaintext. Maps: NIST SC-8, SC-8(1), SC-13; ASVS V12.1.1, V12.3.1, V12.3.2
- DB-4: Every data store, queue, volume, snapshot and backup is encrypted at rest. Maps: NIST SC-28, SC-28(1); ASVS V14.2.4
- DB-5: Logs never hold personal data, credentials or key material; such fields are masked or dropped before the record is written. Maps: NIST AU-3(3); ASVS V16.2.5

## Cloud security standards

- DC-1: Each workload runs under its own role, granted only the permissions that workload uses; services never share a role. Maps: NIST AC-2, AC-5, AC-6
- DC-2: Object storage blocks public access at the account and bucket level; sharing goes through named principals or signed links that expire. Maps: NIST AC-3, AC-22; ASVS V8.2.2
- DC-3: Every data store has access logging on, and its logs go to a separate store the workload cannot change or delete. Maps: NIST AU-2, AU-9, AU-12; ASVS V16.4.2, V16.4.3
- DC-4: Keys that protect customer data rotate on a schedule, with rotation enabled on the key itself rather than by hand. Maps: NIST SC-12; ASVS V11.1.1, V13.3.4
- DC-5: Data stores sit on private networks with no public endpoint; services reach them only through private routes. Maps: NIST SC-7, AC-4
- DC-6: Every human sign-in to the cloud account, its consoles and its CI system uses multi-factor authentication. Maps: NIST IA-2(1), IA-2(2); ASVS V6.3.3
