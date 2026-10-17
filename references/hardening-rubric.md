<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->
# Hardening rubric

These rules are Daedalus's own words. CIS benchmark text is licensed and is not reproduced here; a cited section number points at the operator's licensed copy, and `CIS: unmapped` means no licensed copy was available to check a number.

The cis specialist maps each changed resource or code path in a diff to the items below and gives PASS, FAIL or N/A per item.

## IAM

- HR-1: A policy statement grants named actions on named resources; a wildcard action or a wildcard resource on a write, delete or permission-changing action fails. CIS: unmapped
- HR-2: Trust policies name the exact principals allowed to assume a role; an open principal or a whole-account principal without a condition fails. CIS: unmapped
- HR-3: No long-lived access keys are created for people or for workloads that can use a role or a federated identity instead. CIS: unmapped
- HR-4: The root or break-glass identity has no access keys and is not used by any automation in the diff. CIS: unmapped
- HR-5: Human sign-in to a privileged role requires a second factor. CIS: unmapped
- HR-6: Permissions attach to roles or groups, never directly to individual users. CIS: unmapped
- HR-7: A new role that can change IAM, key policies or logging configuration carries a permissions boundary or an equivalent guard. CIS: unmapped
- HR-8: Password policies set by the diff require length of at least 14 characters and block reuse. CIS: unmapped

## Network

- HR-9: No ingress rule opens an administrative port (SSH, RDP, database ports) to any address on the internet. CIS: unmapped
- HR-10: Default security groups or default firewall rules allow no traffic in either direction. CIS: unmapped
- HR-11: Egress is limited to the destinations the workload needs; an allow-all egress rule on a workload holding sensitive data fails. CIS: unmapped
- HR-12: Network flow logging is on for every new virtual network or subnet the diff creates. CIS: unmapped
- HR-13: Services reachable from outside the network accept TLS 1.2 or later only and reject plain HTTP except to redirect. CIS: unmapped
- HR-14: Storage and database endpoints are private by default; public access needs an explicit, documented exception in the diff. CIS: unmapped
- HR-15: Instance metadata services require session tokens, so a request forgery bug cannot read workload credentials. CIS: unmapped

## Logging

- HR-16: Control-plane API activity is recorded in every region the account uses, including global service events. CIS: unmapped
- HR-17: Audit log files are integrity-protected so a later change or deletion is detectable. CIS: unmapped
- HR-18: The storage that holds audit logs denies deletion and overwrite to the workloads it records. CIS: unmapped
- HR-19: Logs have a stated retention period that meets the project's declared standard; unbounded or zero retention fails. CIS: unmapped
- HR-20: Alerts exist for root or break-glass use, IAM policy changes, key disable or deletion, and logging being turned off. CIS: unmapped
- HR-21: Application logs carry no secrets, tokens, key material or personal data, and request bodies are not logged by default. CIS: unmapped

## Encryption at rest

- HR-22: Every new storage resource (object store, block volume, database, queue, log group, secret store) is encrypted at rest. CIS: unmapped
- HR-23: Customer-managed keys have automatic rotation turned on. CIS: unmapped
- HR-24: Key policies name the principals that may use and administer a key, and no single principal holds both roles without a stated reason. CIS: unmapped
- HR-25: Snapshots, backups and replicas inherit encryption and are never shared publicly. CIS: unmapped
- HR-26: Object stores block public access at the bucket or account level and deny requests that do not use TLS. CIS: unmapped

## OS and container

- HR-27: Container images come from a pinned digest or a pinned version in a trusted registry, never a floating latest tag. CIS: unmapped
- HR-28: Containers run as a non-root user and drop the Linux capabilities they do not need. CIS: unmapped
- HR-29: Containers do not run privileged, do not share the host network, PID or IPC namespace, and do not mount the container runtime socket. CIS: unmapped
- HR-30: The root filesystem of a container is read-only where the workload allows, with writable paths named explicitly. CIS: unmapped
- HR-31: Secrets reach a container or host through a secret store or a mounted file, never through an image layer or a build argument. CIS: unmapped
- HR-32: Hosts and images receive security patches through an automated, scheduled path stated in the diff or the project's standards. CIS: unmapped
- HR-33: Remote shell access to hosts uses key or federated authentication; password login and direct root login are off. CIS: unmapped
- HR-34: Services and packages the workload does not use are not installed or are disabled in the image or host configuration. CIS: unmapped
