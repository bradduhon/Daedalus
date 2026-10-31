<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->
The run builds the lifecycle rule and the audit judges the Terraform file against the terraform rules, citing their TF ids. The binary check row passes when terraform sits in a searched folder and warns when it does not; it is never a failure. The run ends complete, and nothing is pushed.
