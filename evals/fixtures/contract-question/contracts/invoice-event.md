<!-- Copyright (c) 2026 Brad Duhon. SPDX-License-Identifier: GPL-3.0-or-later -->
# Invoice event

The orders module publishes this event when an order is paid. The billing module consumes it.

| Field | Type | Meaning |
|---|---|---|
| order_id | string | The paid order. |
| amount | not decided | The amount paid. The operator has not chosen between integer cents and a decimal string, and decides before any code is written. |
