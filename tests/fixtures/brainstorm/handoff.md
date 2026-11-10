# Handoff brief

## Goal as first stated
A planner agent that asks the user design questions until it has enough for a spec.

## Goal now
An agent that shows a confident first draft and lets the user correct it.

## Chosen direction
Show a full draft design first, "confident and wrong is fine", and let the user correct it line by line.

## Why this over the alternatives
- Cap the questions per turn. Reason: it still feels like a form, only shorter.
- Two agents argue while the user watches. Reason: the user wanted to steer, not watch.

## Confirmed constraints
- The result is a spec file the plan step can read (turn 4).

## Soft constraints
- The agent asks the questions: the user would accept the agent proposing instead.

## Open tensions
- How wrong a first draft may be before it anchors the user.

## Parked ideas
- Two agents argue while the user watches and steps in.

## Worth building because
People correct a wrong draft far faster than they answer a blank question.

## Receipts owed
- The planner can write a spec file: agents/planner.md:21
- Corrections arrive faster than answers. ASSUMED
- A draft can be shown before any question: https://example.com/draft-first
