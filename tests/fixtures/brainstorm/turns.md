# Exploring turns

### Turn 1: operator
I want a planner agent that asks the user design questions until it has enough for a spec.

### Turn 2: session
The interesting part is "until it has enough": that is a gap-closing loop, and gap-closing is what makes it feel like a form. Three framings: one, keep it but cap questions per turn; two, flip it so the agent proposes a full draft design first and the user corrects it; three, drop the planner-asks-user model entirely and have the agent argue with a second agent while the user watches and intervenes. I like the second: people correct a wrong draft far faster than they answer a blank question. What if the first thing it ever shows you is a confident, wrong design?

### Turn 3: operator
Would a wrong draft not anchor people on the wrong design?

### Turn 4: session
It can, and the known cure is to show the draft as a sketch with its weakest parts marked. A reader who sees "guess" beside a line treats it as an opening bid. The draft also lists the two framings it did not take, so the user sees the road not taken.

### Turn 5: operator
Fine. Keep the spec at the end, though.

### Turn 6: session
Your "keep the spec" holds the finish line still while the start moves. My guess: the draft becomes the spec once the user stops correcting it. Should the spec be the last corrected draft, with nothing new written after it?
