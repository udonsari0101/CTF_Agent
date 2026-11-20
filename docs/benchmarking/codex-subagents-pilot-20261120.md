# Codex subagent switch: small offline pilot

This pilot checks the new **enable/disable option**, not the effectiveness of
parallel agents. Codex CLI 0.164.0 ran `gpt-6-sol` against two offline benchmark
cases in isolated containers. Each case used the same account, files, prompt,
reasoning level and CPU/memory limit in both conditions. The prompt requested
one independent delegation when the option was enabled. An oracle SHA-256
checked the final answer without recording the flag in this report.

| Case | Reasoning | Subagents | Correct | Wall time | Spawn events |
| --- | --- | --- | --- | ---: | ---: |
| CTFTiny Babycrypto | medium | off | yes | 47.46 s | 0 |
| CTFTiny Babycrypto | medium | on | yes | 35.12 s | 0 |
| CTFTiny What a XOR | xhigh | on | yes | 75.10 s | 0 |
| CTFTiny What a XOR | xhigh | off | yes | 44.44 s | 0 |

There was one run per condition. Neither enabled run actually spawned a child
agent, so the time differences reflect ordinary run variation or option
overhead and **do not measure parallel-agent benefit**. A separate Xhigh attempt
using a different account failed its hardware-key authentication check and was
excluded. The safe default remains subagents off below Ultra, with a per-run
switch for cases where independent analysis is likely to help. Larger matched
runs with observed child-agent activity are needed before changing that default.
