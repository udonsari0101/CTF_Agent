# Documentation

Start with the [English README](../README.md) or [한국어 README](../README.ko.md) for the product overview.

| Topic | Document |
| --- | --- |
| Windows / WSL installation | [Docker Desktop guide](guides/docker-desktop.md) |
| Workspace and challenge transfer | [Transfer guide](guides/workspace-transfer.md) |
| Solver tools and limits | [CTF toolchain](guides/ctf-toolchain.md) |
| Interface translations | [Language packs](guides/localization.md) |
| Benchmark design and reporting | [Protocol](benchmarking/protocol.md) |
| Solver performance research (Korean) | [Research and improvement plan](research/solving-performance-research.ko.md) |

Private working notes and benchmark assessments live under `docs/local/` on the development machine. That directory is excluded from Git because it can contain operational observations and references to private challenge material. Its local `README.md` indexes those notes. Benchmark inputs and private answer oracles remain in the separate `benchmark_problems/` corpus; the solver should receive only a case's `input/` directory.
