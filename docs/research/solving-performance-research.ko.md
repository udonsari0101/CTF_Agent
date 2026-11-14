# CTF Agent 문제 풀이 성능 개선: 근거 조사와 실행 계획

> 초기 조사: 2026-11-04. 통제 연구와 평가기 검토는 2026-11-05에 보강했다. 이 문서는 **성능 향상 결과 보고가 아닌 연구·실험 설계**다. 아래의 외부 성적은 해당 저자와 조건의 결과이며 CTF Agent의 현재 성능이 아니다. 진행 중인 코드 변경과 배포판의 상태도 구분한다.

2026-11-14 v0.4.75 배포 후 실제 풀이 경로의 단일 실행과 예비 짝 실험, 토큰 비용의 계측 한계, 기본값 유지 결정은 [별도 증거 기록](solving-performance-evidence-20261114.ko.md)에 있다. 이 문서의 오래된 준비 상태 표는 당시 스냅샷이며 현재 배포 상태로 읽지 않는다.

## 1. 목표와 판단 원칙

목표는 정해진 대회 시간 안에 **실제로 검증된 Flag를 더 많이, 더 빨리** 얻는 것이다. 답을 떠올렸다는 모델의 주장, 형식만 맞는 Flag 문자열, write-up 생성 성공, CTFd 제출 성공은 서로 다른 상태다. 특히 write-up은 Flag 발견 이후의 별도 작업이므로 풀이 속도 지표에 섞지 않는다. 실행이 거부되거나 필요한 원격 주소를 잘못 요청해 시작조차 못 한 경우도 모델의 추론 실패와 따로 집계한다.

이 문서는 저장소의 기존 `docs/local/todo.md`, `docs/benchmarking/protocol.md`, 그리고 2026-11-01의 로컬 하네스 문헌 조사·참고 저장소/운영 사고 분석·운영 기록 감사·로그/세션 설계를 통합해 풀이 성능에 직접 관련된 결론을 갱신했다. 로컬 조사 문서의 일부 설치 도구·프롬프트/UI 상태는 당시의 **정적 스냅샷**이다. 이후 작업 트리에서 수정된 내용은 현재 코드와 대조했으며, 미커밋 코드가 운영 배포에 반영됐다고 가정하지 않는다. 설치·UI·CTFd 관련 항목은 풀이를 막거나 검증을 왜곡하는 경우에만 다룬다. 이 문서에는 개인 서버 주소, 인증 정보, 비공개 문제의 정답이나 재현 파일을 넣지 않는다.

근거의 우선순위는 다음과 같다.

1. **직접 재현 가능한 비교**: 같은 문제, 같은 모델·계정·추론·시간·도구·네트워크 예산에서 바뀐 요소 한 개만 달리한 CTF Agent 실험. 아직 충분한 실험 결과가 없다.
2. **공개 원문과 실행 자료**: 학회 논문, 논문 부록, 소스, 로그, 평가기. 논문 저자 결과도 우리의 환경으로 일반화하지 않는다.
3. **공개 구현**: 실제 코드가 제안하는 상태 기계와 도구 계약. GitHub star와 대회 성적 주장은 인지도 신호이지 성능 증명이 아니다.
4. **운영 사고 기록**: 실패 유형과 재현 가설을 세우는 자료. 시간대·배포판·계정·원격 서비스가 달랐던 사고를 한 원인으로 묶지 않는다.

공개 정적 문제에서는 모델의 사전학습 및 웹에서 공개 write-up/Flag를 검색하는 오염을 완전히 배제할 수 없다. 실사용에서는 일반 인터넷을 허용하되, **평가**에서는 직접적인 기존 정답 회수와 실제 풀이를 구분하여 기록한다. [CTFusion](https://arxiv.org/html/2605.11504)은 정적 평가에서 직접 Flag 복사와 write-up 검색을 관찰했으며, 라이브 대회 점수가 같은 프레임워크의 공개 문제 점수보다 낮았다. 그러나 난도·문제 분포도 달라 그 차이를 전부 오염 탓으로 돌릴 수 없다.

## 2. 현재 CTF Agent의 기준선과 확인되지 않은 부분

현재 작업 트리의 흐름은 `CTFd/수동 문제 → 격리된 challenge 작업 디렉터리 → 읽기 전용 문제 설명·첨부 → AGENTS.md/CLAUDE.md와 분야별 skill → Codex 또는 Claude Code 실행 → notes/ANALYSIS.md·VULN.md·NEXT.md 및 파일 → Flag 후보 즉시 관측 → 검증/선택적 제출 → write-up`이다. 분야가 비어 있거나 특이하면 `unknown` 지침을 선택할 수 있다. 기존 원본의 문제 풀이 구조를 보존한다는 요구 때문에 프롬프트·노트·solver의 기본 계약을 후보 변경으로 통째로 교체하지 않는다. 관련 코드: [`agent_workspace.py`](../../ctf_agent/agent_workspace.py), [`solver_worker.py`](../../ctf_agent/solver_worker.py), [`solver_exchange.py`](../../ctf_agent/solver_exchange.py), [`solver_service.py`](../../ctf_agent/solver_service.py).

현재 이미지는 [도구 설명](../guides/ctf-toolchain.md)과 [`deploy/image-smoke.py`](../../deploy/image-smoke.py) 기준으로 Chromium/curl/ffuf/sqlmap, Ghidra headless/JADX/radare2/angr, GDB/pwndbg/pwntools/QEMU, PARI·PyCryptodome·Z3·fpylll, binwalk/Sleuth Kit/Volatility·tshark/YARA 등을 제공하도록 설계됐다. `REA`, SageMath, 일부 언어별 역공학 도구는 기본 설치가 보장되지 않는 **선택 후보**다. `skill_misc.md`에는 선택 도구인 cvc5·zsteg·fickling을 바로 쓰는 예시가 있어 설치 계약과 대조할 필요가 있다. 이미지에 명령이 존재하는지, 실제 solver의 권한·네트워크·작업 디렉터리 안에서 유효한 결과를 내는지는 다른 검사다. 최종 배포 digest에서 분야별 대표 입력을 처리한 결과가 필요하다.

현재 작업 트리에는 solver job의 일부 시각과 활동 메타데이터, 결과 형식 검사기가 있다. 그러나 실행된 명령의 실제 출력→가설→재현 파일→Flag 최초 관측→공식 판정을 완전히 잇는 증거 그래프와, 큐·준비·첫 모델 응답·도구·원격·Flag의 단계별 시간을 모두 측정하는 데이터는 아직 없다. `scripts/benchmark_plan.py`와 `scripts/benchmark_report.py`는 비교 **일정과 결과 형식**을 검사한다. 별도 비공개 `benchmark_problems/` 폴더에는 정적 입력 17개(`static_pilot`)와 개발용 6개(`bronco_development`), 분리된 판정 메타데이터가 준비됐다. 원격 서비스 후보 3개는 기동·초기화 검증 전이다. 기본 CLI와 서비스의 실제 실행기, 공식 판정이 끝난 실측 결과는 아직 없다. 준비된 corpus나 `benchmark_report.py` 통과를 풀이 성능으로 혼동하지 않는다. 상세 범위와 빠진 분야는 [사전 감사](../benchmarking/preflight-audit.md)에 기록한다.

역사적 운영 분석에서 확인한 풀이 저해 유형은 시작 전 저장공간 거부, 계정/모델 경로 거부, 원격 입력 상태 충돌, 제한 턴 내 Flag 인수인계 실패, 장시간 로그 backfill/화면 갱신, 검증되지 않은 Flag 및 결과 불명 CTFd POST, 다시 풀기 시 세션/체크포인트 혼동이다. 이것들은 같은 증상을 보여도 서로 다른 계층의 결함이다. 시점별 패치와 현재 배포 상태를 재확인하기 전에는 해결 완료라고 표시하지 않는다. 특히 write-up 형식 실패는 이미 저장한 Flag의 발견 성과와 분리해서 집계한다. `agent_workspace.py`의 초기 목표 문구에는 진짜 Flag가 원격에 있다고 단정하는 표현이 남아 있어 원격 대상이 없는 문제와 충돌할 가능성이 있다. 이는 특정 문제 해법을 추가하기보다 여러 분야의 원격 없음 fixture로 검증할 가설이다.

## 3. 영향력이 큰 연구: 실제 주장과 우리에게 필요한 검증

### 3.1 벤치마크와 측정의 기반

| 원문 | 확인한 설계·결과 | 우리에게 쓰는 범위와 한계 |
|---|---|---|
| [NYU CTF Bench, NeurIPS 2024](https://proceedings.neurips.cc/paper_files/paper/2024/file/69d97a6493fbf016fff0a751f253ad18-Paper-Datasets_and_Benchmarks_Track.pdf), [프로젝트](https://nyu-llm-ctf.github.io/) | CSAW 기반 다분야 CTF 문제와 실행 환경·Flag 판정기를 공개한다. 개발 55개와 평가 200개가 조사 문서의 기준이다. | 재현 가능한 개발/회귀셋의 출발점. 공개 Flag와 풀이의 사전 노출 가능성이 있으므로 현재 대회 예상 solve rate로 사용하지 않는다. 문제와 정답을 solver에 동시에 마운트하지 않는다. |
| [Cybench, ICLR 2025](https://proceedings.iclr.cc/paper_files/paper/2025/hash/3e9412a9c1d93810ef3ef7825115016b-Abstract-Conference.html), [구현](https://github.com/andyzorigin/cybench) | 네 대회에서 고른 전문 CTF **40개 task**에 시작 파일·실행환경·판정기와 부분 진행을 보는 하위 과제를 둔다. 8개 모델을 기본 agent로 비교하고 상위 2개 모델만 4가지 scaffold에서 추가 비교했다. | 어려운 문제의 단계별 실패 위치 파악에 적합. 하위 과제 힌트를 준 guided 결과와 독립 풀이를 같은 성공률로 비교하지 않는다. |
| [CTFTiny/CTFJudge, AAAI 2026](https://ojs.aaai.org/index.php/AAAI/article/view/40210), [arXiv 원문](https://arxiv.org/abs/2508.05674), [문제셋](https://github.com/NYU-LLM-CTF/CTFTiny) | 5개 분야, 50개 소형 문제와 부분 진척 판정. | 빠른 기능 회귀용. 작고 공개된 문제셋만 통과했다고 실전 고난도 풀이 성능을 주장하지 않는다. |
| [HackSynth, 2024 preprint](https://arxiv.org/html/2412.01778v1), [구현](https://github.com/aielte-research/HackSynth) | picoCTF 120개와 OverTheWire 80개를 포함한 200개 과제에서 planner와 summarizer의 실행·피드백 구조를 평가한다. | 플랫폼별 동적 checker와 요약의 원문 보존에 참고한다. 공개·상대적으로 오래된 문제의 성공률을 현재 라이브 대회 예측치로 쓰지 않는다. |
| [CTFusion, 2026 preprint](https://arxiv.org/html/2605.11504), [코드](https://github.com/kaist-hacking/CTFusion) | 5개 라이브 CTF·3개 모델·2개 agent를 평가하면서 per-agent 독립 view와 **첫 정답만 실제 CTFd 제출**을 구현했다. 공개 NYU 정적셋 14.4% 대 라이브 평균 6.3%는 모두 집계 pass@3이다. 정적 실험에서 공개 정답 직접 회수도 관측했다. | 복제 문제의 모델 비교는 서로의 상태·제출을 격리해야 한다. 라이브 성적은 난도/시대/모델 차이가 있으므로 정적셋 차이 전체를 오염 크기로 해석하지 않는다. |
| [현장 CTF 연구, USENIX Security 2026](https://www.usenix.org/conference/usenixsecurity26/presentation/tang-tingxuan) | 새 문제를 제공한 현장 대회의 전체 참가자 95명 중 연구 참여 41명의 사용·협업 기록과 동일 문제에 대한 4개 자율 agent의 궤적을 비교했다. | 사람 개입의 도움과 자율 성능을 분리한다. 한 대회·당시 모델/참여자 조건이므로 보편적인 풀이 향상 폭으로 옮기지 않는다. |
| [CTF-Dojo, ICML 2026](https://proceedings.mlr.press/v306/zhuo26c.html), [코드](https://github.com/amazon-science/CTF-Dojo) | 공개 문제 658개 중 650개는 반복 재현을 확인했고, 274개 고유 문제에서 **Flag 획득으로 성공 판정된 궤적 486개**를 모았다. 이 궤적으로 모델을 학습한 32B의 세 벤치 평균 pass@1은 20.3%에서 31.9%로 11.6%p 올랐다. | Flag 성공은 exploit 경로를 독립 감사했다는 뜻이 아니다. 11.6%p는 모델 학습 효과이며 CTF Agent의 런타임 하네스 예상 효과가 아니다. 개별 벤치의 최대 상승폭과도 구분한다. |
| [InterCode, NeurIPS 2023](https://papers.nips.cc/paper/2023/hash/4b175d846fb008d540d233c188379ff9-Abstract-Datasets_and_Benchmarks.html) | 코드 생성에서 실행 피드백을 포함한 상호작용형 평가 환경을 표준화했다. | 실패한 명령/실제 출력/다음 선택을 분리하는 평가 모델에 간접 참고. CTF 전체 성공률과 직접 비교하지 않는다. |

### 3.2 풀이 구조·도구·시간에 관한 실험

| 원문 | 무엇을 측정했는가 | 적용 가설과 반대 근거 |
|---|---|---|
| [EnIGMA, ICML 2025](https://proceedings.mlr.press/v267/abramovich25a.html), [CTF 구현](https://github.com/SWE-agent/SWE-agent/tree/v0.7) | 네 벤치마크 390개 CTF에서 대화형 디버거·서버 접속 도구를 연구했다. 실제 상호작용 없이 관측을 지어내는 `soliloquizing`도 분석했다. | **지속 상태가 필요한** GDB/원격 접속에서 실제 명령과 출력을 결합하면 도움이 될 수 있다. 현재 CLI의 일반 shell이 실제로 그 상태를 잃는지 먼저 재현해야 한다. |
| [D-CIPHER, 2025 preprint](https://arxiv.org/html/2502.10931), [구현](https://github.com/NYU-LLM-CTF/nyuctf_agents) | planner·여러 executor·auto-prompter의 기본 Claude 3.5 Sonnet 구성은 NYU CTF 19.0%, Cybench 22.5%, HTB 44.0%였다. NYU에서 auto-prompter를 제거한 ablation은 22.0%였다. | 분업은 후보지만 모델·문제·시간·도구가 달라 현행 단일 solver보다 낫다는 근거는 아니다. 기본 적용 전에 같은 모델의 단일 executor를 대조한다. |
| [Autonomous LLM Agents & CTFs: A Second Look, 2026 preprint](https://arxiv.org/html/2605.21497) | 웹 30개·14개 취약점군에서 GPT-5의 세 구조를 문제당 3회, Claude Code Opus 4.5를 문제당 1회 실행했다. 각 구조의 최대 성공 문제 수는 19/30. GPT-5 bare executor의 평균 336.74초가 planner+evaluator 구조에서 925.80초로 늘었고, 후자의 3회 중 전부 성공한 문제는 12→16개로 늘었다. | 반복 안정성과 비용은 나아질 수 있으나 **빠른 Flag**에는 매 단계 오케스트레이션이 불리할 수 있다. 19/30이라는 숫자가 같아도 3회 최고값과 1회 결과를 동률 순위로 읽지 않는다. |
| [Baselines Before Architecture, 2026 preprint](https://arxiv.org/html/2607.13085), [재현 자료](https://github.com/krodalabs/coding-agent-research-artifact) | 웹 XBOW 104개에서 같은 GPT-5·예산·대상 인터페이스로 기본 Codex/OpenCode/Pi를 비교했다. 기본 Codex의 두 번 실행은 각 70개 성공, 합집합 81개였다. 보안용 상세 프롬프트 두 형태는 기본 Codex보다 이 실험에서 낮았다. | **기본 CLI를 강한 대조군**으로 둔다. 프롬프트를 늘리거나 전용 구조를 추가하는 효과를 모델/예산 증가와 분리한다. XBOW 웹만의 저자 실험이며 CTF 전 분야 결론은 아니다. |
| [Systematic Capability Benchmarking, 2026 preprint](https://arxiv.org/html/2604.17159), [코드 저장소](https://github.com/TATAR-LAB/ctf-agents) | NYU 공개 200문제에서 D-CIPHER 기반 Ubuntu 환경 42.5% 대 Kali+100여 도구 및 도구 검색 환경 52.0%를 보고했다. Kali+일반 프롬프트에서는 분야별 tip이 40.0%, 자동 사전 prompt가 39.5%로 하락했다. 단일 시행·온도 1.0이다. | **도구 묶음과 검색 인터페이스가 함께 바뀌어** 어느 요소가 +9.5%p를 낳았는지 분리되지 않는다. CTF Agent에서는 필요한 도구의 존재·호출 가능성·발견 가능성을 한 요소씩 시험한다. 긴 분야별 skill과 사전 탐색도 대조 없이 확대하지 않는다. |
| [PwnAgent, Cybersecurity 2026](https://link.springer.com/article/10.1186/s42400-026-00649-5) | 공개 pwn 66개, 대부분 x86 및 stack 유형. 같은 Kimi K2.6에서 62.12% 대 비교대상 31.82%의 저자 실험. GDB 실측과 실패 후 exploit 수정을 강조한다. | 런타임 주소·레지스터·crash 증거를 PoC 수정과 연결할 후보. 커널/heap/비x86 또는 전 분야 효과로 일반화하지 않는다. |
| [AgentRE-Bench](https://github.com/agentrebench/AgentRE-Bench), [v3.1 결과](https://www.agentre-bench.ai/results/v3-1/) | 전체 공개 저장소의 범위와 v3.1 평가를 구분한다. v3.1은 Windows PE 10개 프로그램의 stripped/unstripped **20개 artifact**, 모델 5개·artifact당 5회로 **500 episode**를 평가한다. | 고정 도구·25회 호출·구조화 점수는 rev 진척 측정용이며 Flag 성공률이 아니다. 과거 23 level/전체 33 artifact와 v3.1의 표본 수를 섞지 않는다. |

### 3.3 원문의 결과를 해석할 때 특히 주의할 점

- [D-CIPHER 원문](https://arxiv.org/html/2502.10931)의 ablation은 planner 제거 시 해당 조건의 19%가 14%로 내려갔지만, auto-prompter 제거 시 19%가 22%로 **올라간** 결과도 포함한다. 따라서 ‘하위 에이전트가 많을수록 좋다’는 결론을 내릴 수 없다.
- [EnIGMA 원문](https://openreview.net/pdf?id=Of3wZhVv1R)의 전체 ablation은 29.5% 해결률에서 대화형 도구 제거 27.4%, LM 기반 긴 출력 요약 대체 26.9%, 도구 데모 제거 23.3%였다. 대화형 도구의 전체 절대 효과는 이 조건에서 약 2.1%p이고 웹 등 일부 분야에서는 방향이 달랐다. 따라서 현재 CLI에 새 대화형 레이어를 넣기 전에 어떤 상태가 실제로 손실되는지 확인한다.
- [Systematic Capability Benchmarking](https://arxiv.org/html/2604.17159)의 Kali와 Ubuntu 비교는 운영체제 이름만 바뀐 실험이 아니다. 약 100개 도구와 도구 조회 인터페이스가 함께 추가돼 어느 요소가 성능을 올렸는지 분리할 수 없다. 단일 시행, 공개 NYU 문제, 온도 1.0의 저자 프리프린트라는 조건도 함께 기록한다. 같은 논문에서 ‘Cybench 90문제’라는 표현은 [Cybench 원문](https://proceedings.iclr.cc/paper_files/paper/2025/hash/3e9412a9c1d93810ef3ef7825115016b-Abstract-Conference.html)의 40개 task와 맞지 않아 이 문서는 원문 수치를 따른다.
- [Hacking CTFs with Plain Agents](https://arxiv.org/html/2412.02776)의 높은 성공률은 오래되고 쉬운 쪽으로 치우친 InterCode-CTF의 일부 문제에 **최대 다섯 번** 시도한 pass@5 성적이다. pwn·web 표본이 매우 작다. 한 번 실행하는 CTF Agent의 실전 예상 성적이 아니다.
- [PwnAgent](https://link.springer.com/article/10.1186/s42400-026-00649-5), [AgentRE-Bench](https://github.com/agentrebench/AgentRE-Bench), [Reveree](https://arxiv.org/abs/2609.01185)는 각 분야의 실험 지표가 유용하지만 다른 분야로 넘겨 쓰지 않는다. RE 분석 점수, 실제 Flag 획득, CTFd 정답 판정도 다른 지표다.
- OpenAlex에서 2026-11-04 조회한 일부 arXiv 레코드의 인용 수가 학회판과 병합되지 않아 비정상적으로 낮았고 NYU CTF Bench 검색도 누락됐다. **인용 수 순위는 채택하지 않았다.** 대신 NeurIPS/ICLR/ICML/USENIX의 출판 상태, 공개 구현·실행 자료, 비교 통제의 품질을 중요도 기준으로 썼다. 새 연구의 인용 수가 적다고 무시하지도 않는다.

### 3.4 우선 읽을 연구의 설계·반례·채택 경계

**평가셋을 만드는 방법 — NYU CTF Bench, Cybench, CTFTiny, CTFusion.** [NYU CTF Bench](https://proceedings.neurips.cc/paper_files/paper/2024/file/69d97a6493fbf016fff0a751f253ad18-Paper-Datasets_and_Benchmarks_Track.pdf)는 다분야 실행 가능 문제와 판정 자료를 제공하므로 동일 입력으로 반복하는 데 적합하다. 그러나 저장소 전체를 solver 작업공간에 넣으면 문제 메타데이터·패키지에서 정답을 읽을 수 있다. [Cybench](https://proceedings.iclr.cc/paper_files/paper/2025/hash/3e9412a9c1d93810ef3ef7825115016b-Abstract-Conference.html)의 하위 과제는 전체 Flag에 도달하지 못한 이유를 볼 수 있지만, 하위 과제 안내가 들어간 실행을 무힌트 풀이와 같은 열에 놓으면 안 된다. [CTFTiny](https://ojs.aaai.org/index.php/AAAI/article/view/40210)의 50개 소형 문제는 스모크 회귀에 쓰고, 이를 통과한 결과로 장시간 대회 문제 실력을 추정하지 않는다. [CTFusion](https://arxiv.org/html/2605.11504)은 공개 정답 검색이라는 오염 경로와 복제 agent의 제출 충돌 문제를 직접 다룬다. 우리 평가기는 문제 번들만 solver에 전달하고 oracle·기존 풀이·다른 worker의 상태를 분리하며, 공식 정답 제출은 경쟁에 영향을 주지 않도록 한 번만 내보내는 구조가 필요하다. 신규 대회의 성적은 별도 라이브 층으로 표시하고, 공개셋과 합산하지 않는다.

**대화형 도구 — EnIGMA.** [ICML 원문](https://proceedings.mlr.press/v267/abramovich25a.html)은 디버거나 원격 서비스 연결을 한 번의 shell 호출로 끝내기 어려운 문제를 겨냥해 지속적인 상호작용 도구를 추가했다. 390개 문제 전체의 제거 실험에서 이 도구를 뺐을 때 29.5%에서 27.4%로 떨어졌지만, 도구 사용 시연 제거는 23.3%, 긴 출력 요약의 LM 대체는 26.9%였다. 구성 요소별 차이의 크기와 방향이 다르므로 ‘PTY adapter 하나를 넣으면 크게 향상된다’고 읽지 않는다. 특히 웹 범주에는 도구의 이득이 일관되지 않았다. CTF Agent에서는 기존 shell/tmux/원격 릴레이로 실제 세션이 끊기는 GDB·REPL·프로토콜 fixture를 찾고, 확인된 실패 유형에만 선택형 지속 세션 adapter를 대조한다. 원본 stdout을 보존하고 모델이 보지 않은 실행 결과를 본 것처럼 말한 경우를 별도 오류로 센다.

**분업과 사전 프롬프트 — D-CIPHER.** [저자 구현·실험](https://arxiv.org/html/2502.10931)은 사전 탐색 agent, 전체 계획을 가진 planner, 새로운 문맥에서 단일 작업을 수행하는 executor를 묶는다. executor의 결론은 요약으로 planner에 돌아가며 모든 agent가 같은 컨테이너와 문제 환경을 이용한다. 저자 평가에서 planner 제거는 특정 조건의 19%를 14%로 낮췄지만, auto-prompter 제거는 19%를 22%로 높인 조건도 있다. 저자 본문은 이것을 일반적 auto-prompter 무용론으로 보지 않았고, 다른 모델/셋에서는 비용이나 성공이 개선됐다고 보고했다. 우리가 가져올 것은 ‘항상 planner를 만든다’는 규칙이 아니라, 독립 작업의 목표·예산·완료 증거를 부모에게 돌려주는 제한된 위임 계약이다. 사전 탐색 프롬프트는 시작 시간을 잡아먹거나 첫 오판을 고정할 수 있으므로 기본 CLI·현재판 대비 별도 arm으로 측정한다.

**도구 환경과 프롬프트의 상호작용 — Systematic Capability Benchmarking.** [2026년 프리프린트](https://arxiv.org/html/2604.17159)는 200개 공개 NYU 문제에서 환경·프롬프트·모델·여러 역할을 비교한다. 같은 Gemini 3 Pro 조건의 일반 프롬프트에서 Ubuntu 85/200, Kali+도구/검색 104/200이었고, 도구가 많은 조건에서 분야별 팁·자동 사전 프롬프트는 오히려 낮은 결과가 많았다. ‘Kali’에는 100개 넘는 도구와 발견 인터페이스가 함께 묶였으므로 운영체제만의 인과효과로 해석할 수 없다. 또한 공개 문제, 모델 한 종류의 해당 ablation, 단일 시도라는 제약이 있다. 우리 쪽 실험은 설치된 명령의 실제 작동, agent가 그 명령을 찾을 수 있는지, 분야별 skill의 길이를 별개 요소로 다뤄야 한다. 공개 벤치의 최고 모델 순위를 현 시점 사용자 계정 모델의 권장 순위로 옮기지 않는다.

**기본 CLI를 빼놓은 성능 주장 방지 — Baselines Before Architecture와 A Second Look.** [XBOW 104문제 연구](https://arxiv.org/html/2607.13085)는 동일 GPT-5로 일반 코딩 CLI를 먼저 비교했다. Codex 기본 상태의 두 시행은 각각 70개, 두 시행의 합집합은 81개를 풀었다. 상세 보안 프롬프트는 두 시행에서 64·58개, 전체 시스템 프롬프트는 60·68개로 기본 상태보다 낮거나 불안정했고 도구 호출·비용이 늘었다. 여기서 81개는 pass@1이 아니다. 또한 공개 XBOW의 노출·포화 문제와 지출 기준이 턴 경계에서 적용되는 조건을 보존해야 한다. [30개 웹 문제 연구](https://arxiv.org/html/2605.21497)는 공개 풀이가 없는 문제를 사람이 먼저 확인했고, 단일 executor, evaluator, planner를 비교했다. GPT-5의 세 구조 모두 문제당 3회 중 최고 성공 수는 19/30이지만 planner+evaluator는 일관성과 비용에서 이점이 있는 반면 평균 종료 시간은 336.74초에서 925.80초로 길었다. Claude Code의 19/30은 단일 시행이므로 동률 비교가 아니다. 따라서 CTF Agent의 1차 목표인 제한시간 내 최초 검증 Flag에 대해 동일 모델·CLI 기본판 B0, 현재판 B1, 후보판 C를 따로 측정해야 한다.

**성공 궤적의 품질 — CTF-Dojo와 CTF-ABACUS.** [CTF-Dojo](https://proceedings.mlr.press/v306/zhuo26c.html)의 486개 성공 궤적은 학습 자료이고, 여기서 얻은 모델 성능 상승을 런타임 하네스의 효과로 말하면 안 된다. 다만 실행 환경과 자동 판정의 재현성을 높이는 방법은 corpus 제작에 참고할 수 있다. [CTF-ABACUS](https://arxiv.org/html/2608.26237)는 Flag를 얻은 행위와 실제 취약점 이용 근거가 남은 행위가 다를 수 있음을 궤적으로 보여준다. 자동 judge도 오차가 있으므로 우리 시스템의 정답 판정은 공식 oracle, 풀이 근거는 명령·파일·출력 provenance로 따로 남긴다. 이것은 write-up의 그럴듯함을 점수화하려는 목적이 아니라, 정답 유출·우연·잘못된 제출을 구분하기 위한 것이다.

**분야 특화와 사람 개입 — PwnAgent, Reveree, 현장 연구.** [PwnAgent](https://link.springer.com/article/10.1186/s42400-026-00649-5)는 디버거에서 읽은 레지스터·주소·crash를 exploit 수정에 되돌리는 구조를 제시하지만 실험 문제가 주로 x86 stack pwn이어서 커널·heap 전반으로 확장하지 않는다. [Reveree](https://arxiv.org/html/2609.01185)는 rev를 이해→분석→재현 단계로 나누어 어느 단계에서 막히는지를 보이지만 일부 판정은 사람과 대조한 LLM judge다. [USENIX 2026 현장 연구](https://www.usenix.org/conference/usenixsecurity26/presentation/tang-tingxuan)는 새 문제에서 사람의 제한적 개입이 실패한 agent의 경로를 바꿀 수 있음을 관찰했다. 이 세 자료를 합치면 분야별로 동일한 ‘추론 수준 올리기’보다, 현재까지 실제 관측한 것과 다음에 필요한 한 단계·사용자 입력의 정확한 사유를 보여주는 UI/로그가 더 먼저 검증할 후보라는 결론이 나온다. 이 결론은 연구들을 종합한 **우리의 가설**이지, CTF Agent 실측 결과가 아니다.

## 4. 공개 구현 조사: 인기와 구현 가치를 분리

별 수는 2026-11-04 09:15–09:19 KST GitHub REST API 조회 스냅샷이다. 수치는 변하며, 프로젝트 전체의 별이 특정 CTF 실험 구현의 성능이나 현재 유지보수를 증명하지 않는다. 타 저장소의 코드를 그대로 복사하기 전에 해당 파일의 라이선스와 버전을 따로 확인한다.

| 저장소·조회 시 별 | 실제로 참고할 구현 | 평가 한계와 CTF Agent 적용 판단 |
|---|---|---|
| [SWE-agent / EnIGMA](https://github.com/SWE-agent/SWE-agent) **20,716★** | CTF용 EnIGMA는 현재 main보다 [v0.7 계열](https://github.com/SWE-agent/SWE-agent/tree/v0.7)에 가깝다. 디버거와 원격 서버 연결을 상태 있는 상호작용으로 노출한다. | main의 별 수를 CTF 풀이 능력으로 대체하지 않는다. 현재 solver의 shell·원격 릴레이가 지속 세션을 실제로 잃는 경우만 좁게 보강한다. |
| [PentestGPT](https://github.com/GreyDGL/PentestGPT) **16,255★** | 현재 [loop](https://github.com/GreyDGL/PentestGPT/blob/main/pentestgpt_agent/src/pentestgpt_agent/loop.py)와 [memory](https://github.com/GreyDGL/PentestGPT/blob/main/pentestgpt_agent/src/pentestgpt_agent/memory.py)는 계획 revision, 실행 lease, trace 복구, 도구 action receipt를 구분한다. | [USENIX 2024 논문](https://www.usenix.org/conference/usenixsecurity24/presentation/deng)은 구버전 구조의 결과다. 현재 코드의 성능 증거로 오용하지 않는다. 중단 복구와 부작용 있는 명령의 중복 실행 방지 설계를 참고한다. |
| [CAI](https://github.com/aliasrobotics/cai) **9,847★** | specialist 위임, 병렬 세션, turn 상한, trace/메모리/압축 설계. | 2026-08 archive 상태. README의 대회 성적은 저자 보고이며 같은 모델·문제·예산의 A/B가 아니다. 독립 부분문제에서만 bounded worker 가설을 시험하고 의존성으로 채택하지 않는다. |
| [ctf-skills](https://github.com/ljagiello/ctf-skills) **3,615★** | 여러 분야의 도구·진행 체크리스트. | solver가 아니라 skill 모음이다. 실사용 도구 누락 점검에 참고하되 프롬프트를 대량으로 복사하지 않는다. 길고 중복된 지침이 오히려 성능을 낮출 수 있다. |
| [verialabs/ctf-agent](https://github.com/verialabs/ctf-agent) **914★** | CTFd poll/coordinator, 이종 모델 swarm, 최초 정답 dedup, 오답 cooldown, 운영자 입력 inbox. | README의 특정 대회 52/52는 저자 자체 보고이며 통제된 재현 자료가 없다. 현재 기본값을 무조건 다중 solver로 바꾸지 않는다. 제출 충돌 방지와 확인된 finding 공유만 좁게 비교한다. |
| [BoxPwnr](https://github.com/0ca/BoxPwnr) **467★** | 플랫폼·실행기·solver adapter 분리, 시간/비용/턴 예산, `progress.md`와 trace, 원본 로그를 남긴 컨텍스트 압축. | 자체 실행기와 플랫폼 다양성은 유익하지만 동일 조건 성적표는 확인되지 않았다. 우리 `ANALYSIS/NEXT`·native resume와 중복되는 부분은 재구현하지 않는다. 복구 시 사실/가설/부작용을 잃지 않는지 검증한다. |
| [D-CIPHER / nyuctf_agents](https://github.com/NYU-LLM-CTF/nyuctf_agents) **177★** | planner·독립 executor·선택형 auto-prompter와 ablation 스크립트. | 공개 문제·과거 모델 조건. 구조를 통째로 가져오기보다 어려운 문제에 한정한 분업과 단일 solver 대조군 설계에 사용한다. |
| [CTFusion](https://github.com/kaist-hacking/CTFusion) **4★** | 라이브 CTF에서 비교 agent별 독립 진행과 첫 정답만 원격 제출. | 별은 적어도 실험 설계상 가치가 높다. 동일 문제 복제 실험의 상태 격리와 제출 중복 방지에 참고한다. |

추가 후보인 [Muteki](https://github.com/FishCodeTech/muteki)의 verified finding/witness 구분은 근거 그래프에 도움이 되지만 AGPL-3.0 코드 자체를 가져오지 않는다. [OpenCode-for-CTF](https://github.com/h1kibi/Opencode-for-CTF), [yakisoba0728/ctf-solver-agent](https://github.com/yakisoba0728/ctf-solver-agent), [hongyime/ctfsolver](https://github.com/hongyime/ctfsolver), [HexMystic/ctf-agent](https://github.com/HexMystic/ctf-agent) 등은 특정 상태·메시지 버스 아이디어를 제공한다. 공개 독립 성능 비교가 없고 일부는 라이선스·제출 stub·유지보수 상태에 한계가 있어 핵심 설계를 이들에게 의존하지 않는다.

## 5. 문헌·운영 기록을 합친 개선 가설

1. **먼저 실행 가능한 환경을 보증한다.** 명령이 설치됐다는 사실과, solver 계정이 같은 바이너리·원격 서비스·GPU/커널 기능을 실제로 쓸 수 있다는 사실을 구분한다. 모델이 추론을 시작하기 전 저장공간·mount·권한·인증·원격 상태 오류가 있으면 Flag 획득 가능성은 0이다. 도구 총수보다는 문제가 요구하는 도구가 유효한 출력까지 내는지가 중요하다.
2. **관찰과 추정을 분리한다.** EnIGMA의 허구 관찰, CTFusion의 공개 정답 회수, 내부 운영의 `flag_not_submitted`/원격 입력 오판은 공통으로 ‘무엇을 실제로 확인했는가’를 흐릴 수 있다. 명령·출력·파일·Flag·oracle을 연결하면 잘못된 확신과 불필요한 사용자 요청을 줄일 수 있다는 **검증할 가설**이다. 아직 CTF Agent의 성공률 개선으로 입증된 것은 아니다.
3. **프롬프트는 더 짧거나 선택적일 수도 있다.** 원본 skill 구조를 유지하되 길이·중복·도구 부재 안내가 실제 결과에 미치는 효과를 측정한다. [기본 CLI 대조 연구](https://arxiv.org/html/2607.13085)와 [200문제 도구/프롬프트 실험](https://arxiv.org/html/2604.17159)은 보안 지침의 단순 추가가 향상을 보장하지 않음을 보여준다. 현재 `skill_web.md` 같은 긴 지침을 바로 삭제하거나, 특정 문제의 풀이법을 공통 지침에 넣지 않는다.
4. **상태 보존과 압축은 원문을 잃지 않아야 한다.** 같은 공급자에서 동일 세션 재개와 모델/공급자 변경 시 파일 handoff는 별개다. 제공자 응답이 실제 resume을 확인하기 전에는 ‘같은 세션’이라고 표시하지 않는다. 장황한 stdout은 원본 파일을 보존하고 모델에는 위치·해시·범위가 있는 요약을 준다. 잘못된 요약으로 결정적 단서가 사라지는지 측정한다.
5. **추가 역할은 막힌 뒤에만 제한적으로 검토한다.** 다중 solver와 Ultra 하위 에이전트는 어려운 문제에서 독립 가설을 병렬 시험할 수 있지만 같은 가설·도구·원격 시도를 중복해 wall-clock과 자원을 악화시킬 수 있다. 작업을 독립적으로 나눌 수 있고, 진척 없음이 관측되며, 남은 시간·자원이 충분한 경우에만 후보로 삼는다. 이 조건 자체도 A/B로 평가한다.
6. **사람의 개입은 성능 설계에 포함한다.** [USENIX Security 2026 현장 연구](https://www.usenix.org/system/files/usenixsecurity26-tang-tingxuan.pdf)는 새로운 17문제 대회에서 희소한 인간 개입이 일부 실패를 회복했다고 보고한다. 화면의 실시간 로그, 원격 주소/누락 파일 요청, steer 명령과 적용 시각은 문제 풀이 흐름의 일부다. 다만 개입이 많아야 해결되는 구조를 자율 성능 향상으로 포장하지 않는다.

## 6. 후보별 상세 적용·실험 계획

각 후보는 별도 변경으로 구현하고 **현재판과 같은 모델의 기본 CLI** 두 대조군을 유지한다. 후보를 여러 개 합쳐 한 번에 시험하면 원인을 알 수 없다. 아래 ‘채택’은 우선 opt-in 가능성을 판단하는 기준이며 기본값 승격은 §7의 보류셋·실전 검증 이후다.

### A. 재현 가능한 corpus·runner·oracle — 모든 성능 주장에 앞서는 P0

- **문제:** 현재 계획/보고 스크립트는 형식 검증만 하며 solver를 실행하거나 독립적으로 Flag를 판정하지 않는다.
- **변경:** 권한과 재배포 조건이 명확한 문제에 대해 설명·첨부·원격 이미지 digest·카테고리 원문·실행 명령·비공개 정답/동적 checker를 별도 manifest로 고정한다. 원격 인스턴스 시각과 종료도 기록한다. runner는 같은 문제를 기본 Codex/Claude CLI, 현행 CTF Agent, 단일 후보판에 배정하며 시작 전 파일 snapshot을 새로 만들고 이전 시도의 notes·브라우저·쿠키·검색 결과가 섞이지 않게 한다. 정답 oracle은 solver 컨테이너에서 읽을 수 없어야 한다.
- **검증:** 같은 입력 SHA-256에서 runner 재현, 다른 입력·Flag 유출·정답 파일 mount·동일 문제 중복 카운트·원격 서버 준비 실패를 거부한다. 중단/타임아웃도 실패가 아니라 별도 결과 코드로 보존한다.
- **채택:** 최소 한 다분야 개발셋과 튜닝에 사용하지 않은 보류셋을 실제 실행해 문제별 원본 로그·oracle 판정·비용/시간을 재생산할 수 있을 때만 개선 효과를 주장한다.

### B. 시작 전 환경과 도구의 ‘작동’ 점검 — P0

- **문제:** 저장공간·mount·인증·모델 route·원격 접속 실패는 모델 추론을 시작하기 전에 시간을 소모한다. 이미지 smoke가 통과해도 실제 solver 프로필·권한과 다를 수 있다.
- **변경:** 최종 이미지 digest와 solver 사용자·seccomp·volume·네트워크 프로필에서 분야별 **최소 실제 작업**을 실행한다. 예: 웹은 로컬 취약 앱을 열고 HTTP 요청/응답 재생, rev는 작은 바이너리 decompile과 실행 비교, pwn은 GDB 연결·레지스터/메모리 읽기, crypto는 검증 가능한 대수/격자 샘플, forensics는 원본 해시를 보존하며 파일/pcap 파싱. 필요한 순간에만 추가 도구의 사용 가능성을 조회한다.
- **검증:** 설치 유무·실행 가능·기능 결과·네트워크 접근·시간/메모리 피크를 각각 기록한다. `/volume`/WSL/일반 Docker 경로의 오판도 별도 fixture로 검사한다.
- **채택:** 새 도구 자체의 성공률 이득이 보이기 전에는 기존 도구의 잘못된 ‘사용 가능’ 안내와 startup 실패를 제거하는 것을 성공으로 본다. 도구 총수 증가를 성능 향상으로 보고하지 않는다.

### C. 실행 증거 사슬과 막힘 판별 — P0/P1

- **문제:** Flag 후보가 어떤 명령·출력에서 왔는지, 추가 입력이 진짜 필요한지, 유효한 가설을 어디까지 시험했는지 현재 이벤트만으로 완전하게 추적할 수 없다.
- **변경:** job·agent·operation ID를 기준으로 `가설 → 입력 변경점/명령 → 실제 출력의 위치·해시·종료 코드 → 결론(확인/반증/미확인) → PoC/Flag 파일 → oracle`을 연결한다. 일부 출력이 길면 원본은 solver 산출물에 남기고 UI/모델 요약에는 절단 표시와 원문 접근 경로를 둔다. Flag 문자열·토큰·세션 쿠키는 공개 로그/벤치 결과에서 제외한다. 원격 정보 요청은 ‘현재 주소가 없음’과 ‘외부 정보 없이는 논리적으로 불가능함’을 구분하고, 후자에는 로컬 단서·생성 경로·필수 의존성의 반례 검사를 요구한다.
- **검증:** 관찰하지 않은 출력의 인용, 거짓 Flag, 결과 불명 POST 재시도, 로컬 파일에 답 단서가 남은 상황에서의 잘못된 원격 요청을 여러 분야 fixture로 검출한다. 한 문제의 고유 해법을 공통 prompt에 하드코딩하지 않는다.
- **채택:** 오탐 추가 입력 요청과 잘못된 ‘Flag 발견’/중복 제출이 줄고, 실제 성공률·시간이 악화되지 않을 때 유지한다. 증거 수집이 느리면 필요한 경계에만 샘플링하되 원본 재현성은 보존한다.

### D. 도구 인터페이스: 상태 있는 세션과 발견 가능성 — P1

- **문제:** 대화형 debugger/원격 연결/GUI가 문제에 필수일 수 있다. 반대로 현재 CLI가 이미 충분하면 새 adapter가 오히려 지연·오류를 만든다.
- **변경:** 먼저 실제 로그에서 PTY/세션 소실 여부와 command 실패 원인을 분류한다. 확인된 경우에만 지속형 GDB·서버 연결 adapter를 선택적으로 제공한다. 기존 `curl`/브라우저/도구 명령은 유지한다. 도구 카탈로그는 설치된 명령만 보여주고 버전·최소 예제·필요 권한·출력 경로를 제공한다.
- **검증:** 같은 도구로 원래 가능한 pwn/web/rev 문제에서 일반 shell 대비 상태 복원, 명령 성공률, 출력 누락, 첫 유효 단서까지 시간, 전체 Flag 시간을 비교한다. 새 adapter가 강제 시작되지는 않는다.
- **채택:** 필요한 분야에서 정답 또는 시간의 이득이 검증되고 다른 분야의 오류·지연이 악화되지 않을 때 기본 제공한다. [EnIGMA의 분야별 ablation](https://openreview.net/pdf?id=Of3wZhVv1R)을 이식 효과로 가정하지 않는다.

### E. 원본 skill·프롬프트의 최소화 실험 — P1

- **문제:** 현재 공통 manual과 분야 skill은 원본 풀이 구조의 중요한 일부이지만 길고 중복된 문장이 첫 tool action을 늦추거나 탐색을 한 방향으로 고정할 가능성이 있다. 반대로 무리한 축약은 원본의 유용한 절차를 잃게 한다.
- **변경 후보를 분리:** E1은 현재 원본 manual/skill 그대로, E2는 동일한 도구·노트 계약을 보존하고 중복 문장만 줄인 판, E3은 상세 분야 지침을 문제의 관찰된 증거가 요구할 때만 불러오는 판이다. `unknown`/비표준 분야를 별도 층으로 두며 웹·crypto·rev만 기준으로 삼지 않는다. 특정 실패 문제의 flag, 해법, 취약점 종류를 공통 prompt에 넣지 않는다.
- **검증:** 각 arm의 시작 토큰, 첫 유효 명령까지 시간, 불필요한 탐색·근거 없는 단정, Flag 성공, 어려운 분야별 회귀를 기록한다. 같은 모델·런타임·도구·문제 snapshot에서 prompt만 바꾼다.
- **채택:** 보류 문제에서 검증된 Flag 획득 또는 시간 개선이 있고 중요한 분야의 반복 실패가 늘지 않을 때만 기본값을 바꾼다. 인상적인 한두 사례로 전체 prompt를 교체하지 않는다.

### F. 중단·재시작·컨텍스트 압축의 성능 — P1

- **문제:** 실패 후 ‘다시 풀기’가 실제 동일 공급자 세션인지, 파일 handoff인지, 신규 시도인지에 따라 앞선 분석 재사용 정도가 다르다. 원본 대화 로그를 무작정 다시 넣으면 컨텍스트와 시간이 낭비되고, 너무 많이 압축하면 결정적 관찰이 사라진다.
- **변경:** job에 `native_session | workspace_checkpoint | fresh`와 선택 이유·공급자 ack·세션 ID/런타임·입력 fingerprint를 남긴다. 같은 공급자·계정·모델·설정과 유효 세션이 확인되면 native resume을 시도하고 실패하면 `ANALYSIS/VULN/NEXT`와 산출물에 근거한 checkpoint로 전환한다. Codex↔Claude 전환은 동일 세션이라고 부르지 않는다. 모델에 주는 요약과 사용자가 볼 수 있는 원본 실행 로그를 분리하고 압축 전후 중요한 명령·결과·미검증 가설의 출처가 유지되는지 검사한다.
- **검증:** 중단 직전/직후의 동일 가설 재실험 횟수, 첫 유효 action까지 시간, Flag 시간, 잘못된 중복 원격 요청/POST, 실제 native resume 성공률, context 사용률의 **측정 가능 여부**를 평가한다. 공급자가 퍼센트를 내지 않으면 추측값 대신 `측정 불가`로 둔다.
- **채택:** 같은 세션이라고 표시한 항목의 공급자 ack가 100% 존재하고, checkpoint 전환에서 사실이 유실되지 않으며 풀이 시간이 증가하지 않을 때 유지한다.

### G. 조건부 병렬 풀이·모델/추론 승격 — P2

- **문제:** 단일 어려운 문제에서 독립적인 접근이 도움이 될 수 있지만, N개의 solver가 같은 원격 서비스와 리소스를 경쟁하면 속도와 정확도가 나빠질 수 있다. Ultra와 높은 추론 수준도 하위 에이전트 생성이나 더 빠른 풀이를 보장하지 않는다.
- **변경:** 기본은 단일 solver다. 유효한 가설이 반복 실패하고 새로운 증거가 일정 시간 나오지 않으며, 문제를 독립 부분작업으로 나눌 수 있고 원격 동시 연결 제한·CPU/RAM·계정 한도가 허용할 때만 추가 solver/하위 에이전트 또는 모델/추론 승격을 제안한다. 사용자가 사전 허용한 범위에서만 자동 승격한다. 각 worker는 가설·범위·시도 예산을 달리하고, 공통 메모리에 넣는 것은 출처 있는 finding만으로 제한한다. 확인되지 않은 후보 Flag를 형제에게 확정 사실로 전파하지 않는다.
- **검증:** 단일 solver 대비 문제별 성공률, 최초 검증 Flag까지 wall-clock, CPU/RAM 최대, 중복 명령/원격 요청, 비용, 사람 개입과 취소 후 잔존 프로세스를 함께 기록한다. 원격이 팀당 한 세션인 문제에는 병렬 원격 연결을 생성하지 않는다.
- **채택:** 어려운 문제의 보류셋에서 wall-clock 또는 검증 성공의 재현 가능한 이득이 있어야 opt-in을 유지한다. 전체 기본값 변경은 실제 라이브/새 문제로도 확인한 후에만 결정한다.

### H. 선택형 분야 도구팩과 특수 환경 — P2

- **문제:** 어떤 문제는 SageMath, REA, ILSpy, Foundry, 특수 kernel/GUI/GPU 환경이 필요할 수 있지만 모든 이미지에 항상 넣으면 배포·시작·유지비가 늘고 도구 선택 혼란이 생긴다.
- **변경:** 입력 파일/실행 오류에서 필요성이 드러난 때에만 별도 고정 digest·버전·라이선스가 있는 tool pack 또는 적절한 격리 실행 프로필을 선택한다. REA는 Ghidra/JADX/radare2/angr와 겹치는 부분을 실제 rev fixture에서 측정한 뒤 채택한다. CVE/원데이 예제와 공개 풀이를 정답으로 사전 주입하지 않는다. 특수 하드웨어와 GUI는 그 문제의 입력·실행 요구가 확인될 때 도입한다.
- **검증:** 동일 모델의 현재 도구 대 새 팩을 같은 과제에서 비교하고 설치 크기, 최초 사용까지 지연, 실패율, 보안·자원 프로필, 재현성을 포함한다. 분야별 결과를 섞어 평균만 보고하지 않는다.
- **채택:** 특정 입력군에서 실제 Flag 획득이나 필수 단계 통과가 개선되고 비용·라이선스가 수용 가능할 때 opt-in으로 둔다. 대중적이라는 이유만으로 기본 이미지에 추가하지 않는다.

### I. 제출과 write-up을 풀이의 임계 경로에서 분리 — P0/P1

- **문제:** Flag 후보 발견 뒤 write-up 재시도나 CTFd 인증 문제가 ‘문제를 못 풂’으로 보일 수 있다. 결과 불명 POST를 자동 반복하면 대회 시도 제한을 낭비한다.
- **변경:** Flag 최초 관측 즉시 저장·UI·Telegram 갱신하고, 실제 검증을 비동기·명확한 상태로 표시한다. CTFd 자동 제출은 작업공간의 명시적 선택을 따르며, POST가 서버에 도달했는지 불명확하면 조회/확인 전 자동 재POST하지 않는다. write-up은 보존된 풀이 근거로 후속 생성하며 내부 agent 명령/CTFd 자동제출 명령을 독자용 코드 블록에 넣지 않는다.
- **검증:** Flag 발견 시각, 공식 정답 판정 시각, 알림 시각, write-up 완료 시각을 따로 기록한다. write-up 실패·제출 인증 실패·수동 완료를 Flag 풀이 실패로 합산하지 않는다.
- **채택:** 첫 Flag의 저장/알림 누락이 없고, 불명확 제출에서 중복 POST가 없으며, 문제 풀이 중 후속 작업 때문에 solver가 중단되지 않을 때 기본 흐름으로 유지한다.

### J. 연결·복제 문제의 선택형 근거 공유 — P2

- **문제:** 이전 문제에서 확인된 프로토콜·파일 형식·취약 구성 요소가 다음 문제의 출발점일 수 있다. 반면 같은 문제를 모델별로 복제한 작업공간 두 곳과 정말 이어지는 별개 문제를 한 종류의 연결로 취급하면, 과거 정답 유출과 벤치마크 독립성 붕괴가 생긴다.
- **변경:** 출처 문제 ID와 관계 종류를 분리한다. 관계는 동일 원본의 복제, 선후가 없는 관련 문제, 명시된 전제 자료의 세 가지로 기록하되 연결 방향이 불분명할 때 선행/후행을 임의로 만들지 않는다. 공유할 정보는 사용자가 선택한 확인된 finding, 재현 파일의 해시, 적용 가능한 조건과 만료/변경 시각만이다. 이전 Flag·세션 쿠키·계정·원격 접속 비밀·미확인 추측은 자동 주입하지 않는다. 관련 문제가 두 개의 복제본에 동시에 존재하면 원본 ID와 provenance로 하나의 논리적 근거를 식별하고, 각각의 시도에서는 접근 허용 여부를 별도로 기록한다.
- **검증:** 같은 정보가 없는 단일 풀이와 공유한 풀이를 동일 조건에서 비교하고, 연결이 틀렸거나 전제가 바뀐 fixture에서 오도·시간 낭비·정답 누출을 측정한다. 벤치 보류셋에서 같은 문제의 형제 풀이가 공유되면 해당 시도를 독립 성능 평가에서 제외한다.
- **채택:** 실제 연계 문제에서 첫 유효 단서와 정답 시간이 개선되고 무관한 문제의 성능 악화나 검증 정보 유출이 없을 때만 사용자가 켜는 기능으로 둔다.

### 6.1 현재 코드에 붙이는 최소 변경 경계

아래 표는 **구현 지시의 후보**다. 기존 기능을 새로 만들었다고 주장하지 않도록 실제 존재하는 경계를 표시한다. 구현 시 함수명·스키마는 그 시점의 코드에서 다시 확인한다.

| 후보 | 현재 존재하는 경계 | 추가해야 할 계약과 회귀 |
|---|---|---|
| A 평가 기반 | `scripts/benchmark_plan.py`의 `build_plan`과 `scripts/benchmark_report.py`의 두 arm 형식은 일정을 만들고 결과 메타데이터를 검사한다. 비공개 정적 후보 23개와 서비스 후보 3개는 수집됐으나 모델 시도는 없다. | 운영 DB와 분리된 runner, 실제 판정 가능한 비공개 oracle, `candidate:<id>` arm, 복제 그룹 ID, 입력/환경 digest와 시도별 원본 trace를 갖춘다. trial key는 실험·case·반복·arm으로 고유하게 하고 CTFd 자동 제출이 꺼진 격리 인스턴스를 사용한다. 실행기가 없는 상태에서 보고서 형식 검사를 성능 통과로 부르지 않는다. |
| B 환경 기능 검사 | `deploy/image-smoke.py`와 `solver_worker.py`의 runtime attestation·provider sandbox canary, `solver_exchange.py`의 staging/저장공간 검사. | 최종 이미지 digest·사용자·mount·seccomp·network 프로필을 맞춘 실행 결과를 남긴다. 캐시 키는 이미지·런타임·보안 프로필 digest로 잡아 매 문제마다 무거운 분야 스모크를 반복하지 않는다. |
| C 증거 사슬 | `solver_worker.py`의 `_report_activity`는 일부 활동 근거 메타데이터를 이미 남기고 `solver_exchange.py`의 event 검증/`_commit_event`가 이를 받는다. | 기존 activity ID를 기준으로 가설, 원문 산출물 상대경로/해시, 종료 코드, 결론, Flag 출처를 연결한다. 원본 stdout 전체를 공개 DB 이벤트에 복제하지 않는다. 짧은 UI 로그 샘플과 비공개 원문 인덱스를 분리한다. |
| D/E 도구·프롬프트 | `agent_workspace.py`의 `assemble_manual/prepare_agent_workspace`가 기존 skill과 tmux 지침을 조립한다. Codex/Claude driver가 실제 턴을 수행한다. | PTY 손실이 재현될 때만 지속 세션 adapter를 실험한다. E1 원본/E2 중복 축약/E3 증거 기반 skill 선택을 소스 덮어쓰기 없이 prompt variant digest로 고정한다. 원격 없음·비표준 분야 fixture를 모두 포함한다. |
| F 재개/압축 | `solver_exchange.py`에 `continuation_mode/continuation_confirmed`, `_store_continuation`·`_continuation_for_stage`가 있고 `solver_continuation.py`가 snapshot을 보존한다. | 현행 모드 `fresh/checkpoint/workspace/session`을 유지하며 요청 모드, 실제 모드, provider ack, 입력 digest, fallback 이유를 별도 기록한다. `solver_time.py`의 활성 시간 계산과 대조해 중단 공백을 제외하고, 공급자 교차 재개는 session이 아니라 workspace handoff로 표시한다. |
| G/H 조건부 병렬·도구팩 | `solver_service.py`의 Ultra 요청과 `solver_exchange.py`의 coordinator pool/autoscaler가 이미 있다. 이미지·툴체인은 `Dockerfile.toolchain`, `toolchain.lock`, `deploy/image-smoke.py`에서 관리한다. | 기존 ask/auto 선택을 유지하고 추가 worker마다 서로 다른 가설·예산·원격 제한을 검증한다. 도구팩은 버전·digest가 고정된 선택형 후보로 시험한다. 기본 이미지에 먼저 합치지 않는다. |
| I Flag·제출·write-up | worker의 Flag watcher, coordinator의 Flag/write-up 이벤트, Telegram hook, `ctfd_submit.py`의 POST 전 dispatch 영속화·결과 불명 조회가 이미 있다. | 그 비동기 경계를 유지하면서 Flag 저장→알림→공식 판정→write-up 시각을 분리한다. 문제 status의 `solved` 또는 수동 완료만으로 CTFd accepted라고 세지 않는다. 검증된 결과는 독립 oracle이나 CTFd 제출 결과로 확인한다. |
| J 연결 문제 | 작업공간의 관련 문제 context와 복제 기능이 있다. | 동일 문제 복제 관계와 관련 문제 관계를 구분하고 finding의 출처·검증 상태·사용자 선택을 붙인다. 다른 시도의 정답/비밀값을 벤치 arm에 넘기지 않는 격리 테스트를 추가한다. |

가장 중요한 순서는 **A의 판정기·실행기 → B의 실제 환경 검사 → 현재판 기준선 → 후보 한 개씩 비교**다. C/F/I는 기본 메커니즘이 이미 있으므로 무조건 재설계하지 않고 누락된 provenance·상태·계측만 좁게 보완한다. 특히 현재 문제 상태의 `solved`는 write-up 완료나 수동 처리와 섞일 수 있으므로 공식 oracle의 `accepted`와 절대 같은 값으로 저장하지 않는다.

## 7. 실제 A/B 평가 프로토콜

### 7.1 문제셋을 먼저 고정한다

- **스모크:** 대략 12개 짧은 다분야 fixture로 기동·도구·oracle·이벤트 계약을 점검한다. 이 결과로 풀이 성능 향상을 선언하지 않는다.
- **개발:** NYU 개발셋·자체 재현 문제 중 분야/난도·원격 유무·파일 크기를 나눈 문제를 사용한다. 공개 정답·write-up의 존재와 모델이 웹에서 직접 조회했는지 표시한다. 특정 실패 1개를 고친 규칙은 다른 유형 문제에서도 오탐을 조사한다.
- **보류:** 개발에 쓰지 않은 최소 수십 개의 서로 다른 challenge를 사전에 정하고 입력 해시를 봉인한다. 공개 보류셋도 모델의 사전학습으로부터 숨겨진 문제는 아니다. 가능하면 신규 비공개/라이브 문제를 별도 외삽 검증층으로 둔다. 대회 약관과 원격 동시 연결 제한을 따른다.
- **분야:** 웹·crypto·rev·pwn·forensics·misc와 `unknown`/복합 분야를 포함한다. CTFd category 문자열을 강제 정규화하지 않고 원문 라벨과 사후 분석 라벨을 별도 저장한다. 복제 문제는 독립적인 고유 문제가 아니라 같은 case의 반복으로만 센다.
- **격리:** 고정 입력 SHA-256, 원격 이미지/인스턴스 fingerprint, 공개 시각, 문제 자료 권리, oracle 종류/버전, 시험 전 공개 write-up 여부를 manifest에 남긴다. Flag와 비밀번호는 manifest/solver workspace/공개 결과표에 담지 않는다. [NYU 공개 저장소](https://github.com/NYU-LLM-CTF/NYU_CTF_Bench)의 dataset checkout·metadata·Python 패키지에서 정답을 읽거나, sibling 작업 메모리/웹에서 답을 복사할 수 없는지도 검사한다. oracle 격리와 실제 exploit 근거 감사를 별개로 수행한다.

### 7.2 대조군과 한 번에 바꿀 요소

1. **B0 기본 CLI:** 동일 Codex 또는 Claude Code 버전, 모델, 계정·인증 유형, 추론/티어, 이미지/툴체인, 네트워크, 문제 설명/파일만 제공한다. CTF Agent의 추가 manual·자동 후속 작업은 뺀다. 이것이 모델+일반 CLI의 기여도다.
2. **B1 현재판:** 같은 조건에서 현재 원본 skill·notes·solver 흐름을 사용한다. B0 대비 서비스 하네스 전체 효과를 본다.
3. **Cᵢ 후보판:** B1에서 A~J 중 **하나의 변경만** 적용한다. 도구팩 평가라면 이미지/tool-policy digest 변화가 실험 변수라는 점을 manifest에 명시하고 나머지 통제값은 같다. 현재 `benchmark_report.py`의 B0/B1 두 arm 스키마는 Cᵢ와 이 예외를 표현하지 못하므로 runner와 보고 형식을 먼저 확장해야 한다.

문제·반복 순서의 AB/BA 교차 배치를 사전에 생성하고, 시도마다 새 작업 디렉터리·쿠키·서비스 상태를 제공한다. 같은 공급자라도 서로 다른 계정이나 API 키와 구독형 CLI를 한 arm에 섞지 않는다. 모델·추론·Ultra/Ultracode·1.5배 티어·런타임/이미지 digest를 매 시도에 기록한다. 불가피하게 모델 버전이 바뀌면 이전 run과 합산하지 않고 새 실험으로 분리한다. 여러 solver의 집계는 문제 단위로 클러스터링하며 동일 문제 반복을 표본 수 부풀리기에 쓰지 않는다.

### 7.3 성공, 속도, 비용을 별도로 보고한다

**1차 지표**는 미리 정한 제한 시간 안에 독립 oracle이 `accepted`로 확인한 문제 비율과, 그 정답까지의 활성 풀이 시간이다. Flag 패턴만 찾은 시도는 후보로만 둔다. 기본 시간 한도는 작은 스모크와 어려운 문제에서 다르게 사전 등록한다. 실패의 ‘완료 시간’을 성공의 시간으로 취급하지 않으며, 성공 사례만의 평균 시간으로 빠른 arm을 선언하지 않는다. 제한 시간별 성공률 곡선과 고정 deadline에서의 성공 문제 수를 함께 본다.

**시간 분해**는 큐 대기, 입력 staging, runtime 준비, 첫 모델 응답, 첫 도구 명령, 도구 실행, 원격 대기, Flag 최초 관측, 공식 검증, write-up을 별도 타임스탬프로 기록한다. 중단 뒤 재시작 사이의 비활성 시간은 활성 풀이 시간에서 제외하고, 사용자 관점의 전체 경과 시간은 별도 열에 둔다. 현재 작업 트리의 timing 필드가 이 전부를 측정하지는 않으므로 없는 수치를 0으로 채우지 않는다.

**2차 지표**는 pass@1과 독립 반복의 pass@k를 구분하고, 검증되지 않은 후보·오답 제출·추가 입력 오탐/누락·권한/공급자 오류·시작 실패·중복 원격 동작·사람 개입 횟수·CPU/RAM peak·토큰·추정 비용을 포함한다. 비용은 공급자 실측 또는 버전 고정 가격표로 산출하고, 누락값은 `unknown`이다. write-up 품질은 풀이 성공률이 아니라 후속 출판 품질로 따로 평가한다.

### 7.4 결정 규칙과 부정적 결과

먼저 3회 정도의 소규모 예비 실험으로 runner/fixture의 결함만 찾는다. 이것만으로 우수성을 선언하지 않는다. 본 실험의 반복 수·문제 수·카테고리/난도 가중치·성공 deadline·최소 의미 있는 효과를 결과를 보기 **전에** 등록한다. paired case 차이와 불확실성 구간을 제시하며, 스크립트가 표본 부족/동일 결과 때문에 구간을 계산하지 못하면 ‘불확실’로 둔다. 타 논문의 절대 수치와 직접 순위를 매기지 않는다.

기본값 승격에는 (a) 보류셋의 독립 oracle 성공이 증가하거나, 성공률의 실질적 악화 없이 성공까지 시간이 줄고, (b) 분야별 치명적 회귀·중복 제출·자료 손실·복구 실패가 없으며, (c) 추가 CPU/RAM·토큰·운영 부담이 이득에 비례해야 한다. 작은 표본에서 차이가 애매하면 기본값 승격을 보류하고 opt-in 실험만 유지한다. 특정 분야에서만 유리하면 그 분야의 **입력 증거가 있을 때만** 활성화한다. 악화가 반복되면 되돌리고 음성 결과를 결과표에 남긴다.

공개 문제에서 인터넷으로 기존 풀이를 찾은 경우는 실사용 성공으로 보일 수 있지만 **하네스의 독립 풀이 능력** 증거는 아니다. 답의 최초 출처를 기록하고 ‘검색된 공개 정답’과 ‘실행해 얻은 Flag’를 따로 보고한다. 라이브 대회에서는 별도의 숨겨진 자료를 만들어 평가할 수 없는 만큼 주최측 판정·사전 공지된 시간/비용·문제 출처를 보존한다.

## 8. 단계별 수행 순서와 산출물

| 단계 | 산출물 | 다음 단계로 가는 조건 | 현재 상태(2026-11-04 작업 트리 기준) |
|---|---|---|---|
| 0. 문헌·현황 고정 | 이 문서, 소스 URL/조회일, 현행 CLI·이미지·prompt fingerprint | 외부 수치와 현재 코드 주장을 구분 | 조사 완료, 성능 실측 전 |
| 1. corpus·oracle·runner | 재현 가능한 다분야 manifest, B0/B1/Cᵢ 실행기, AB/BA 일정 | Flag 비공개, 입력/결과 재현, 중복 case 방지 | 정적 후보 23개와 분리된 판정 메타데이터 준비; 서비스 3개 미기동, 웹·pwn 등 실행 범위 미충족, 실제 arm 실행기/결과 없음 |
| 2. 기준선 계측 | 기본 CLI와 현행판의 문제별 로그·공식 판정·시간/토큰/자원 | 같은 조건에서 최소 한 개발·보류 평가 완료 | 미실행 |
| 3. 풀이 차단 오류 해결 | 시작 전 환경 probe, 원격/인증/스토리지 원인 코드, 부작용 있는 제출 상태 | 실패를 원인별 재현하고 데이터·Flag 손실 없이 복구 | 일부 코드 변경은 미커밋·배포 미검증 |
| 4. 작은 후보 A/B | C~F를 각각 따로 비교한 결과표 | 입증된 개선만 다음 후보와 합치기 | 미실행 |
| 5. 어려운 문제 확장 | 조건부 분업/승격, 선택형 도구팩의 분야별 결과 | 단일 solver 대비 시간·성공·자원 이득 | 미실행 |
| 6. 신규/실전 점검 | 오염 가능성을 기록한 새 대회/허가된 문제의 결과 | 재현 가능한 이득과 운영 회귀 없음 | 미실행 |

문서 작성 시점에는 **CTF Agent가 기본 CLI보다 빠르다, 더 많이 푼다, 특정 모델/Ultra가 우월하다**고 주장할 실측 자료가 없다. 실제 성능 순위나 도구의 기본 채택은 단계 1~6의 결과를 받은 뒤 이 문서의 결과 표에 기록한다. 문서화 작업 동안 풀이 코드와 서버 배포는 진행하지 않는다.

## 9. 결과 기록 표준

향후 한 실험의 공개 가능한 요약은 다음 열을 갖는다. `experiment_id`, 사전 등록 시각, 문제셋·입력 digest, 공개/라이브 구분, 문제 수/분야, B0/B1/Cᵢ 변경 한 가지, 모델·CLI·이미지 digest, 동일 예산 여부, 독립 시도 수, 공식 accepted 수, deadline별 성공 수, 정답까지 시간 중앙값/P90, 토큰·비용 누락률, 추가 입력/시작/도구/제출 실패 수, 오염 의심 수, CPU/RAM peak, 결과 데이터/재현 스크립트 digest, 채택/보류/철회 결정과 이유. 실제 Flag·계정 정보·비공개 파일은 보고서에서 제외한다.

이 문서는 연구·실행 계획의 **단일 진입점**이다. 추가 연구가 나오면 이곳의 출처·가설·판정과 결과 상태를 먼저 갱신하고, 세부 구현 문서나 `docs/local/todo.md`는 이 문서의 항목 ID를 참조하게 한다. 다른 날짜의 로컬 조사 스냅샷을 현재 성능의 증거로 인용하지 않는다.

## 부록 A. 기존 문서 대조 기록

이 문서는 다음 자료를 모두 읽고 **풀이 성능과 직접 연관된 부분만** 가져왔다. 로컬 `docs/local/`은 Git에서 제외되어 공개 저장소에서 볼 수 없었다. 이 문서가 공개 가능한 단일 출발점이 되도록 개인 인프라와 비밀정보는 옮기지 않았다.

| 대조한 문서·코드 | 가져온 핵심 | 이번에 바로잡거나 남겨 둔 차이 |
|---|---|---|
| `docs/local/research/CTF_AGENT_HARNESS_RESEARCH_2026-11-01.md` | 19개 외부 저장소 후보, 다분야 도구 갭, 기본 CLI 대조·증거 사슬·조건부 병렬 우선순위 | 2026-11-01의 star와 도구/prompt 스냅샷을 재조회·현행 코드와 대조했다. CTF-Dojo +11.6%p를 **학습한 32B의 3벤치 평균 pass@1 상승**으로, CTFusion 14.4/6.3을 **pass@3**로 정확히 기술했다. |
| `docs/local/research/CTF_AGENT_REPOSITORIES_AND_INCIDENTS_2026-11-01.md` | 비교 저장소의 실제 코드 경로, 시작·원격·제출·로그·복구 사고의 원인 확실성, 기존 agent를 통째로 대체하지 않는 설계 | 당시 사고 횟수를 현행 배포판의 결함 건수로 다시 주장하지 않았다. 개인 인프라·문제 정답·인증 정보도 옮기지 않았다. |
| `docs/local/research/CTF_AGENT_ANALYSIS_2026-11-01.md` | 모델/worker·재풀이·CTFd 신뢰성 및 각 후보의 실행 순서 | 그 문서의 일부 제안은 현재 미커밋 코드와 중복하므로 ‘이미 운영에서 입증됨’으로 바꾸지 않았다. 성능 변화는 아직 동일 조건 A/B로 입증되지 않았다. |
| `docs/local/research/CTF_AGENT_LOG_SESSION_RELEASE_DESIGN_2026-11-01.md` | 전체 로그에서 명령/결과 귀속, native resume과 파일 handoff의 구분, 공급자 컨텍스트 퍼센트의 의미 | UI 자체보다는 풀이 중 인간 개입·압축·재시작이 시간/정확도에 미치는 부분만 반영했다. 토큰 누적량과 활성 컨텍스트 사용률을 혼용하지 않는다. |
| `docs/benchmarking/protocol.md`, `docs/benchmarking/preflight-audit.md`, `scripts/benchmark_plan.py`, `scripts/benchmark_report.py` | 사전 일정, 동일 조건·AB/BA, 입력 해시, oracle·비용 출처, paired 보고, 비공개 후보 corpus의 준비 상태 | 정적 후보가 준비됐지만 실제 arm 실행기/공식 성공 결과는 없다. 두 arm 스키마는 세 번째 후보판과 의도적인 도구 환경 변화까지 표현하지 못한다. 형식 검증을 성능 검증으로 오인하지 않는다. |
| `docs/local/todo.md`와 현재 `agent_workspace.py`·`solver_worker.py`·`solver_exchange.py`·`deploy/image-smoke.py`·프롬프트 | 작업 우선순위와 현재 원본 solver 구조·도구/시각/이벤트 계약 | 프롬프트의 원격 Flag 단정, 선택 도구의 설치 보장 여부, 최종 배포 digest의 실행 증거, 실제 첫 모델/도구/원격 시간은 미검증/미계측으로 남긴다. |

## 부록 B. 검증과 출처에 대한 추가 연구

- [CTF-ABACUS, 2026 preprint](https://arxiv.org/html/2608.26237)는 여섯 모델의 240개 문제·1,435번 시도에서 2,870개의 두 judge 관점 solve profile을 분석했다. 저자에 따르면 회수된 Flag 중 trace에서 실제 exploit가 확인된 것은 benchmark에 따라 62–87%였다. 자동 trace 판정에도 분류 오차가 있으므로 우리 평가의 공식 Flag oracle과 행동 증거 감사를 **서로 다른 열**로 보관한다. 이 수치를 곧바로 우리 서비스의 허구 성공률로 적용하지 않는다.
- [Reveree, 2026 preprint](https://arxiv.org/html/2609.01185)는 picoCTF/NYU의 88개 rev 문제·9개 모델·4개 prompt에서 8단계 진척을 평가한다. comprehension 단계는 결과를 보지 않는 LLM judge를 사람 전문가와 대조하고, 나머지는 결정적으로 확인한다. 추가 시간·추론 수준이 초반 이해 실패를 항상 구제하지 못했다. 따라서 rev에서 무조건 Ultra/시간만 늘리기보다, 바이너리 구조 이해→가설→동적 확인→solver 작성의 어느 단계가 막혔는지 먼저 측정한다. LLM judge의 판정 불확실성도 명시한다.
- [USENIX Security 2026 현장 CTF 연구](https://www.usenix.org/conference/usenixsecurity26/presentation/tang-tingxuan)는 새 문제를 실제 대회에서 인간 참여자와 자율 agent가 풀도록 비교했다. 95명 중 연구 참여 41명의 협업 기록과 4개 agent의 궤적을 관찰했다. 이 설계는 공개 문제 반복의 한계를 보완하지만 한 대회·당시 모델/도구로의 외삽 한계가 있다. 우리 서비스에서는 steer/원격 요청/GUI 관련 사용자 개입을 ‘풀이 도움’과 ‘agent가 스스로 푼 성과’로 분리 기록한다.
- [PwnAgent](https://link.springer.com/article/10.1186/s42400-026-00649-5)의 66문제와 [AgentRE-Bench](https://github.com/agentrebench/AgentRE-Bench)의 구조화 점수는 각각 분야 진단에는 강하지만 전 분야 CTF 성공률의 대체 지표가 아니다. 단순한 star 수, 공개 대회 한 번의 만점, 타 논문의 서로 다른 모델 순위도 우리의 성능 판정으로 쓰지 않는다.

## 부록 C. 기존 조사 문서의 나머지 후보를 어떻게 처리했는가

주요 비교표에 없는 자료도 버리지 않았다. 이 표는 **직접 도입을 보류한 이유**까지 남겨, 인기 있는 저장소나 큰 숫자가 새로 보일 때마다 기본 하네스를 흔드는 일을 막는다. 아래의 과제·모델·판정은 서로 달라 가로로 순위를 매길 수 없다.

| 자료 | 실제 범위와 이번 판단 |
|---|---|
| [CrackMeBench](https://arxiv.org/abs/2605.10597) | 공개 보정 8개와 C/Rust/Go로 생성한 12개 rev 바이너리를 5분·세 번 제출·동일 shell로 평가한다. 생성 문제의 pass@3 성적은 분야 소형 진단값이지 복잡한 실제 rev의 예상 해결률이 아니다. 짧은 rev fixture의 독립 실행 oracle, stripped/언어별 실패 분류에 참고한다. |
| [AICrypto](https://arxiv.org/abs/2507.09580) | 개념 질문 135개, crypto CTF 150개, 증명 과제 30개를 구분한다. 암호학 지식 객관식 정답이 코드 작성·실행·Flag 검증 능력을 뜻하지 않으므로 이 서비스의 crypto 성능표는 CTF 실행 과제만 사용한다. |
| [AgentCTF × AgentXploit 공식 결과](https://ctf.secure-agent.com/agentctf_report_2026.pdf) | 공개 CVE 재현 20개(개발 10·숨김 10), 유효 제출 13건에 대한 주최 측 분석이다. 짧은 구조, task-adaptive 지침, 개발 문제 하드코딩의 과적합을 지적하지만 작은 표본과 LLM 보조 판정이 있다. CTF 전 분야의 승자 구조로 가져오지 않고 보류셋 누출 검사에 참고한다. |
| [DeepRed, AIware 2026](https://arxiv.org/html/2604.19354v2) | 격리 VM의 10개 CTF 목표와 단계별 checkpoint를 제공한다. 저자 예비 실행에서는 핵심 과제의 root Flag 획득이 없었고 최고 모델의 평균 checkpoint 완료는 약 35%였다. 부분 진척은 실패 위치 진단에 유용하지만 요약→judge가 붙은 중간 점수와 공식 Flag 판정은 별도로 보관한다. |
| [Open Trajectory Gym](https://github.com/vecna-labs/open-trajectory-gym) | Cybench에서 기본/지도학습/강화학습 성적을 공개한 후훈련 프레임워크다. 모델 학습 효과와 현행 서비스 하네스 효과를 분리한다. 당장은 원본 trace와 판정 데이터를 보존하는 형식만 참고한다. |
| [h5i websec bench](https://github.com/h5i-dev/h5i-websec-bench) | 공개 웹 과제를 HTTP 요청·응답 캡처와 재실행 중심으로 기록한 작은 프로젝트다. 실제 브라우저→curl 전환에서 상태·쿠키가 사라지는 문제가 재현될 경우에만 그 캡처 방식을 비교한다. 자체 성적은 독립 검증으로 보지 않는다. |
| [SRE-Bench](https://arxiv.org/abs/2608.11469) | 비공개 대형 rev 프로그램 19개로부터 262개 바이너리·1,572개 결정적 평가 항목을 만든다. 정답 오염 방지와 바이너리 규모라는 원칙은 강하게 참고하되 CTF Flag 문제와 목표가 다르므로 성능 수치를 합치지 않는다. |
| [AgentCyberRange](https://arxiv.org/abs/2606.14295), [CyberGym](https://arxiv.org/abs/2506.02548) | 전자는 다중 호스트 범위·실제 웹앱 15개/취약점 110개, 후자는 프로젝트 188개/취약점 1,507개에서 PoC 재현을 평가한다. 우리 일반 CTF 문제의 oracle을 대신하지 않으며, 훗날 특수 원격/장기 작업을 별도 시험할 때만 참고한다. |
| [DFIR-Metric](https://arxiv.org/abs/2505.19973) | 포렌식 지식 객관식 700개, CTF형 150개, 디스크/메모리 사례 500개를 나눈다. 파일·PCAP·메모리 아티팩트의 실제 파싱과 증거 교차 검증을 우선하고 지식 문답은 도구 작동 시험에 섞지 않는다. |
| [HarnessSecurity-Bench](https://arxiv.org/abs/2610.07639) | 23개 과제·여섯 coding harness·2,500회 시도에서 기능 완료와 실행 통제의 상호작용을 본다. 네트워크/GUI/커널 등 실행 프로필을 바꿀 때 정답률뿐 아니라 다른 서비스와 공유 자원의 영향을 함께 시험한다. 이 수치를 CTF solve rate로 변환하지 않는다. |
| [NDSS BAR 2026 rev 실패 분석](https://www.ndss-symposium.org/wp-content/uploads/bar2026-58.pdf) | 24개 rev 문제·세 agent 로그에서 관측 과신, 계획 고착, 학습 편향, 컨텍스트 손실을 분류한다. Ghidra 출력 자체를 결론으로 삼지 않고 실행/assembly와 대조하는 provenance 테스트에 참고한다. 작은 표본의 실패 유형 빈도를 전 분야에 일반화하지 않는다. |
| [Cyber-Zero](https://arxiv.org/abs/2508.00910) | 공개 write-up으로 합성한 trajectory로 **모델을 후훈련**한다. 저자 상승폭은 런타임 서비스 패치의 기대치가 아니며 공개 정답 노출도 평가에 영향을 준다. 추후 별도 학습 프로젝트가 아닌 이상 기본 solver의 자료 공급 경로로 넣지 않는다. |
| [KryptoPilot 철회 공지](https://arxiv.org/abs/2601.09129) | 저자들이 최종 내용에 동의하지 않고 연구 기여로 인용하지 말라고 명시했다. 성능 수치와 도구 추천의 근거로 사용하지 않는다. |

기존 참고 저장소 중 [yakisoba0728/ctf-solver-agent](https://github.com/yakisoba0728/ctf-solver-agent)는 challenge별 메시지 버스와 circuit breaker, [hongyime/ctfsolver](https://github.com/hongyime/ctfsolver)는 공급자 사이의 파일 handoff, [HexMystic/ctf-agent](https://github.com/HexMystic/ctf-agent)는 모델 단계 변경과 선택형 병렬, [Conly-Zy/CTF-Agent](https://github.com/Conly-Zy/CTF-Agent)는 제한된 worker와 취소 흐름, [rmjohnson12/CTF_Agents](https://github.com/rmjohnson12/CTF_Agents)는 checkpoint/trace를 참고할 수 있다. 그러나 본문 §4의 대형·검증 자료가 있는 프로젝트보다 독립 평가 자료가 부족하며 일부는 라이선스·제출 구현 상태가 불명확하다. 해당 아이디어는 각각 C/F/G 후보와 중복하므로 별도 프레임워크를 이식하지 않는다. [OpenCode-for-CTF](https://github.com/h1kibi/Opencode-for-CTF)는 도구 묶음과 팀 모드 후보이며 H/J의 비교군으로만 둔다. 각 저장소의 2026-11-01 star/최근 변경 스냅샷은 기존 로컬 문서에 보존돼 있고, 이번 문서에서 재확인하지 않은 수치를 현재값처럼 반복하지 않는다.

## 부록 D. 운영 사고 자료에서 추린 성능 저해 요인

이 항목은 `docs/local/research/CTF_AGENT_REPOSITORIES_AND_INCIDENTS_2026-11-01.md`의 **그때 보존된 로그와 코드**를 해석한 것이다. 조사 당시 서버 job 208개 중 최종 오류 코드의 일부는 저장공간 사전 거부 22, 인증 필요 13, Flag handoff 부재 12, 원격 호스트 조회 실패 6, 원격 입력 상태 충돌 6, 정책 거부 6, Ultra 전환 요청 6, 한도 소진 5, 추가 입력 요청 5, 특정 모델 route 거부 4, write-up 형식 실패 4건이었다. 한 job의 최종 코드 집계이며 원인의 고유 발생 수·현재 배포판의 재현율이 아니다. Ultra 전환 요청은 실패가 아니라 제어 상태일 수 있다. 다음 항목은 무엇이 **확인**됐고 무엇이 **아직 추정**인지를 유지한다.

| 사고 유형 | 관찰과 원인 확실성 | 이 연구 계획에 반영한 대응·판정 |
|---|---|---|
| 저장공간 사전 거부 | 22건이 solver 실행 전 끝났고 일부는 첨부파일이 없었다. 당시 볼륨의 free/inode, 기존 예약, errno가 한 시점에 저장되지 않아 물리적 디스크 부족으로 단정할 수 없다. | B의 runtime probe에 실제 컨테이너 mount와 요청/예약/하한을 함께 남긴다. 저장공간 부족, 조회 실패, 권한, 복사 중 ENOSPC를 다른 코드로 분리하고 모델 추론 실패 통계에서 제외한다. |
| 인증 필요·모델 route·한도 | 로그인 snapshot, CLI credential 유효성, 모델 entitlement, 공급자 보안 정책, 5시간/주간 한도는 서로 다른 검사다. 한 종류의 ‘다시 로그인’ 안내로 묶으면 반복 실패가 생긴다. | 실험 manifest에 계정 종류(API key/구독 CLI), 모델 route와 quota 상태를 분리 기록한다. 실패 시 근거 있는 모델/계정 변경을 제시하고 무한 자동 재로그인을 하지 않는다. |
| 제한 턴 종료와 Flag handoff 부재 | `flag_not_submitted` 12건은 정해진 종료 시점까지 로컬 handoff가 없었다는 코드이지 난도가 절대 불가능하거나 원격 제출이 실패했다는 뜻이 아니다. | C의 마지막 유효 가설·실제 시도·원격 응답·발견 후보를 기록하고 F의 checkpoint와 연결한다. 추가 추론/병렬화가 유리한지는 G의 별도 실험에서만 판단한다. |
| 원격 정보·상태 충돌 | 조회 실패·이미 확정된 원격 상태에서 재요청·‘원격 없음’ 설정 뒤 필수 원격을 발견한 상황이 섞여 있다. 특정 단일 원인으로 합치지 않는다. | 현재의 원격 없음·모름·주소 있음 상태를 증거 기반 요청과 분리한다. 요청 전에 로컬 상수·파일·생성 경로를 확인하고, 인스턴스 주소 변경은 입력 fingerprint에 반영해 이어서 풀이 가능 여부를 판단한다. |
| CTFd 로그인과 제출 | 과거 코드에는 읽기용 JSON 로그인은 되지만 제출용 nonce가 없는 경로가 있었고, 원격 POST의 응답만 유실되면 중복 제출 위험이 있었다. 실제 단일 인증 실패가 그 경로였는지는 미확정이다. 현재 제출 큐에는 POST 전 dispatch 기록과 결과 불명 조회가 존재한다. | I에서는 read-ready와 submit-ready를 따로 판정하며, 결과 불명에는 자동 재POST를 금지하는 현행 경계를 회귀 검사한다. 임의 Flag를 실전 CTFd에 시험 제출하지 않는다. |
| 임시 격리 검사의 경합 | 교환 디렉터리 자체 점검 실패 뒤 재시도가 성공한 보고가 있고, 파일 원자 교체 중 임시 이름이 보였다는 설명이 코드와 부합한다. 당시 실측 파일 목록이 없어 강한 추정이다. | 일회 재검사 후에도 실패하면 내용 없이 엔트리 수·이름 digest·시각·프로세스 출처를 남긴다. 같은 오류가 아닌 계정/도구 실패까지 일반 재시도하지 않는다. |
| write-up 실패와 내부 명령 혼입 | Flag 저장 후 한국어 형식 실패는 풀이 실패와 다르다. 기존 조사에서는 서비스 내부 Flag handoff 명령이 설명문, 코드 블록 또는 첨부한 solver 코드에서 출판될 수 있는 검증 공백을 가상 입력으로 재현했다. 실제 사용자 문서의 정확한 유입 경로는 원본 job을 대조해야 한다. | I에서 write-up 입력을 풀이 증거와 독자용 재현 명령으로 선별한다. 설명문·inline·fence·삽입 코드에 대해 출판 전 검사하고, 내부 운영 명령을 제거하다 PoC를 깨뜨리면 게시 보류한다. Flag 자체는 보존한다. |
| 로그·선택 UI 갱신 | 과거 DOM 전체 재생성으로 선택 창이 닫히고, 대량 이벤트는 과거 backfill 지연으로 실시간 로그가 늦어졌다. 현재 작업 트리에 수정이 있으나 최종 배포판의 실제 체감은 확인되지 않았다. | 로그 데이터의 최신 tail과 과거 backfill을 분리하고, 사람이 추가 지시를 내릴 수 있는 상태를 보존한다. UI 처리 시간·폴링 지연은 solver의 추론 시간과 다른 열에 기록한다. |
| 재부팅·업데이트·외부 DB | 과거 Windows/WSL 설치에서 DB 파일은 남았으나 Docker bind가 다른 파일시스템을 보아 빈 DB 화면이 나타난 사례가 있다. 복구 후 기존 작업공간·계정이 보였다는 확인도 있었다. | 서비스 시작 전 DB UUID·크기/행 수와 컨테이너 시야를 대조해 잘못된 mount에서 새 빈 DB가 생성되지 않게 하는 검사로 B를 확장한다. 운영자가 ‘문제가 사라졌다’는 화면을 풀이 데이터 삭제로 바로 해석하지 않도록 한다. |

이 사고 표는 **해법 모음이 아니다**. 한 번 실패한 특정 문제의 취약점이나 생성된 Flag를 공통 skill에 넣지 않는다. 사후 분석이 제공하는 것은 요청 전 증거 확인, 실행 출력 귀속, 오래된 상태를 버리는 기준, 재개 시 입력 변경 감지 같은 일반적인 실패 경계다. 실제 개선 여부는 §7의 독립 문제·동일 모델 비교로 판정한다.

## 부록 E. 새 통제 연구와 공개 성능 비교의 조건 (2026-11-05)

[Amine·Saab의 동료 심사 논문](https://link.springer.com/article/10.1007/s10207-026-01350-x)은 NYU CTF Bench 200문제에서 누출 감사를 거친 29/200 성공을 보고한다. 기존 단일 에이전트의 3/200과 비교한 큰 차이에는 상위 모델 접근, 도구·스킬·환경·시점이 함께 바뀌어 있다. 저자가 별도로 수행한 **같은 80문제·도구·스킬·340 action 상한의 2×2 실험**에서는 승격 없는 단일 에이전트가 두 시행에서 4/80·3/80, 승격을 허용한 단일 에이전트가 22/80·19/80이었다. 플래너와 전문가를 더한 승격 조건은 14/80·15/80이었다. 해당 조건에서 모델 승격은 도움이 됐지만 상시 플래너의 독립적인 성공률 이득은 입증되지 않았다. 연구의 승격은 GPT-4o-mini에서 GPT-5-mini로의 **모델 교체**이므로, 이 결과를 Codex `medium→ultra` 전환 효과로 간주하지 않는다. 우리 서비스에서는 정체 기준과 한 번의 선택적 전환을 사전 정의하고, 전환 없이 유지한 arm 및 처음부터 높은 추론을 쓴 arm과 별도로 비교할 수 있다.

공개 점수를 넘어서는 최종 목표에는 평가 조건의 동등성이 필요하다. [공식 Inspect Evals Cybench 4-C](https://ukgovernmentbeis.github.io/inspect_evals/evals/cybench/index.html)는 원본 40개 중 라이선스상 한 문제를 제외한 `hard` 39개를 사용한다. 최종 completion을 채점하며 기본 ReAct는 한 시행 안에서 최대 세 번의 명시적 제출과 오답 피드백을 제공한다. 이 절차는 서비스가 발견한 첫 Flag 후보를 즉시 별도 오라클에 대조하는 내부 시험과 다르다. 현재 정적 입력 16개의 B1/C1 교차 시험은 같은 `gpt-6-sol`·`medium`·계정·도구·900초 조건에서 **첫 지시문 축소 한 변수**만 비교하는 내부 실험이다. 원격 victim 23개 및 공식 완료 채점 경로는 별도 검증이 필요하다. [공개 비용 연구](https://arxiv.org/html/2607.15263)의 39문제×3 시행 GPT-5.5 94.1%는 모델·API 경로·비용 상한·평가 revision까지 같다고 입증되기 전에는 역사적 참고값일 뿐이다.

외부의 검증된 결과를 채택할 때는 순정 CLI 대조군, 실제 trace에 나타난 도구 결손, 정답 출처 감사, 조건부 재계획·승격을 **서로 다른 실험**으로 취급한다. [기본 CLI 통제 연구](https://arxiv.org/html/2607.13085)는 장문의 보안 지시가 같은 모델에서 오히려 손해일 수 있음을 보였고, [EnIGMA](https://proceedings.mlr.press/v267/abramovich25a.html)는 상태 있는 도구의 효과가 분야마다 달랐다. 따라서 유명 저장소의 역할·skill 묶음을 한꺼번에 들여와 성능이 올랐다고 가정하지 않는다. 동일 평가기·문제·모델·예산의 결과를 얻고 신규 대회 문제에서 재검증하기 전에는 공개 수치보다 우월하다고 주장하지 않는다.
