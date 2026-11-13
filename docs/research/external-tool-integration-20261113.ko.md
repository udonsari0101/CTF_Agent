# 외부 도구 도입 판단 및 연결 계획 (2026-11-13)

## 결론과 기준

제공된 24개 프로젝트를 현재 CTF Agent의 Jeopardy 풀이 경로와 대조했다. 저장소의 별점·기능 개수·README의 속도 주장은 발견 지표일 뿐, CTF Agent에서 검증된 정답률이나 정답까지의 시간은 아니다. 현재 기본 이미지에는 Chromium/Playwright, Ghidra/JADX, GDB/pwndbg/pwntools, 분야별 분석 도구가 있고, 작업별 `notes/`와 형제 솔버의 검증 근거 공유가 있다. 모델 worker는 임의 MCP 호출을 허용하지 않는다. 이 계약을 바꾸려면 공급자별 도구 호출, 권한, 이벤트 기록, 재개, 버전 고정, 이미지 크기를 모두 다시 검증해야 한다.

**결정:** 지금은 외부 프로젝트 전체를 기본 이미지·상시 MCP 서버로 합치지 않는다. REA의 *선택형 CLI*와 PentestGPT의 *짧은 가설·근거·다음 실험 기록 방식*만 우선 비교한다. 웹 데이터 추출과 GUI/Android는 기존 도구로 실패한 재현 사례가 생길 때 선택형 실험으로 연다. 검증 없이 속도 개선을 주장하거나 `rea-agents@latest`를 풀이 도중 다운로드하지 않는다.

## 프로젝트별 결정

| 프로젝트 | 결정 | CTF Agent와의 관계 및 연결 방식 |
| --- | --- | --- |
| [REA](https://github.com/morluto/rea) | 선택형 실험 | 기존 Ghidra/JADX 위에 근거가 붙은 함수·참조 조회를 제공한다. MCP는 현 worker 계약과 맞지 않으므로 첫 실험은 고정 버전의 로컬 CLI로만 수행한다. 기존 Ghidra 직접 호출과 같은 입력을 비교한다. 기본 이미지 편입은 보류한다. |
| [PentestGPT](https://github.com/GreyDGL/PentestGPT), [논문](https://www.usenix.org/conference/usenixsecurity24/presentation/deng) | 방법론 비교 | 작업 트리·단계별 맥락 유지가 오래 헤매는 경우에 관련 있다. 이미 있는 `ANALYSIS/VULN/NEXT`와 반복 명령 감지에 비해 추가 정보가 있는지 먼저 확인한다. 전체 에이전트 프레임워크는 교체하지 않는다. 2024년 논문의 구형 모델 수치를 현재 모델의 성능 근거로 쓰지 않는다. |
| [Scrapling](https://github.com/D4Vinci/Scrapling) | 조건부 실험 | 기존 `ctf-browser-act`의 DOM·요청 캡처로 해결되지 않는 동적 웹 추출 사례에서만 비교한다. CTFd 가져오기는 공식 API 우선이며, 일반 크롤러로 교체하지 않는다. |
| [agent-desktop](https://github.com/vercel-labs/agent-desktop) | 조건부 별도 실행 환경 | OS 접근성 트리로 네이티브 앱을 조작한다. 현재 headless 웹 브라우저와 다른 능력이지만 solver 컨테이너에서 사용자의 호스트 데스크톱을 직접 제어하도록 연결하지 않는다. GUI 전용 문제가 나오면 별도 세션·권한 프로필로 실험한다. |
| [docker-android](https://github.com/budtmo/docker-android) | 조건부 별도 실행 환경 | APK 정적 분석은 이미 JADX/Apktool이 담당한다. 동적 Android 실행이 필요한 문제에서만 별도 KVM 지원 호스트/사이드카를 검토한다. 기본 이미지나 일반 solver 슬롯에 포함하지 않는다. |
| [agent-reach](https://github.com/Panniantong/agent-reach) | 문제별 선택 | 영상 자막·커뮤니티 OSINT 입력이 주어진 경우에만 사용 가능성을 검토한다. 로그인 세션을 다루므로 다른 문제의 계정과 공유하지 않는다. 일반 웹·CTFd 수집의 기본 경로는 아니다. |
| [tutti](https://github.com/tutti-os/tutti) | 설계 참고 | Codex/Claude 공유 맥락·인계 UI는 참고할 수 있다. 현재 작업공간·세션·형제 근거 공유를 대체하지 않으며 별도 협업 서버를 상시 붙이지 않는다. |
| [hexstrike-ai](https://github.com/0x4m4/hexstrike-ai) | 도구 목록만 참고 | 대규모 MCP 도구 카탈로그는 현재 도구와 겹치고 매 호출 선택 비용을 늘릴 수 있다. 구체적 결핍이 확인된 단일 도구만 원래 프로젝트 기준으로 평가한다. 전체 MCP 서버는 연결하지 않는다. |
| [pentagi](https://github.com/vxcontrol/pentagi) | 아키텍처 참고 | 범용 침투 테스트용 자율 에이전트 스택이다. CTFd 문제별 상태·제출·재개 경로와 중복되므로 서비스에 이식하지 않는다. |
| [Claude-Red](https://github.com/SnailSploit/Claude-Red) | 문서 참고 | 관련 분야의 조사 절차를 검토할 수 있으나 Claude 전용 스킬 묶음을 솔버 프롬프트에 전량 주입하지 않는다. 관찰 가능한 짧은 절차만 기존 playbook과 중복 여부를 비교한다. |
| [Awesome-REA](https://github.com/reacher-z/Awesome-REA) | 자료 색인 | 소프트웨어 의존성이 아닌 참고 자료. 특정 리버싱 사례를 찾을 때만 사용한다. |
| [security-audit-skill](https://github.com/cloudflare/security-audit-skill), [codex-security](https://github.com/openai/codex-security) | 개발 과정용 | CTF Agent 자체의 코드 검토 후보. 문제 풀이용 모델 도구·솔버 이미지에는 넣지 않는다. |
| [drawdb](https://github.com/drawdb-io/drawdb) | 개발 과정용 | DB 스키마 도식화에 쓸 수 있지만 문제 풀이 속도와 무관하다. |
| [freellmapi](https://github.com/tashfeenahmed/freellmapi), [uncensored-ai-api](https://github.com/7API/uncensored-ai-api) | 연결하지 않음 | 공식 Codex/Claude 계정 경로를 대체할 성능 근거가 없고, 모델 기능·세션·사용량 의미가 달라질 수 있다. 별도 공급자 지원을 원할 때 표준 API 호환성과 재개를 독립 과제로 평가한다. |
| [DeepInfer](https://github.com/deepseek-ai/DeepInfer) | 연결하지 않음 | 자체 GPU 모델 서빙 인프라. 현재 원격 Codex/Claude 기반 Jeopardy 솔버의 병목을 해결하지 않는다. |
| [OpenMausBot](https://github.com/milind-soni/OpenMausBot) | 연결하지 않음 | 범용 봇·VM 작업공간으로 현재 서비스와 기능이 겹친다. |
| [open-seo](https://github.com/every-app/open-seo), [claude-seo](https://github.com/AgriciDaniel/claude-seo) | 연결하지 않음 | SEO 분석 도구로 CTF 풀이 경로와 무관하다. |
| [Pake](https://github.com/tw93/Pake) | 연결하지 않음 | 웹을 데스크톱 앱으로 감싸는 패키징 도구다. 현재 Windows 설치기·브라우저 서비스의 기능 결핍을 해결하지 않는다. |
| [Pinggy](https://pinggy.io/) | 기본 연결하지 않음 | 임시 외부 터널이 필요한 문제라면 기존 OOB 콜백 경로와 비교할 수 있다. 상시 서버/솔버 외부 노출 수단으로 추가하지 않는다. |
| [wifit3](https://github.com/derv82/wifit3) | 연결하지 않음 | USB Wi-Fi 하드웨어 중심 도구다. 일반 Jeopardy 파일·원격 서비스 분석 이미지에 맞지 않는다. |
| [jailbreaks](https://github.com/togg53192-cmd/jailbreaks) | 연결하지 않음 | 탈옥 프롬프트 모음은 문제 풀이 하네스의 도구 능력이나 검증 능력을 제공하지 않는다. |

## 선택형 연결을 검증하는 순서

1. **REA 기초 검증:** 고정 버전·해시·Node 최소 버전을 확인한다. 현재 공개 npm `rea-agents@6.9.0`의 보고된 압축 해제 크기는 약 190MB다. 풀이 중 네트워크 설치는 제외하고 별도 실험 환경에만 설치한다. Ghidra provider와 CLI의 대상 파일·출력 경로를 작업별 디렉터리로 제한한다. MCP 등록 자동 명령은 실행하지 않는다.
2. **리버싱 짝 비교:** 정답을 모델에 노출하지 않은 서로 다른 유형의 rev 입력을 최소 3개 고정한다. 기존 `file`/`r2`/Ghidra 경로와 REA CLI 경로를 동일한 CPU·메모리·시간 예산으로 교차 실행한다. 첫 유효 함수/상수까지의 시간, 필요한 도구 호출 수, 피크 메모리, 결과 오류, 정답 검증까지의 시간을 따로 기록한다. REA가 시간을 줄이지 못하거나 오류를 늘리면 기본 구성에 넣지 않는다.
3. **작업 트리 비교:** 현재 `notes/NEXT.md`의 관찰·가설·반증·다음 실험과 PentestGPT의 PTT에서 빠진 정보가 무엇인지 먼저 대조한다. 없는 정보가 발견되면 한두 문장짜리 구조로 시범 적용한다. 프롬프트 길이와 재개 비용이 증가하는지도 측정한다. 같은 내용의 이중 기록은 만들지 않는다.
4. **웹/GUI 게이트:** 기존 Playwright로 재현된 실패가 있을 때 Scrapling을, 실제 데스크톱 앱 조작이 필수인 입력에서 agent-desktop을, 정적 APK 분석으로 답을 못 얻는 동적 Android 입력에서 docker-android를 개별 실험한다. 세 도구의 실험 결과를 서로의 채택 근거로 삼지 않는다.
5. **채택 기준:** 독립 Flag 판정의 성공률·활성 풀이 시간·오답과 불필요한 입력 요청·설치 크기·콜드 시작/피크 RAM을 함께 본다. 이미 성공하는 간단한 문제 몇 개에서만 빨라진 결과로 전체 기본값을 바꾸지 않는다. 선택형 경로라도 버전 고정, 제거 가능성, 실패 시 기존 경로 복귀, 업데이트/롤백 검사가 끝나야 서비스 옵션으로 노출한다.

## 현재 상태와 한계

## 격리된 REA 파일럿 결과

현재 로컬 이미지의 Node는 22.23.2이고, `rea-agents@6.9.0`이 요구하는 최소 버전 `22.23.4`보다 낮다. 제품 이미지를 바꾸지 않고 일회용 컨테이너에 Node 24.22.1과 REA 6.9.0을 설치했다. 공식 Node 배포 해시를 확인했고, `rea doctor --provider ghidra`에서 설치된 Ghidra 12.1.4를 정상으로 판정했다. REA 패키지 디렉터리는 약 327MiB, 설치 중 npm 캐시는 약 82MiB였다. 이 수치는 전체 이미지 증가량이 아니라 해당 실험 컨테이너의 디스크 사용량이다.

동일 컨테이너에서 CPU 2개·메모리 4GiB를 제한하고, 서로 다른 작은 ELF 세 개의 첫 분석 호출 시간을 측정했다. REA와 직접 Ghidra의 출력 범위가 완전히 같지는 않으므로 이 표는 **정답까지의 시간 비교가 아닌 초기 도구 지연 비교**다.

| 입력 | REA 6.9.0 + Ghidra | 기존 Ghidra 직접 호출 | 관찰 |
| --- | ---: | ---: | --- |
| `ctftiny-rev-whataxor` | 14.21초 | 12.17초 | 두 경로 모두 `main` 의사코드 2,305자를 얻었다. REA는 추가 구조화 근거를 생성했다. |
| `ctftiny-rev-beleaf` | 12.63초 | 8.22초 | stripped ELF의 첫 전체 분석. |
| `bronco-rev-cat-simulator` | 13.21초 | 8.46초 | stripped ELF의 첫 전체 분석. |

세 입력 모두 REA가 작동했지만 빠르지는 않았다. REA가 제공하는 함수·참조·근거 조회의 사용성은 유용할 수 있으나, 세 작은 파일만으로 Flag 정답률·풀이 시간을 개선한다고 볼 수 없다. 현재 기본 이미지와 풀이 프롬프트에는 REA를 추가하지 않는다. Ghidra 직접 호출이 특정 입력에서 막힌 재현 사례가 생기면 별도 선택형 도구로 다시 비교한다.

## 여러 솔버가 공유하는 MCP 판단

현재 Codex/Claude worker는 임의의 MCP 호출을 거부하고, Claude 프로젝트 MCP를 비활성화한다. 공유 REA·Ghidra MCP를 하나 띄우면 파일·분석 세션·작업 기록의 소유권을 솔버마다 분리해야 한다. CPU와 메모리를 쓰는 분석 요청은 다른 솔버의 지연에도 영향을 준다. 위 파일럿에서 REA는 기존 직접 도구보다 빠르지 않았으므로, 공유 서버를 운영해 얻을 측정된 이익이 없다. **상시 공유 MCP는 도입하지 않는다.**

향후 같은 바이너리의 중복 분석이 실제 병목으로 확인될 경우에는 먼저 기존 작업 파일과 검증된 형제 풀이 근거 공유를 재사용한다. 그래도 부족하면 읽기 전용·콘텐츠 해시 기반 결과 캐시를 시험한다. MCP가 필요한 경우에는 작업별 namespace, 권한 확인, 호출·결과 출처, 취소와 crash 정리, 동시 실행 상한, 버전 고정 및 기존 CLI로의 복귀를 갖춘 *선택형* 경로로만 비교한다. 한 분석 세션을 여러 솔버가 쓰도록 설계하지 않는다.

## PentestGPT 방식과 현재 기록의 대조

[현재 PentestGPT 구현 문서](https://github.com/GreyDGL/PentestGPT/blob/main/pentestgpt_agent/CONTEXT.md)는 작업·시도·실제 명령/도구 결과를 별도 식별하고, 정확한 관찰 조각만 근거로 승격한다. CTF Agent는 이미 `notes/ANALYSIS.md`·`VULN.md`·`NEXT.md`에 관찰 사실, 미검증/반증 가설, 다음 실험, 바꾼 입력을 기록하도록 지시한다. 실행 이벤트와 재개 이력도 별도로 보유한다. 외부 PTT를 그대로 더하면 같은 내용을 다시 쓰게 되고 초기 문맥이 늘어난다. 현 시점에는 별도 작업 트리·추가 프롬프트를 도입하지 않는다. 실제 로그에서 근거 없는 결론이 반복될 때만, 완료 주장을 해당 명령 결과에 연결하는 *작은* provenance 개선을 검토한다. [2024년 논문](https://www.usenix.org/conference/usenixsecurity24/presentation/deng)의 성능 수치를 현재 Codex/Claude 모델에 그대로 적용하지 않는다.

## 결론과 한계

이 문서의 조사는 기본 이미지·MCP 설정·프로덕션 서비스를 변경하지 않았다. 연구 및 도구 파일럿은 끝났고, 외부 프로젝트에서 즉시 제품에 넣을 변경은 발견하지 못했다. 원래 풀이 성능 개선 작업의 남은 핵심은 현재판과 이전판의 **같은 모델·문제·예산에 대한 짝지은 실제 풀이**와 독립 Flag 판정이다. 외부 도구의 별점이나 파일럿 초기 지연을 정답률 근거로 대체하지 않는다.
