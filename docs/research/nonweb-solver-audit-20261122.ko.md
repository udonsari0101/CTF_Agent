# 비웹 분야 풀이 지침·도구 점검 (2026-11-22)

## 범위와 판정

리버싱, 포너블, 암호, 포렌식, misc, OSINT, 블록체인, AI/ML, 분야 미분류의 현재 playbook과 실제 도구 호출 경로를 살폈다. 이번 변경은 문제별 풀이를 외우게 하거나 기본 이미지에 도구를 더 싣는 작업이 아니다. 실제 명령 실패, 잘못된 계산, 근거 없는 공격 선택, 큰 파일의 무제한 추출을 유도할 수 있는 항목만 고쳤다. 문제 풀이 성공률과 소요 시간이 개선됐다는 실험 결과는 아직 없다.

| 분야 | 확인한 문제 | 변경 |
|---|---|---|
| 리버싱 | Ghidra 디컴파일 도우미가 `0x`가 붙은 함수 주소를 못 찾음 | 주소 표기를 정규화하고, 같은 프로젝트를 재사용해 주소로 디컴파일하는 이미지 검사를 추가 |
| 포너블 | 생성한 cyclic 패턴과 오프셋 검색의 `n`이 다름; 첫 안전 연결 누출을 힙 시작 주소로 단정; 로컬 libc를 원격 libc로 오인할 수 있음 | 실제 패턴·주소·라이브러리·입출력 프레이밍을 검증하도록 예시 수정 |
| 암호 | 선형이 아닌 전체 AES 라운드를 선형으로 취급할 수 있음; 길이만으로 암호 방식을 확정; 재사용 nonce, Groth16, MT19937 등에서 조건 없는 성공 단정 | 적용 조건과 반례를 명시하고 확인 가능한 식·오라클 결과로 검증하도록 수정 |
| 포렌식 | 설치된 Volatility 3에 없는 `windows.clipboard`를 첫 명령으로 제시; PCAP/대형 이미지의 전체 추출을 먼저 권장; 원본 디스크 수리 명령을 권장 | 설치된 플러그인 확인, 메타데이터·프로토콜·파티션 우선 조사, 제한된 추출과 읽기 전용 분석으로 변경 |
| misc | PoW 비트 검사가 SHA-256의 256비트로 고정돼 다른 해시에서 틀림; 원격 식을 `eval`로 실행 | 해시별 비트 폭을 계산하고, 허용한 정수 연산만 파싱하는 예시로 교체 |
| OSINT | 숫자·해시 모양만으로 출처를 단정하고, 아카이브된 도구의 비공식 API 및 많은 사이트 일괄 조회를 권장 | 단서를 먼저 확인하고 조회 범위를 좁히며 실제 프로필 본문으로 검증하도록 변경 |
| 블록체인 | 모든 문제가 RPC·개인키·`isSolved()`·플래그 엔드포인트를 제공한다고 가정 | 제공된 성공 조건과 실제 원격 정보만 사용하도록 변경. 개인키를 내보내는 노트에 복사하지 않도록 명시 |
| AI/ML | 모든 모델 형식을 코드 실행 위험 또는 안전한 형식으로 양분; 설치되지 않은 구형 Foolbox API를 바로 실행하도록 제시 | 직렬화 형식·자원 위험을 구분하고 도구 버전을 확인하도록 변경 |
| 분야 미분류 | 숨김 파일을 `file *`로 누락하고 모든 파일에 `binwalk`·`unzip` 적용 | 숨김 파일까지 값싼 판별을 수행한 뒤 관련 형식에만 도구 적용 |

Volatility 3의 [공식 플러그인 목록](https://volatility3.readthedocs.io/en/v2.28.0/volatility3.plugins.windows.html)과 [공식 Windows 사용법](https://github.com/volatilityfoundation/volatility3/blob/develop/doc/source/getting-started-windows-tutorial.rst)을 확인했다. `clipboard`는 구형 Volatility 저장소에는 있지만 현재 이미지에 고정된 Volatility 3의 기본 플러그인 목록에는 없다. 따라서 그 명령을 필수 첫 단계에서 제거했다.

V8의 [현재 Math.random 구현](https://chromium.googlesource.com/v8/v8/+/refs/heads/main/src/builtins/math.tq)과 [32비트 캐시 조건](https://chromium.googlesource.com/v8/v8/+/refs/heads/main/src/numbers/math-random.cc)을 확인했다. 기존 지침의 무조건적인 출력 역순 가정은 64비트 실행에서 틀릴 수 있어 버전·아키텍처·실제 출력으로 확인하도록 변경했다.

[HashClash의 공식 사용법](https://github.com/cr-marcstevens/hashclash)은 동일 접두사와 선택 접두사 MD5 충돌을 별도 도구로 구분한다. 기존 FastColl 표기를 고쳤고, 설치되지 않은 `hashpump` CLI·`randcrack` 패키지는 사용 전 존재를 확인하도록 수정했다. OSINT 조회 지침은 [WhatsMyName의 현재 저장소 상태](https://github.com/WebBreacher/WhatsMyName)를 확인해 불확실한 API 호출을 제거했다.

## 검증 경계와 다음 결정

로컬에서 playbook 계약 검사 7건과 `deploy/image-smoke.py` Python 문법 검사가 통과했다. 포너블·misc의 PoW 예시는 SHA-1/SHA-256/SHA-512와 범위 오류 입력으로 직접 실행해 확인했다. Ghidra 주소 입력과 프로젝트 재사용은 빌드된 이미지에서 CI smoke test가 검증하도록 연결했다. 실문제 풀이 시간·정답률은 동일한 모델·계정·예산·문제 입력을 두 버전에 적용하고 별도의 정답 판정기로 비교해야 한다. 현재 수정만으로 특정 분야의 성능 향상을 수치로 주장하지 않는다.

새 도구나 상시 MCP 서버를 기본 이미지에 더하면 설치 크기, 시작 시간, 공용 자원 경합이 생긴다. 현 점검에서 이를 상쇄할 재현 가능한 미해결 도구 결함은 발견하지 못했다. 이후 실제 실패 로그가 특정 기능의 부재를 보여 주면 그 분야의 선택형 도구로 검토한다.
