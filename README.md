# SecureSocketChat

![Python CI](https://github.com/allen8524/secure-socket-chat/actions/workflows/python-tests.yml/badge.svg)

PyNaCl 기반 공개키 교환으로 클라이언트-서버 암호화 채널을 구성한 Python 보안 소켓 채팅 프로젝트입니다.

SecureSocketChat은 단순 채팅 예제를 넘어, 네트워크 패킷 framing, 암호화 세션 구성, GUI 클라이언트, 파일 payload 무결성 검증, 테스트 자동화까지 직접 설계한 학습 및 포트폴리오 목적의 보안 네트워크 프로젝트입니다. 서버와 각 클라이언트는 PyNaCl `Box` 기반의 독립적인 암호화 채널을 만들고, 메시지와 이미지/일반 파일 데이터를 자체 패킷 프로토콜을 통해 주고받습니다.

## Demo

데모 GIF는 `assets/demo/secure-socket-chat-demo.gif` 경로에 추가할 수 있도록 구성했습니다. 해당 파일을 추가한 뒤 아래 주석을 해제하면 README 상단에서 바로 시연 화면을 확인할 수 있습니다.

```md
<!--
![SecureSocketChat Demo](assets/demo/secure-socket-chat-demo.gif)
-->
```

GUI를 여러 개 띄우지 않고 핵심 통신 흐름을 확인하려면 CLI 자동 데모를 실행할 수 있습니다.

```bash
python demo.py
```

CLI 데모는 로컬 서버를 thread로 시작한 뒤 `alice`, `bob` 테스트 클라이언트를 연결하고, 전체 채팅, 귓속말, SHA-256 검증 기반 파일 전송, 서버 통계 요청을 자동으로 수행합니다. 데모용 TOFU trust store와 샘플 파일은 임시 디렉터리에 생성되며 종료 후 정리됩니다.

자세한 시나리오는 `docs/demo.md`를 참고하세요.

## 핵심 기능

| 구분 | 내용 |
|---|---|
| 암호화 채널 | PyNaCl PrivateKey/PublicKey 기반 키 교환과 PyNaCl Box 기반 클라이언트-서버 암호화 통신 |
| 패킷 프로토콜 | 4바이트 길이 prefix + JSON header + binary payload 구조의 자체 패킷 framing |
| 채팅 기능 | 전체 채팅, 1:1 귓속말, `/w` 명령어 기반 귓속말 |
| 실험적 E2E whisper | `/e2e 사용자명 메시지`로 1:1 텍스트 whisper 본문을 수신자 E2E 공개키로 추가 암호화 |
| 이미지 전송 | 이미지 파일 전송 및 SHA-256 이미지 무결성 검증 |
| 파일 전송 | 일반 파일 전송, 파일 크기 표시, SHA-256 무결성 검증, 위험 확장자 경고 |
| 보안 정보 | GUI Security Dashboard에서 보안 세션 정보와 송수신 패킷 상태 표시 |
| 패킷 관찰 | Packet Inspector에서 암호화 전 논리 패킷과 암호화 후 전송 패킷의 요약 비교 |
| 서버 운영 정보 | 서버 uptime, 접속자 수, 메시지/이미지/파일 전송 통계 조회 |
| GUI | Tkinter 기반 데스크톱 GUI 클라이언트와 접속자 목록 실시간 동기화 |
| 방어 로직 | TOFU 기반 서버 fingerprint 검증, sequence number 기반 replay 방어, payload/header 크기 제한 |
| 테스트/CI | pytest, pytest-cov, ruff, bandit, GitHub Actions 기반 자동 검증 구조 |

## 기술 스택

| 영역 | 기술 |
|---|---|
| Language | Python 3.10+ |
| Network | socket, threading |
| Encryption | PyNaCl PublicKey, PrivateKey, Box |
| Protocol | Length-prefix framing, JSON header, binary payload |
| GUI | Tkinter |
| Test | pytest, pytest-cov |
| Quality | ruff, bandit |
| CI | GitHub Actions |

## 빠른 실행 방법

### 1. 가상환경 생성 및 의존성 설치

Windows PowerShell 기준입니다.

```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

macOS/Linux 기준입니다.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. 서버 실행

```bash
python run_server.py --host 127.0.0.1 --port 9999
```

디버그 로그까지 확인하려면 다음처럼 실행합니다.

```bash
python run_server.py --host 127.0.0.1 --port 9999 --verbose
```

### 3. 클라이언트 실행

터미널을 2개 이상 열고 각각 다른 이름으로 실행합니다.

```bash
python run_client.py --host 127.0.0.1 --port 9999 --name alice
python run_client.py --host 127.0.0.1 --port 9999 --name bob
```

이름을 인자로 넘기지 않으면 GUI 실행 후 입력창이 나타납니다.

```bash
python run_client.py
```

## 보안 설계 요약

이 프로젝트는 전체 기능에 대해 종단 간 암호화를 보장하는 메신저가 아닙니다. 기본 구조는 클라이언트-서버 간 암호화 채널이며, 서버가 메시지를 중계하는 과정에서 일반 chat, 일반 whisper, 파일 metadata를 복호화할 수 있습니다.

대신 프로젝트의 초점은 다음과 같습니다.

- 클라이언트-서버 간 암호화 채널 구성
- 실험적 1:1 E2E whisper mode를 통한 whisper 본문 추가 보호
- 공개키 기반 세션별 키 교환 흐름 구현
- 바이너리 payload를 포함하는 자체 패킷 framing 구현
- 비정상 header/payload 방어
- TOFU 기반 서버 공개키 fingerprint 저장 및 변경 감지
- sequence number 기반 replay 의심 패킷 차단
- 파일명 경로 조작 가능성 축소
- 공개키 fingerprint를 통한 세션 식별
- 이미지/파일 payload SHA-256 검증을 통한 전송 무결성 확인

실험적 E2E whisper mode는 1:1 텍스트 whisper 본문만 대상으로 합니다. 전체 채팅 broadcast와 파일/이미지 전송은 현재 E2E 대상이 아니며, 서버는 E2E 메시지 본문은 복호화하지 못하지만 송신자, 수신자, 전송 시각, 패킷 크기 같은 metadata는 볼 수 있습니다.

상대방 E2E 공개키 fingerprint는 `/fingerprint 사용자명` 명령어 또는 GUI의 `E2E FP 확인` 버튼으로 확인할 수 있습니다. 이 값은 사용자가 상대방과 직접 비교할 수 있는 식별 정보이며, 인증기관 기반 인증을 제공하지는 않습니다.

자세한 구조와 보안 한계는 아래 문서 구성에서 이어서 확인할 수 있습니다.

## 문서 구성

| 문서 | 설명 |
|---|---|
| [Architecture](docs/architecture.md) | 전체 시스템 구조, 키 교환, 메시지 전송, 파일 전송 흐름을 Mermaid 다이어그램으로 설명 |
| [Protocol](docs/protocol.md) | 4-byte length prefix, JSON header, binary payload, secure packet 규칙 정리 |
| [Security Notes](docs/security-notes.md) | 적용한 보안 요소와 클라이언트-서버 암호화 채널의 한계 설명 |
| [Threat Model](docs/threat-model.md) | 보호 대상, 신뢰 경계, 공격 시나리오와 현재 대응 방식 정리 |
| [Testing](docs/testing.md) | 단위/통합 테스트 실행 방법과 검증 범위 정리 |
| [CI](docs/ci.md) | GitHub Actions, ruff, coverage, bandit 검증 흐름 정리 |
| [Demo](docs/demo.md) | `demo.py` 기반 CLI 자동 시연 흐름 설명 |
| [Feature Pack](docs/feature-pack.md) | 포트폴리오 시연에서 강조할 부가 기능 요약 |

## 프로젝트 구조

```txt
secure-socket-chat/
├─ README.md
├─ LICENSE
├─ requirements.txt
├─ requirements-dev.txt
├─ pyproject.toml
├─ run_server.py
├─ run_client.py
├─ demo.py
├─ secure_chat/
│  ├─ config.py
│  ├─ protocol.py
│  ├─ crypto_channel.py
│  ├─ server.py
│  ├─ client.py
│  ├─ file_transfer.py
│  ├─ gui.py
│  ├─ logging_config.py
│  ├─ packet_inspector.py
│  ├─ security.py
│  ├─ trust_store.py
│  └─ utils.py
├─ tests/
│  ├─ test_protocol.py
│  ├─ test_protocol_invalid_packets.py
│  ├─ test_crypto_channel.py
│  ├─ test_demo.py
│  ├─ test_e2e.py
│  ├─ test_file_transfer.py
│  ├─ test_integration_chat.py
│  ├─ test_integration_file_transfer.py
│  ├─ test_sequence_replay.py
│  ├─ test_server_e2e.py
│  ├─ test_trust_store.py
│  ├─ test_packet_inspector.py
│  ├─ test_gui_dashboard.py
│  ├─ test_security.py
│  └─ test_utils.py
├─ docs/
│  ├─ architecture.md
│  ├─ ci.md
│  ├─ demo.md
│  ├─ feature-pack.md
│  ├─ protocol.md
│  ├─ testing.md
│  ├─ security-notes.md
│  └─ threat-model.md
└─ assets/
   ├─ demo/
   └─ screenshots/
```

## 사용 방법

| 기능 | 방법 |
|---|---|
| 전체 채팅 | 접속자 목록에서 `전체` 선택 후 메시지 전송 |
| 귓속말 | 접속자 목록에서 대상 선택 후 메시지 전송 |
| 명령어 귓속말 | `/w 사용자명 메시지` 입력 |
| E2E whisper | `/e2e 사용자명 메시지` 입력 또는 대상 선택 후 `E2E 전송` 버튼 클릭 |
| E2E fingerprint 확인 | `/fingerprint 사용자명` 입력 또는 대상 선택 후 `E2E FP 확인` 버튼 클릭 |
| 이미지 전송 | 대상 선택 후 `이미지` 버튼 클릭 |
| 파일 전송 | 대상 선택 후 `파일` 버튼 클릭 |
| 보안 세션 확인 | `/security` 또는 `보안정보` 버튼 |
| 서버 통계 조회 | `/stats` 또는 `서버통계` 버튼 |
| 접속자 확인 | `/users` 입력 |
| 대화 로그 저장 | `/save` 또는 `대화저장` 버튼 |
| 화면 지우기 | `/clear` 또는 `화면지우기` 버튼 |
| 종료 | 창 닫기 또는 `end` 입력 |

## 테스트 실행

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
pytest -q
```

테스트 범위는 다음과 같습니다.

- 패킷 packing/unpacking 검증
- payload 크기 제한 검증
- 잘못된 패킷 방어 검증
- PyNaCl Box 암호화/복호화 검증
- 실제 서버/클라이언트 통합 채팅 라우팅 검증
- 1:1 귓속말 라우팅 및 오류 응답 검증
- 파일/이미지 전송과 SHA-256 무결성 검증
- 실험적 E2E whisper 암호화/복호화 및 라우팅 검증
- sequence number 기반 replay 방어 검증
- TOFU trust store 저장/변경 감지 검증
- 수신 파일명 정규화 검증
- 파일 전송 helper 및 SHA-256 검증 테스트
- 공개키 fingerprint 및 session id 생성 검증
- SHA-256 해시 검증

자동 테스트는 GUI를 띄우지 않고 headless 네트워크 클라이언트를 사용합니다. Tkinter GUI 화면, 버튼 배치, 실제 파일 선택 대화상자는 수동 확인 대상입니다.

## Quality Checks

이 프로젝트는 GitHub Actions의 `Python CI` workflow에서 Python 3.10, 3.11, 3.12를 대상으로 다음 검증을 자동으로 수행합니다.

- pytest 기반 단위/통합 테스트
- pytest-cov 기반 coverage 측정
- ruff 기반 코드 스타일 검사
- bandit 기반 Python 보안 스캔

로컬에서 CI와 같은 품질 검사를 실행하려면 개발 의존성을 설치한 뒤 아래 명령어를 사용합니다.

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
ruff check .
pytest --cov=secure_chat --cov-report=term-missing
bandit -r secure_chat
```

운영 실행 의존성은 `requirements.txt`에, 테스트와 품질 검사 도구는 `requirements-dev.txt`에 분리했습니다. 자세한 CI 구성은 `docs/ci.md`, 테스트 구조는 `docs/testing.md`를 참고하세요.

## 아키텍처

서버는 각 클라이언트와 독립적인 암호화 채널을 생성합니다. 클라이언트가 보낸 메시지는 서버에서 복호화된 뒤, 수신 대상 클라이언트의 암호화 채널을 통해 재전송됩니다.

전체 구조, 키 교환 sequence, 메시지 라우팅, 파일 전송 및 SHA-256 검증 흐름은 [Architecture](docs/architecture.md)에 Mermaid 다이어그램으로 정리했습니다.

## 구현 근거

| 파일 | 역할 |
|---|---|
| `secure_chat/protocol.py` | 4바이트 header length + JSON header + binary payload 구조 구현 |
| `secure_chat/crypto_channel.py` | 공개키 교환, 암호화 송수신 래퍼, 세션 fingerprint 관리 구현 |
| `secure_chat/e2e.py` | 실험적 1:1 E2E whisper용 키 생성, inner payload 암호화/복호화 구현 |
| `secure_chat/server.py` | 멀티클라이언트 접속, 메시지 라우팅, 접속자 목록 broadcast 처리 |
| `secure_chat/client.py` | 서버 연결, 암호화 송신, 수신 스레드, 메시지 큐 처리 |
| `secure_chat/file_transfer.py` | 파일 SHA-256 계산, 크기 표시, 위험 확장자 감지, file header 생성 |
| `secure_chat/gui.py` | Tkinter 기반 GUI, 귓속말 대상 선택, 이미지/파일 전송 UI 구현 |
| `secure_chat/packet_inspector.py` | 암호화 전 logical packet과 암호화 후 transport packet의 안전한 요약 생성 |
| `secure_chat/security.py` | 공개키 fingerprint, 세션 ID, SHA-256 해시 유틸리티 구현 |
| `secure_chat/trust_store.py` | TOFU 기반 서버 fingerprint 로컬 저장 및 변경 감지 구현 |
| `secure_chat/utils.py` | 수신 파일 저장 및 안전한 파일명 처리 |

## 포트폴리오 설명 문구

Python socket 기반 채팅 프로그램에 공개키 교환 방식을 적용해 클라이언트-서버 간 암호화 통신 채널을 구성했습니다. 메시지는 JSON header와 binary payload로 분리하고, 4바이트 길이 prefix를 사용하는 자체 패킷 프로토콜로 framing했습니다. 서버는 다중 클라이언트 접속을 스레드로 처리하며, 전체 채팅, 1:1 귓속말, 실험적 E2E whisper, 이미지/일반 파일 전송, 접속자 목록 동기화를 지원합니다. 또한 공개키 fingerprint와 세션 ID를 GUI에 표시하고, TOFU 방식으로 서버 fingerprint 변경을 감지하며, 파일 payload는 SHA-256 해시로 무결성을 확인하도록 구현했습니다. payload 크기 제한, header 크기 검증, sequence 기반 replay 방어, 파일명 정규화 등을 적용해 비정상 패킷과 파일 경로 조작 가능성을 줄였습니다.

## 시연 포인트

- GUI 좌측 Security Dashboard에서 연결/암호화 상태, session id, client/server fingerprint, TOFU 신뢰 상태, sequence/replay 상태 확인
- Security Dashboard에서 E2E 사용 가능 여부, 내 E2E fingerprint, 선택 대상 E2E fingerprint, 마지막 E2E 복호화 결과 확인
- `/fingerprint bob` 또는 `E2E FP 확인` 버튼으로 상대방의 현재 세션 E2E fingerprint 확인
- GUI Packet Inspector에서 암호화 전 logical packet과 암호화 후 transport packet 차이 확인
- `/e2e bob hello`로 실험적 1:1 E2E whisper 전송 및 수신자 측 복호화 확인
- Packet Inspector는 메시지 전문, 이미지/file binary, 전체 암호문을 표시하지 않고 제한된 preview만 표시
- `/security` 명령어로 현재 암호화 세션 정보 출력
- `/stats` 명령어로 서버 uptime, 접속자 수, 메시지/이미지/파일 전송량 조회
- 이미지 전송 시 SHA-256 해시를 header에 포함하고 수신 측에서 payload 무결성 확인
- 일반 파일 전송 시 `received_files/` 저장 위치와 SHA-256 검증 결과 확인
- `/save` 명령어로 보안 세션 정보가 포함된 대화 로그 저장

## 개선 예정 아이디어

- 서버 키 영속화
- 사용자 E2E fingerprint TOFU, key pinning 또는 QR fingerprint verification
- CLI 클라이언트 추가
- 서버 설정 파일 분리
- 파일 전송 정책 고도화
- 데모 GIF 및 실행 화면 스크린샷 추가
