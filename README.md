# SecureSocketChat

PyNaCl 기반 공개키 교환으로 클라이언트-서버 암호화 채널을 구성한 Python 보안 소켓 채팅 프로젝트입니다.

SecureSocketChat은 단순 채팅 예제를 넘어, 네트워크 패킷 framing, 암호화 세션 구성, GUI 클라이언트, 이미지 payload 무결성 검증, 테스트 자동화까지 직접 설계한 학습 및 포트폴리오 목적의 보안 네트워크 프로젝트입니다. 서버와 각 클라이언트는 PyNaCl `Box` 기반의 독립적인 암호화 채널을 만들고, 메시지와 이미지 데이터는 자체 패킷 프로토콜을 통해 주고받습니다.

## Demo

데모 GIF는 `assets/demo/secure-socket-chat-demo.gif` 경로에 추가할 수 있도록 구성했습니다. 해당 파일을 추가한 뒤 아래 주석을 해제하면 README 상단에서 바로 시연 화면을 확인할 수 있습니다.

```md
<!--
![SecureSocketChat Demo](assets/demo/secure-socket-chat-demo.gif)
-->
```

## 핵심 기능

| 구분 | 내용 |
|---|---|
| 암호화 채널 | PyNaCl PrivateKey/PublicKey 기반 키 교환과 PyNaCl Box 기반 클라이언트-서버 암호화 통신 |
| 패킷 프로토콜 | 4바이트 길이 prefix + JSON header + binary payload 구조의 자체 패킷 framing |
| 채팅 기능 | 전체 채팅, 1:1 귓속말, `/w` 명령어 기반 귓속말 |
| 이미지 전송 | 이미지 파일 전송 및 SHA-256 이미지 무결성 검증 |
| 보안 정보 | 공개키 fingerprint, session ID, cipher 등 보안 세션 정보 표시 |
| 서버 운영 정보 | 서버 uptime, 접속자 수, 메시지/이미지 전송 통계 조회 |
| GUI | Tkinter 기반 데스크톱 GUI 클라이언트와 접속자 목록 실시간 동기화 |
| 방어 로직 | payload 크기 제한, header 크기 제한, 수신 파일명 정규화 |
| 테스트/CI | pytest 기반 테스트와 GitHub Actions 기반 테스트 구조 |

## 기술 스택

| 영역 | 기술 |
|---|---|
| Language | Python 3.10+ |
| Network | socket, threading |
| Encryption | PyNaCl PublicKey, PrivateKey, Box |
| Protocol | Length-prefix framing, JSON header, binary payload |
| GUI | Tkinter |
| Test | pytest |
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

이 프로젝트는 종단 간 암호화를 보장하는 메신저가 아닙니다. 서버가 메시지를 중계하는 구조이므로 서버는 라우팅 과정에서 메시지 내용을 복호화할 수 있습니다.

대신 프로젝트의 초점은 다음과 같습니다.

- 클라이언트-서버 간 암호화 채널 구성
- 공개키 기반 세션별 키 교환 흐름 구현
- 바이너리 payload를 포함하는 자체 패킷 framing 구현
- 비정상 header/payload 방어
- 파일명 경로 조작 가능성 축소
- 공개키 fingerprint를 통한 세션 식별
- 이미지 payload SHA-256 검증을 통한 전송 무결성 확인

자세한 보안 메모는 `docs/security-notes.md`, 위협 모델 관점의 정리는 `docs/threat-model.md`를 참고하세요.

## 프로젝트 구조

```txt
secure-socket-chat/
├─ README.md
├─ LICENSE
├─ requirements.txt
├─ pyproject.toml
├─ run_server.py
├─ run_client.py
├─ secure_chat/
│  ├─ config.py
│  ├─ protocol.py
│  ├─ crypto_channel.py
│  ├─ server.py
│  ├─ client.py
│  ├─ gui.py
│  ├─ logging_config.py
│  ├─ security.py
│  └─ utils.py
├─ tests/
│  ├─ test_protocol.py
│  ├─ test_crypto_channel.py
│  └─ test_utils.py
├─ docs/
│  ├─ architecture.md
│  ├─ protocol.md
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
| 이미지 전송 | 대상 선택 후 `이미지` 버튼 클릭 |
| 보안 세션 확인 | `/security` 또는 `보안정보` 버튼 |
| 서버 통계 조회 | `/stats` 또는 `서버통계` 버튼 |
| 접속자 확인 | `/users` 입력 |
| 대화 로그 저장 | `/save` 또는 `대화저장` 버튼 |
| 화면 지우기 | `/clear` 또는 `화면지우기` 버튼 |
| 종료 | 창 닫기 또는 `end` 입력 |

## 테스트 실행

```bash
pytest
```

테스트 범위는 다음과 같습니다.

- 패킷 packing/unpacking 검증
- payload 크기 제한 검증
- 잘못된 패킷 방어 검증
- PyNaCl Box 암호화/복호화 검증
- 수신 파일명 정규화 검증
- 공개키 fingerprint 및 session id 생성 검증
- SHA-256 해시 검증

## 아키텍처

```txt
Client A
  └─ SecureChannel
       └─ encrypted packet
            ↓
          Server
            ↓
       ┌───────────────┐
       │ route message │
       └───────────────┘
            ↓
       encrypted packet
  └─ SecureChannel
Client B
```

서버는 각 클라이언트와 독립적인 암호화 채널을 생성합니다. 클라이언트가 보낸 메시지는 서버에서 복호화된 뒤, 수신 대상 클라이언트의 암호화 채널을 통해 재전송됩니다.

## 구현 근거

| 파일 | 역할 |
|---|---|
| `secure_chat/protocol.py` | 4바이트 header length + JSON header + binary payload 구조 구현 |
| `secure_chat/crypto_channel.py` | 공개키 교환, 암호화 송수신 래퍼, 세션 fingerprint 관리 구현 |
| `secure_chat/server.py` | 멀티클라이언트 접속, 메시지 라우팅, 접속자 목록 broadcast 처리 |
| `secure_chat/client.py` | 서버 연결, 암호화 송신, 수신 스레드, 메시지 큐 처리 |
| `secure_chat/gui.py` | Tkinter 기반 GUI, 귓속말 대상 선택, 이미지 전송 UI 구현 |
| `secure_chat/security.py` | 공개키 fingerprint, 세션 ID, SHA-256 해시 유틸리티 구현 |
| `secure_chat/utils.py` | 수신 파일 저장 및 안전한 파일명 처리 |

## 포트폴리오 설명 문구

Python socket 기반 채팅 프로그램에 공개키 교환 방식을 적용해 클라이언트-서버 간 암호화 통신 채널을 구성했습니다. 메시지는 JSON header와 binary payload로 분리하고, 4바이트 길이 prefix를 사용하는 자체 패킷 프로토콜로 framing했습니다. 서버는 다중 클라이언트 접속을 스레드로 처리하며, 전체 채팅, 1:1 귓속말, 이미지 전송, 접속자 목록 동기화를 지원합니다. 또한 공개키 fingerprint와 세션 ID를 GUI에 표시하고, 이미지 payload는 SHA-256 해시로 무결성을 확인하도록 구현했습니다. payload 크기 제한, header 크기 검증, 파일명 정규화 등을 적용해 비정상 패킷과 파일 경로 조작 가능성을 줄였습니다.

## 시연 포인트

- GUI 좌측 보안 세션 패널에서 cipher, session id, client/server fingerprint 확인
- `/security` 명령어로 현재 암호화 세션 정보 출력
- `/stats` 명령어로 서버 uptime, 접속자 수, 메시지/이미지 전송량 조회
- 이미지 전송 시 SHA-256 해시를 header에 포함하고 수신 측에서 payload 무결성 확인
- `/save` 명령어로 보안 세션 정보가 포함된 대화 로그 저장

## 개선 예정 아이디어

- 키 핀닝 또는 인증서 검증
- CLI 클라이언트 추가
- 서버 설정 파일 분리
- 데모 GIF 및 실행 화면 스크린샷 추가
