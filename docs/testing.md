# Testing

## 실행 방법

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
pytest -q
```

모든 테스트는 GUI 창을 띄우지 않고 실행됩니다. Tkinter 화면 구성과 실제 파일 선택 대화상자는 수동 확인 대상입니다.

coverage를 포함해 실행하려면 다음 명령어를 사용합니다.

```bash
pytest --cov=secure_chat --cov-report=term-missing
```

로컬에서 CI와 같은 품질 검사를 확인하려면 아래 명령어를 순서대로 실행합니다.

```bash
ruff check .
pytest --cov=secure_chat --cov-report=term-missing
bandit -r secure_chat
```

## 테스트 구조

| 범위 | 파일 | 내용 |
|---|---|---|
| 프로토콜 단위 테스트 | `tests/test_protocol.py`, `tests/test_protocol_invalid_packets.py` | packet packing/unpacking, header/payload 크기 제한, 깨진 JSON, payload 길이 불일치 |
| 암호화 채널 테스트 | `tests/test_crypto_channel.py`, `tests/test_sequence_replay.py` | PyNaCl Box 송수신, sequence 증가, replay/비정상 sequence 차단 |
| E2E whisper 테스트 | `tests/test_e2e.py`, `tests/test_server_e2e.py` | E2E keypair, public key encode/decode, inner payload 암호화/복호화, outer packet 평문 미포함, 서버 E2E 오류 응답 검증 |
| 통합 채팅 테스트 | `tests/test_integration_chat.py` | 실제 서버 thread와 headless client를 연결해 전체 채팅, users 목록, 일반 귓속말, 실험적 E2E whisper, 오류 응답 검증 |
| 통합 파일 테스트 | `tests/test_integration_file_transfer.py` | 실제 서버를 통한 file/image payload 라우팅과 SHA-256 무결성 검증 |
| TOFU 테스트 | `tests/test_trust_store.py` | 임시 trust store에서 최초 등록, 동일 fingerprint, 변경 감지, 깨진 JSON, host:port 분리 저장 검증 |
| GUI 상태 helper 테스트 | `tests/test_gui_dashboard.py`, `tests/test_packet_inspector.py` | Security Dashboard와 Packet Inspector에 표시되는 요약 상태 검증 |
| 데모 helper 테스트 | `tests/test_demo.py` | CLI demo 시나리오 구성, 임시 파일 생성, 메시지 대기 helper, port 점유 감지 |

## 통합 테스트 방식

통합 테스트는 테스트마다 사용 가능한 임시 TCP port를 할당하고, `ChatServer`를 별도 thread로 실행합니다. 테스트 클라이언트는 `ChatClient`를 직접 사용하며 Tkinter GUI에 의존하지 않습니다.

각 테스트는 fixture의 `finally` 경로에서 클라이언트 연결과 서버 socket을 정리합니다. 메시지 수신은 queue와 짧은 timeout을 사용해 실패 원인을 알 수 있도록 구성했습니다.

## 수동 확인 항목

자동 테스트는 프로토콜, 암호화, 실험적 E2E whisper, 파일 전송, TOFU, replay 방어를 검증합니다. 다음 항목은 별도 수동 확인이 필요합니다.

- `python demo.py` 원클릭 데모 출력
- `python run_server.py`
- `python run_client.py --name alice`
- `python run_client.py --name bob`
- GUI 파일 선택 대화상자와 위험 확장자 경고창
- Security Dashboard와 Packet Inspector의 실제 화면 배치
- `/e2e 사용자명 메시지` 입력과 `E2E 전송` 버튼의 실제 GUI 표시 상태

## CI 연동

GitHub Actions의 `Python CI` workflow는 Python 3.10, 3.11, 3.12에서 `ruff check .`, coverage 포함 pytest, `bandit -r secure_chat`을 실행합니다. GUI 창을 띄우는 수동 시나리오는 CI에 포함하지 않습니다.
