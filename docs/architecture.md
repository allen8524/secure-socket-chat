# Architecture

## 전체 구조

SecureSocketChat은 서버가 중앙에서 접속자를 관리하고 메시지를 라우팅하는 클라이언트-서버 구조입니다.

```txt
Client
  ├─ GUI
  ├─ ChatClient
  └─ SecureChannel
        ↓ encrypted raw packet
Server
  ├─ ChatServer
  ├─ clients registry
  └─ SecureChannel per client
```

## 서버 흐름

1. 서버 socket bind/listen
2. 클라이언트 접속 수락
3. 클라이언트별 처리 스레드 생성
4. 공개키 교환
5. 암호화 채널 생성
6. join 요청 검증
7. 사용자 등록
8. chat, whisper, image 패킷 라우팅
9. leave 또는 연결 종료 시 사용자 제거

## 클라이언트 흐름

1. GUI 실행
2. 사용자 이름 입력 또는 CLI 인자 사용
3. 서버 접속
4. 공개키 교환
5. 암호화 채널 생성
6. join 패킷 전송
7. 수신 스레드 시작
8. 수신 메시지를 queue에 저장
9. Tkinter event loop에서 queue를 읽어 화면 갱신

## 책임 분리

| 모듈 | 책임 |
|---|---|
| `protocol.py` | 패킷 구조, 송수신, 검증 |
| `crypto_channel.py` | 키 교환, 암호화 송수신 |
| `server.py` | 접속자 관리, 메시지 라우팅 |
| `client.py` | 네트워크 클라이언트, 수신 스레드 |
| `gui.py` | 화면 구성, 사용자 입력 처리 |
| `utils.py` | 파일명 정규화, 수신 파일 저장 |

## 왜 queue를 사용하는가

Tkinter는 메인 스레드에서 UI를 갱신해야 합니다. 네트워크 수신 스레드가 직접 UI를 수정하면 race condition 또는 런타임 오류가 발생할 수 있습니다.

따라서 수신 스레드는 메시지를 queue에 넣고, GUI 메인 루프는 `after()`로 주기적으로 queue를 읽어 화면을 갱신합니다.
