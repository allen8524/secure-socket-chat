# Protocol

## Raw packet format

모든 네트워크 패킷은 다음 구조를 사용합니다.

```txt
+----------------------+----------------------+------------------+
| 4 bytes header size  | JSON header          | binary payload   |
+----------------------+----------------------+------------------+
```

- header size: unsigned big-endian integer
- JSON header: UTF-8 encoded JSON object
- binary payload: 이미지와 같은 바이너리 데이터

## Header 예시

```json
{
  "type": "chat",
  "text": "hello",
  "payload_size": 0
}
```

이미지 전송 예시입니다.

```json
{
  "type": "image",
  "to": "전체",
  "filename": "sample.png",
  "payload_size": 1024
}
```

## Secure packet

암호화 전 논리 패킷도 같은 형식입니다.

```txt
logical packet = header length + JSON header + payload
```

이 논리 패킷 전체를 PyNaCl Box로 암호화한 뒤, 바깥 raw packet의 payload에 넣습니다.

```json
{
  "type": "secure",
  "payload_size": 2048
}
```

## Packet types

| type | 방향 | 설명 |
|---|---|---|
| `server_public_key` | server -> client | 서버 공개키 전달 |
| `client_public_key` | client -> server | 클라이언트 공개키 전달 |
| `secure` | both | 암호화된 논리 패킷 wrapper |
| `join` | client -> server | 사용자 입장 요청 |
| `leave` | client -> server | 사용자 퇴장 요청 |
| `chat` | both | 전체 메시지 |
| `whisper` | both | 1:1 메시지 |
| `image` | both | 이미지 전송 |
| `users` | server -> client | 접속자 목록 갱신 |
| `system` | server -> client | 시스템 알림 |
| `error` | server -> client | 오류 알림 |

## 방어 로직

- header size가 0 이하이거나 최대값을 넘으면 거부
- payload size가 음수이거나 최대값을 넘으면 거부
- JSON header가 object가 아니면 거부
- 복호화된 payload 길이와 header의 payload_size가 다르면 거부
