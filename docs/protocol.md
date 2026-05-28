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
- binary payload: 이미지나 일반 파일 같은 바이너리 데이터

## Header 예시

```json
{
  "type": "chat",
  "text": "hello",
  "sequence": 12,
  "payload_size": 0
}
```

이미지 전송 예시입니다.

```json
{
  "type": "image",
  "to": "전체",
  "filename": "sample.png",
  "sequence": 13,
  "sha256": "이미지 payload의 SHA-256 해시",
  "payload_size": 1024
}
```

일반 파일 전송 예시입니다.

```json
{
  "type": "file",
  "to": "bob",
  "filename": "report.pdf",
  "file_size": 250880,
  "sha256": "파일 payload의 SHA-256 해시",
  "mime_type": "application/pdf",
  "extension": ".pdf",
  "sequence": 14,
  "payload_size": 250880
}
```

## Secure packet

암호화 전 논리 패킷도 같은 형식입니다.

```txt
logical packet = header length + JSON header + payload
```

이 논리 패킷 전체를 PyNaCl Box로 암호화한 뒤, 바깥 raw packet의 payload에 넣습니다.

`sequence`는 암호화 전 logical header에 포함되며, SecureChannel이 송신할 때마다 1씩 증가시킵니다. 수신 측은 채널별 마지막 sequence를 저장하고, sequence가 없거나 정수가 아니거나 마지막으로 처리한 sequence 이하이면 패킷을 거부합니다.

```json
{
  "type": "secure",
  "payload_size": 2048
}
```

## Packet Inspector

GUI 클라이언트의 Packet Inspector는 시연용 관찰 기능입니다. 암호화 전 logical packet과 암호화 후 transport packet의 차이를 이해할 수 있도록 최근 패킷의 요약만 표시합니다.

| 표시 항목 | 의미 |
|---|---|
| direction | `OUTBOUND` 또는 `INBOUND` 방향 |
| logical packet type | 복호화된 논리 패킷의 `type` 값 |
| logical header summary | 메시지 전문 대신 type, 대상, 파일명, 짧은 text preview 등 안전한 요약 |
| sequence | logical header에 포함된 sequence number |
| replay | sequence 기반 replay 검증 결과 |
| blocked | replay 또는 비정상 sequence로 패킷이 차단되었는지 여부 |
| payload size | logical packet의 payload byte 크기 |
| encrypted packet size | PyNaCl Box로 암호화된 transport payload byte 크기 |
| ciphertext preview | base64로 인코딩한 암호문의 앞부분 일부 |
| integrity hash | 이미지/file header에 SHA-256 값이 포함되었는지 여부 |
| integrity result | GUI에서 payload SHA-256을 재계산해 확인한 무결성 결과 |
| decrypt | 수신 패킷 복호화 성공 여부 |
| last error | 복호화 또는 패킷 처리 중 마지막 오류 요약 |

Packet Inspector는 암호화 키, 개인키, 전체 메시지 본문, 전체 이미지/file binary, 전체 암호문을 표시하지 않습니다. 운영 환경에서는 이런 상세 preview도 더 제한하거나 비활성화하는 것이 안전합니다.

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
| `file` | both | 일반 파일 전송 |
| `users` | server -> client | 접속자 목록 갱신 |
| `system` | server -> client | 시스템 알림 |
| `error` | server -> client | 오류 알림 |

## 방어 로직

- header size가 0 이하이거나 최대값을 넘으면 거부
- payload size가 음수이거나 최대값을 넘으면 거부
- JSON header가 object가 아니면 거부
- 복호화된 payload 길이와 header의 payload_size가 다르면 거부
- 암호화 logical packet에 sequence가 없거나 정수가 아니면 거부
- 수신한 sequence가 채널에서 마지막으로 처리한 sequence 이하이면 replay 의심 패킷으로 차단
- file/image payload는 header의 SHA-256 값과 수신 payload의 SHA-256 값을 비교해 무결성을 확인
