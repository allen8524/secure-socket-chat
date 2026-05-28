# Security Notes

## 적용한 보안 요소

### 공개키 기반 키 교환

서버와 클라이언트는 각각 임시 PrivateKey/PublicKey를 생성합니다. 서버가 먼저 공개키를 보내고, 클라이언트가 자신의 공개키를 응답합니다. 이후 양쪽은 PyNaCl Box를 생성해 같은 암호화 채널을 구성합니다.

### TOFU 기반 서버 fingerprint 검증

클라이언트는 서버 공개키 fingerprint를 `~/.secure_socket_chat/trusted_servers.json`에 host:port 단위로 저장합니다. 최초 접속 서버는 TOFU 신뢰 저장소에 등록되고, 이후 같은 host:port로 접속했을 때 fingerprint가 다르면 GUI에서 보안 경고를 표시합니다.

사용자가 변경된 fingerprint를 신뢰하고 계속하기로 선택한 경우에만 로컬 저장소가 갱신됩니다. 이 파일에는 서버 fingerprint, first_seen, last_seen, trust_mode만 저장하며 서버 개인키, 클라이언트 개인키, 세션 키 같은 민감한 암호화 자료는 저장하지 않습니다.

### 암호화 채널

메시지 header와 payload를 하나의 논리 패킷으로 만든 뒤, 논리 패킷 전체를 암호화합니다. 따라서 일반 채팅 메시지뿐 아니라 이미지와 일반 파일 payload도 암호화된 상태로 전송됩니다.

### SHA-256 기반 파일 무결성 검증

이미지와 일반 파일 전송 시 송신자는 payload의 SHA-256 해시를 header에 포함합니다. 수신자는 payload를 받은 뒤 SHA-256을 다시 계산해 header 값과 비교하고, GUI 채팅 로그와 Security Dashboard에 `OK`, `FAIL`, `Unknown` 중 하나로 표시합니다.

검증 실패(`FAIL`)인 파일은 저장하지 않고 경고를 남깁니다. 이 검증은 전송 중 payload가 바뀌었는지 확인하는 용도이며, 파일 내용 자체가 안전하다는 의미는 아닙니다.

### 패킷 크기 제한

비정상적으로 큰 패킷으로 인한 메모리 사용량 증가를 줄이기 위해 header와 payload에 최대 크기를 둡니다.

### Sequence 기반 replay 방어

암호화 logical packet에는 채널 단위 sequence number가 포함됩니다. 송신 측은 패킷을 보낼 때마다 sequence를 증가시키고, 수신 측은 마지막으로 처리한 sequence 이하의 패킷을 replay 의심 패킷으로 차단합니다.

### 실험적 E2E whisper mode

일반 transport SecureChannel은 클라이언트-서버 간 안전한 연결을 담당합니다. 실험적 E2E whisper mode는 이 구조 위에서 1:1 텍스트 whisper 본문만 한 번 더 수신자 E2E 공개키로 암호화합니다.

각 클라이언트는 세션 단위 E2E `PrivateKey/PublicKey`를 생성하고, join packet을 통해 E2E public key와 fingerprint를 서버에 등록합니다. 서버는 사용자 목록에 E2E key metadata를 포함해 배포하고, `/e2e 사용자명 메시지`로 생성된 `e2e_whisper` packet은 본문을 복호화하지 않고 대상 클라이언트에게 라우팅합니다.

사용자는 `/fingerprint 사용자명` 명령어 또는 GUI의 `E2E FP 확인` 버튼으로 상대 사용자의 현재 세션 E2E fingerprint를 확인할 수 있습니다. 이 값은 상대방과 별도 채널에서 직접 비교하는 데 사용할 수 있는 보조 정보입니다.

서버가 복호화하지 못하는 정보:

- E2E inner payload의 `text`
- E2E inner payload의 생성 시각과 본문 JSON

서버가 여전히 볼 수 있는 metadata:

- 송신자와 수신자
- E2E public key와 fingerprint
- ciphertext 크기와 전송 시점
- transport packet 크기와 라우팅 흐름

### 파일명 정규화

수신 이미지와 일반 파일 저장 시 POSIX 스타일 경로 요소를 제거하고 남은 경로 구분자를 `_`로 치환합니다. 이를 통해 `../../example.png`와 같은 경로 조작 시도를 줄입니다.

### 실행 파일 전송 주의사항

`.exe`, `.bat`, `.cmd`, `.ps1`, `.sh` 등 실행 파일 또는 스크립트로 보이는 확장자는 송신 전 GUI 경고를 표시합니다. 현재 구현은 사용자가 확인하면 전송을 허용하지만, 운영 환경에서는 확장자 차단, 다운로드 승인, 바이러스 검사 같은 추가 정책이 필요합니다.

## 제한 사항

### 전체 기능에 대한 종단 간 암호화 보장 아님

기본 구조는 클라이언트와 서버 사이의 암호화 채널입니다. 서버는 일반 chat, 일반 whisper, 파일/이미지 packet을 받은 뒤 복호화하고, 대상 클라이언트에게 다시 암호화해서 전달합니다.

실험적 E2E whisper mode에서는 1:1 텍스트 whisper 본문만 추가로 보호하지만, 프로젝트 전체가 서버가 모든 내용을 볼 수 없는 end-to-end encryption 구조는 아닙니다.

### 공개키 인증 부재

공개키 교환, fingerprint 표시, TOFU 기반 변경 감지는 구현되어 있지만, 인증기관 기반 인증서 검증이나 강한 키 핀닝은 적용되어 있지 않습니다. 따라서 실제 운영 환경에서 중간자 공격까지 방어하려면 추가 인증 절차가 필요합니다.

### TOFU의 한계

TOFU는 최초 접속 이후의 fingerprint 변경을 감지하는 방식입니다. 최초 접속 시점에 이미 공격자가 개입했다면 잘못된 fingerprint를 신뢰할 수 있습니다.

또한 현재 서버 키는 연결 단위로 임시 생성됩니다. 따라서 서버를 재시작하거나 클라이언트가 다시 접속하면 fingerprint가 바뀌어 TOFU 경고가 발생할 수 있습니다. 운영형 신뢰 모델을 만들려면 서버 키를 안전하게 영속화하고, 키 핀닝 또는 인증서 기반 검증을 추가해야 합니다.

### 학습 목적 프로젝트

이 프로젝트는 네트워크 보안, 소켓 프로그래밍, 패킷 설계, 암호화 채널 구현을 보여주기 위한 학습/포트폴리오 목적의 예제입니다.

운영 환경의 메신저로 사용하려면 다음 보완이 필요합니다.

- 인증된 키 교환
- 서버 키 영속화
- 키 핀닝 또는 인증서 기반 서버 인증
- 사용자 인증
- 메시지 저장 정책
- 서버 접근 제어
- TLS 또는 검증 가능한 transport layer 추가
- 로그 민감정보 마스킹
- rate limiting

### E2E mode의 한계

이번 E2E mode는 1:1 텍스트 whisper만 대상으로 합니다. 전체 채팅 broadcast와 파일/이미지 전송은 E2E 대상이 아닙니다.

클라이언트 E2E key는 세션 단위로 생성되므로 재접속 시 fingerprint가 바뀔 수 있습니다. 또한 서버가 사용자 E2E public key를 배포하는 구조이므로, 악의적인 서버가 public key를 바꿔치기하는 key substitution 공격을 완전히 막지는 못합니다.

`/fingerprint` 확인 기능은 사용자가 fingerprint를 직접 비교할 수 있게 돕지만, 인증기관 기반 인증이나 자동 신뢰 검증을 제공하지는 않습니다. 향후 개선 방향은 사용자 E2E fingerprint TOFU, key pinning, QR fingerprint verification, persistent identity key 도입입니다.
