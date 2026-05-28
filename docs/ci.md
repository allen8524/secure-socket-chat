# CI

## 목적

이 문서는 GitHub Actions에서 수행하는 자동 검증과 로컬에서 같은 검사를 재현하는 방법을 정리합니다. CI는 테스트 통과 여부뿐 아니라 코드 스타일, 기본 보안 스캔, coverage 상태를 함께 확인해 보안 채팅 프로젝트의 변경 위험을 줄이는 데 초점을 둡니다.

## Workflow 구성

workflow 이름은 `Python CI`이며, `main` 브랜치 대상 `push`와 `pull_request`에서 실행됩니다.

| 항목 | 내용 |
|---|---|
| Python 버전 | 3.10, 3.11, 3.12 |
| 테스트 | `pytest --cov=secure_chat --cov-report=term-missing` |
| Lint | `ruff check .` |
| 보안 스캔 | `bandit -r secure_chat` |
| 의존성 | `requirements.txt`, `requirements-dev.txt` |

## 로컬 실행

```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
ruff check .
pytest --cov=secure_chat --cov-report=term-missing
bandit -r secure_chat
```

`requirements.txt`는 실행 의존성 중심으로 유지하고, `requirements-dev.txt`는 pytest, coverage, ruff, bandit 같은 개발 및 CI 도구를 담습니다.

## 자동 검증과 수동 검증의 경계

CI는 GUI 창을 띄우지 않습니다. 통합 테스트는 headless client와 임시 TCP port를 사용해 채팅, 귓속말, 파일 전송, SHA-256 검증, replay 방어, TOFU 로직을 검증합니다.

다음 항목은 수동 확인 대상입니다.

- Tkinter GUI 화면 배치
- 파일 선택 대화상자와 위험 확장자 경고창
- Security Dashboard와 Packet Inspector의 실제 표시 상태
- `python demo.py` 출력 흐름

## Bandit 경고 관리

Bandit은 `secure_chat` 패키지를 대상으로 실행합니다. 테스트 코드의 assert 문이나 테스트 fixture는 스캔 대상에서 제외하고, 실제 애플리케이션 코드에서 발생하는 경고만 확인합니다. 경고를 제외해야 할 경우에는 해당 경고가 학습용/시연용 구조에서 불가피한지 먼저 검토하고, 가능한 한 좁은 범위에서만 설정합니다.
