# AI 자율 SOC 파이프라인 (Autonomous AI SOC Security Gateway)

메인 AI 서비스 앞단에서 프롬프트 인젝션, 탈옥(Jailbreak), 정보 유출 시도를 실시간으로 탐지·차단·정화하는 FastAPI 기반 비동기 보안 게이트웨이입니다.

## 🛡 방어 구조 (L0 → L1 → L2)

```
요청 → 블랙리스트 확인 → L0 정규식 사전 필터 → L1 Gemini 위협 스코어링 → L2 정화 → 메인 LLM
```

| 단계 | 역할 | 처리 |
|---|---|---|
| L0 | 명확한 악성 지시어를 API 호출 없이 즉시 차단 | 정규식 Fast-Block / 완전 일치 Fast-Pass |
| L1 | 문맥 기반 위협 점수(0.0~1.0) 산출 | Gemini + Pydantic 구조화 출력 |
| 판정 | Score ≥ 0.8 차단 + 블랙리스트 / 0.4 ≤ Score < 0.8 정화 / 그 외 통과 | `run_security_pipeline()` 공통 함수 |
| L2 | 악성 구문만 제거하고 사용자 의도 유지 | Gemini 정화 |

### 안정성 설계
- **3단계 모델 우회 체인**: `gemini-3.5-flash-lite → gemini-3.1-flash-lite → gemini-2.5-flash-lite`, 503/429 시 1회 재시도 후 다음 모델로 전환
- **Fail-Closed**: 모든 모델이 실패하면 검사되지 않은 요청을 통과시키지 않고 `503` 반환 (사용자는 차단하지 않음)
- **응답 검증**: 빈 응답·잘린 JSON을 감지해 다음 모델로 전환, 원인은 `soc_debug.log`에 기록
- **스트리밍 중복 방지**: 출력 도중 실패하면 다른 모델로 처음부터 다시 생성하지 않음

## 📊 벤치마크 결과 (2026-11-09 측정, `test.py`)

자체 구축 테스트셋 100건 (5개 공격 카테고리 × 적대적 15건 + 정상 5건)

| 지표 | 결과 |
|---|---|
| 적대적 프롬프트 방어 | **75/75 (100%)** — 즉시 차단 74, 정화 1 |
| 정상 요청 통과 | **25/25 (100%)**, 오탐 0건 |
| 차단 응답 지연 (L0+L1) | 1.28초 |
| 정상·정화 응답 지연 (L1+메인 LLM) | 4.64초 |
| 보안 분석 불가 (503) | 0건 — 1순위 모델 할당량 초과(429) 중에도 예비 모델로 자동 전환 |

> 1건은 메인 LLM 응답이 테스트 제한(60초)을 넘겨 응답을 받지 못했으며, 서버 로그상 보안 판정은 정상(PASSED)이었습니다.

## 🔧 개발 중 해결한 문제
- **L0 오탐**: 정상 질문("레시피 추천")을 영구 차단하던 정규식 패턴을 벤치마크로 발견해 제거
- **Fail-Open 취약점**: API 장애 시 위협 점수 0.0으로 통과시키던 구조를 Fail-Closed로 변경
- **판정 누락**: 출력 토큰 한도·생각(thinking) 토큰으로 JSON이 잘리던 문제를 로그로 추적해 모델별 thinking 설정과 응답 검증 추가
- **벤치마크 오염**: 이전 실행의 블랙리스트가 다음 측정에 섞이던 문제를 실행별 고유 ID로 해결

## 🚀 실행 방법

```bash
python -m venv socvenv
socvenv\Scripts\activate          # macOS/Linux: source socvenv/bin/activate
pip install -r requirements.txt
```

`.env` 파일 생성:
```
GEMINI_API_KEY=your_gemini_api_key
```

```bash
uvicorn main:app --reload    # 게이트웨이 실행 (http://127.0.0.1:8000)
python test.py               # 100건 Red-Team 벤치마크 (다른 터미널에서)
```

## ⚠️ 알려진 한계
- `user_id`를 클라이언트가 전달하므로 위조 가능 (API 키/JWT 인증 연동 필요)
- `/admin/reset-db` 엔드포인트에 인증 없음 (로컬 개발용)
- 블랙리스트 해제 절차 없음, async 엔드포인트에서 동기 SQLite 사용
