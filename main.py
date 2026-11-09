import re
import os
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import StreamingResponse
from google import genai
from google.genai import errors
from pydantic import BaseModel

from agents import (
    BLOCK_THRESHOLD,
    SANITIZE_THRESHOLD,
    SecurityAnalysisUnavailable,
    analyze_threat_l1_async,
    sanitize_prompt_l2_async,
    stream_main_llm_response,
    l0_pre_filter,
)
from database import block_user, init_db, is_user_blocked, log_event, reset_db

# 환경 변수 로드
load_dotenv()

app = FastAPI(title="Autonomous AI SOC Security Gateway")

# Gemini API 클라이언트 설정
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
client = genai.Client(api_key=GEMINI_API_KEY)

# 메인 LLM 서비스용 Fallback Chain 모델 리스트
MAIN_MODELS_CHAIN = [
    "gemini-3.5-flash-lite",      # 1순위: 메인 서비스 모델
    "gemini-3.6-flash",           # 2순위: gemini-2.5-flash-lite 제공 중단(404)으로 교체, 실측상 3.1-flash-lite보다 빨라 2순위
    "gemini-3.1-flash-lite"       # 3순위: 백업 모델
]


class ChatRequest(BaseModel):
    user_id: str
    prompt: str


class SecurityDecision(BaseModel):
    final_prompt: str
    soc_action: str        # PASSED | SANITIZED
    threat_score: float


@app.on_event("startup")
def startup_event():
    """서버 시작 시 SQLite 테이블 및 인덱스 초기화"""
    init_db()


@app.post("/admin/reset-db")
def admin_reset_db(confirm: bool = Query(False)):
    """관리자 전용: 데이터베이스 완전 초기화 엔드포인트 (로컬 개발용, 인증 미적용)"""
    if not confirm:
        raise HTTPException(
            status_code=400, detail="Set confirm=true to reset database."
        )
    reset_db()
    return {"status": "success", "message": "Database successfully reset."}


def _sanitize_failure_reason(raw: str, sanitized: str) -> str | None:
    """L2 정화 결과가 '다시 쓴 요청문'으로 보이지 않으면 실패 사유를 반환한다.
    벤치마크 로그에서 확인된 세 가지 실패 유형을 막는다.
    - EMPTY  : 남길 정상 요청이 없음 (요청 전체가 악성)
    - NOOP   : 원문을 그대로 돌려줌 (아무것도 제거하지 못함)
    - ANSWER : 요청을 다시 쓰지 않고 직접 답변함 (코드 블록, 여러 문단, 원문보다 훨씬 긴 출력)
    """
    def _norm(t: str) -> str:
        return re.sub(r"[\s\W_]+", "", t or "").lower()
    out = (sanitized or "").strip()
    if not out:
        return "EMPTY"
    if _norm(out) == _norm(raw):
        return "NOOP"
    if "```" in out and "```" not in raw:
        return "ANSWER"
    if out.count("\n") >= 3 and raw.count("\n") < 2:
        return "ANSWER"
    if len(out) > len(raw) * 1.5 + 40:
        return "ANSWER"
    return None


async def run_security_pipeline(user_id: str, raw_prompt: str) -> SecurityDecision:
    """
    두 엔드포인트(/v1/chat, /v1/chat/stream)가 공유하는 SOC 보안 파이프라인
    블랙리스트 -> L0 사전 필터 -> L1 위협 평가 -> L2 정화
    통과 시 SecurityDecision 반환, 차단/장애 시 HTTPException 발생
    """
    # 1. DB 블랙리스트 사전 검증 (인덱스 조회)
    if is_user_blocked(user_id):
        raise HTTPException(
            status_code=403,
            detail="[SOC Alert] Access Denied: Your User ID is permanently blocked due to malicious activity.",
        )

    # 2. L0 로컬 사전 필터링 (API 호출 없는 Fast-Block / Fast-Pass)
    l0_result = l0_pre_filter(raw_prompt)
    if l0_result:
        if l0_result["action"] == "BLOCK":
            block_user(user_id, l0_result["reason"])
            log_event(user_id, raw_prompt, 1.0, "PROMPT_INJECTION", "BLOCKED")
            raise HTTPException(status_code=403, detail=l0_result["reason"])
        if l0_result["action"] == "PASS":
            log_event(user_id, raw_prompt, 0.0, "NONE", "PASSED")
            return SecurityDecision(final_prompt=raw_prompt, soc_action="PASSED", threat_score=0.0)

    # 3. 비동기 L1 보안 분석 (Gemini API + Fallback Chain)
    try:
        sec_report = await analyze_threat_l1_async(raw_prompt)
    except SecurityAnalysisUnavailable:
        # Fail-Closed: 보안 검사를 못 했으면 메인 LLM을 호출하지 않음 (사용자는 차단하지 않음)
        log_event(user_id, raw_prompt, -1.0, "UNKNOWN", "UNAVAILABLE")
        raise HTTPException(
            status_code=503,
            detail="[SOC Warning] Security analysis is temporarily unavailable. Please try again later.",
        )

    threat_score = float(sec_report.get("threat_score", 0.0))
    attack_type = sec_report.get("attack_type", "NONE")
    reason = sec_report.get("reason", "")

    print(f"[SOC Monitor] User: {user_id} | Threat Score: {threat_score} | Type: {attack_type}")

    # 4. 고위협 (Score >= BLOCK_THRESHOLD): 차단 및 DB 블랙리스트 자동 등록
    if threat_score >= BLOCK_THRESHOLD:
        block_user(user_id, f"High threat detected ({attack_type}): {reason}")
        log_event(user_id, raw_prompt, threat_score, attack_type, "BLOCKED")
        raise HTTPException(
            status_code=403,
            detail=f"[SOC Blocked] Malicious behavior detected ({attack_type}). Reason: {reason}",
        )

    # 5. 중위협 (SANITIZE_THRESHOLD <= Score < BLOCK_THRESHOLD): L2 프롬프트 정화
    final_prompt = raw_prompt
    soc_action = "PASSED"
    if threat_score >= SANITIZE_THRESHOLD:
        soc_action = "SANITIZED"
        try:
            final_prompt = await sanitize_prompt_l2_async(raw_prompt)
        except SecurityAnalysisUnavailable:
            log_event(user_id, raw_prompt, threat_score, attack_type, "UNAVAILABLE")
            raise HTTPException(
                status_code=503,
                detail="[SOC Warning] Prompt sanitization is temporarily unavailable. Please try again later.",
            )
        # 정화 결과 검증: 정화기(L2)도 AI라서 출력을 그대로 믿지 않는다. 이상하면 통과시키지 않고 차단 (Fail-Closed)
        failure = _sanitize_failure_reason(raw_prompt, final_prompt)
        if failure:
            log_event(user_id, raw_prompt, threat_score, attack_type, f"BLOCKED_SANITIZE_{failure}")
            print(f"[SOC Defense] Sanitization failed ({failure}) -> blocked: '{raw_prompt[:60]}'")
            raise HTTPException(
                status_code=403,
                detail=f"[SOC Blocked] Suspicious request could not be safely sanitized ({attack_type}). Reason: {reason}",
            )
        print(f"[SOC Defense] Prompt Sanitized: '{raw_prompt}' -> '{final_prompt}'")

    log_event(user_id, raw_prompt, threat_score, attack_type, soc_action)
    return SecurityDecision(final_prompt=final_prompt, soc_action=soc_action, threat_score=threat_score)


@app.post("/v1/chat")
async def chat_endpoint(request: ChatRequest):
    """일반 JSON 응답 엔드포인트"""
    decision = await run_security_pipeline(request.user_id, request.prompt)
    return await _generate_main_llm_json_response(
        decision.final_prompt, decision.soc_action, decision.threat_score
    )


@app.post("/v1/chat/stream")
async def chat_stream_endpoint(request: ChatRequest):
    """실시간 스트리밍 응답 엔드포인트 (첫 토큰 생성 즉시 전송으로 체감 지연 시간 최소화)"""
    decision = await run_security_pipeline(request.user_id, request.prompt)
    return StreamingResponse(
        stream_main_llm_response(decision.final_prompt, MAIN_MODELS_CHAIN),
        media_type="text/plain",
        headers={"X-SOC-Action": decision.soc_action, "X-SOC-Threat-Score": str(decision.threat_score)},
    )


async def _generate_main_llm_json_response(prompt: str, soc_action: str, threat_score: float):
    """메인 LLM JSON 응답 생성 헬퍼 함수 (Fallback Chain 순차 적용)"""
    for current_model in MAIN_MODELS_CHAIN:
        try:
            response = await client.aio.models.generate_content(
                model=current_model, contents=prompt
            )
            return {
                "status": "success",
                "soc_action": soc_action,
                "threat_score": threat_score,
                "response": response.text,
                "model_used": current_model,
            }
        except errors.APIError as e:
            print(f"[Main LLM Warning] {current_model} failed ({e.code}). Switching to next model...")
            continue
        except Exception as e:
            print(f"[Main LLM Error] {current_model} unexpected error: {e}")
            continue

    raise HTTPException(
        status_code=503,
        detail="[SOC Warning] All upstream AI models in chain are currently unavailable. Please try again later.",
    )
