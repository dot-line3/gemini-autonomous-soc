"""
모델 사용 가능 여부 점검 스크립트

models.list()에 나와도 "no longer available to new users"(404)로 막힌 모델이 있어,
후보 모델에 짧은 요청을 실제로 1번씩 보내 지금 이 API 키로 쓸 수 있는지 확인한다.
(후보 1개당 요청 1건만 사용)

실행: python check_models.py
"""
import os
import time

from dotenv import load_dotenv
from google import genai
from google.genai import errors

load_dotenv()
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

CANDIDATES = [
    # 현재 SOC 체인
    "gemini-3.5-flash-lite",
    "gemini-3.1-flash-lite",
    "gemini-2.5-flash-lite",
    # 3순위 교체 후보
    "gemini-flash-lite-latest",
    "gemini-3.5-flash",
    "gemini-3.6-flash",
    "gemini-3.8-flash",
    # OOTD / Spotify가 마지막 백업으로 쓰는 모델
    "gemini-2.5-flash",
]

print(f"{'모델':<28} {'결과':<10} {'응답 시간':>9}  비고")
print("-" * 80)
for model in CANDIDATES:
    start = time.time()
    try:
        r = client.models.generate_content(model=model, contents="Reply with the single word: OK")
        status, note = "OK", (r.text or "").strip()[:20]
    except errors.APIError as e:
        status, note = f"ERR {e.code}", str(e)[:60].replace("\n", " ")
    except Exception as e:
        status, note = "ERR", f"{type(e).__name__}: {str(e)[:50]}"
    print(f"{model:<28} {status:<10} {time.time() - start:>8.2f}s  {note}")
    time.sleep(1.0)  # 연속 호출로 429가 나는 것을 줄이기 위한 간격
