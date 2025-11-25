"""
Agent Backend API

FastAPI 백엔드 - Agent Engine과 연동
"""

# [중요 1] 이 설정이 다른 모듈 임포트보다 가장 먼저 실행되어야 합니다.
# Windows 환경에서 ProactorEventLoop 오류를 방지하기 위해 SelectorEventLoop로 강제 설정합니다.
# if sys.platform.startswith("win"):
#     asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import sys
import os

# 현재 디렉토리(agent-backend)를 sys.path에 추가하여
# routers, utils 등을 절대 경로로 import 할 수 있게 함
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
from starlette.middleware.sessions import SessionMiddleware

# 새로운 라우터 구조
from routers.sessions import router as sessions_router
from routers.chat import router as chat_router
from routers.auth import router as auth_router
from routers.profiles import router as profiles_router
from routers import database

import config

# HTTPBearer security scheme (Swagger UI용)
security = HTTPBearer()

# FastAPI 앱 생성
app = FastAPI(
    title="Kangnam Agent API",
    description="강남대학교 Multi-Agent 챗봇 API",
    version="2.0.0",
    # Swagger UI에 Bearer 인증 추가
    swagger_ui_parameters={
        "persistAuthorization": True
    }
)

# CORS 설정 (프론트엔드 연동용)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 프로덕션에서는 특정 도메인으로 제한
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 세션 미들웨어 (OAuth State 관리용)
# 환경에 따라 자동으로 설정 조정
IS_PRODUCTION = os.getenv("K_SERVICE") is not None  # Cloud Run 환경 감지
OAUTH_REDIRECT_URI = config.OAUTH_REDIRECT_URI or ""

# 프로덕션 환경 판단: Cloud Run이거나 HTTPS를 사용하는 경우
is_https = OAUTH_REDIRECT_URI.startswith("https://")

if IS_PRODUCTION or is_https:
    # 프로덕션 환경: SameSite=Lax (Google OAuth GET 리다이렉트 지원)
    # same_site='none'은 HTTPS 필수이므로 HTTP 리다이렉트 URI를 지원하려면 'lax' 사용
    app.add_middleware(
        SessionMiddleware,
        secret_key=config.JWT_SECRET_KEY or "secret-key",
        same_site="lax",   # GET 요청 시 크로스 사이트 쿠키 전송 (OAuth 리다이렉트 지원)
        https_only=False,  # HTTP 리다이렉트 URI도 지원
    )
    print("[INFO] Session middleware configured for PRODUCTION (SameSite=Lax, HTTPS not required)")
else:
    # 로컬 개발 환경: HTTP 허용, SameSite=Lax
    app.add_middleware(
        SessionMiddleware,
        secret_key=config.JWT_SECRET_KEY or "secret-key",
        same_site="lax",   # 일반적인 크로스 사이트 요청에서 쿠키 전송
        https_only=False,  # HTTP에서도 쿠키 전송
    )
    print("[INFO] Session middleware configured for DEVELOPMENT (HTTP, SameSite=Lax)")

# 라우터 등록 (새로운 구조)
app.include_router(sessions_router)
app.include_router(chat_router)
app.include_router(auth_router)
app.include_router(profiles_router)
app.include_router(database.router, prefix="/db", tags=["database"])

# 헬스체크 (Cloud Run 필수)
@app.get("/health")
async def health_check():
    """헬스체크 엔드포인트"""
    return {"status": "ok", "service": "agent-backend-api"}

# 루트 엔드포인트
@app.get("/")
async def root():
    """API 정보"""
    return {
        "service": "Kangnam Agent API",
        "version": "2.0.0",
        "endpoints": {
            "health": "/health",
            "create_session": "POST /sessions",
            "list_sessions": "GET /sessions",
            "send_message": "POST /chat/message",
            "get_messages": "GET /sessions/{session_id}/messages",
            "delete_session": "DELETE /sessions/{session_id}",
            "save_profile": "POST /profiles"
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
    # Uvicorn이 실행되면서 위에서 설정한 SelectorEventLoop를 무시하고 
    # 다시 Proactor로 돌아가는 것을 방지합니다.
    # uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=True, loop="asyncio")
