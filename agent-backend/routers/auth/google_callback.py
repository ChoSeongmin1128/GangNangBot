"""
GET /auth/google/callback - Google OAuth 콜백 처리
"""
from fastapi import APIRouter, HTTPException, Request, Depends
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from routers.database import get_db
from utils.jwt import create_access_token
from .oauth_config import oauth
from .helpers import upsert_user
import config

router = APIRouter()


@router.get("/google/callback")
async def google_callback(request: Request, db: AsyncSession = Depends(get_db)):
    """
    Google OAuth 콜백 처리
    
    Google로부터 인증 코드를 받아 토큰으로 교환하고,
    사용자 정보를 DB에 저장한 후 프론트엔드로 리다이렉트합니다.
    """
    try:
        # 토큰 교환 및 검증 (Authlib이 State 검증 자동 수행)
        token = await oauth.google.authorize_access_token(request)
        
        # 사용자 정보 가져오기
        user_info = token.get('userinfo')
        if not user_info:
            raise HTTPException(status_code=400, detail="Failed to get user info")
        
        google_id = user_info.get('sub')
        email = user_info.get('email')
        name = user_info.get('name', email.split('@')[0])
        
        # DB에 사용자 정보 저장/업데이트
        user_id = await upsert_user(db, google_id, email, name)
        
        # JWT 액세스 토큰 생성
        access_token = create_access_token(data={"user_id": user_id})
        
        # 세션에서 프론트엔드 redirect_uri 가져오기 (없으면 기본값 사용)
        frontend_redirect = request.session.get('frontend_redirect_uri')
        if not frontend_redirect:
            # 기본값: config에 설정된 프론트엔드 URL
            frontend_redirect = f"{config.FRONTEND_URL}/auth/callback"
        
        # 세션에서 redirect_uri 제거 (일회성)
        request.session.pop('frontend_redirect_uri', None)
        
        # URL에 이미 쿼리 파라미터가 있는지 확인
        separator = '&' if '?' in frontend_redirect else '?'
        
        # 프론트엔드로 리다이렉트 (token을 URL 파라미터로 전달)
        return RedirectResponse(
            url=f"{frontend_redirect}{separator}token={access_token}&email={email}&name={name}"
        )
        
    except Exception as e:
        # 에러 발생 시 프론트엔드 로그인 페이지로 리다이렉트
        frontend_url = config.FRONTEND_URL
        error_message = str(e).replace(" ", "_")  # URL 안전하게
        return RedirectResponse(
            url=f"{frontend_url}/login?error={error_message}"
        )
