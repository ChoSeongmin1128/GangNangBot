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

router = APIRouter()


@router.get("/google/callback")
async def google_callback(request: Request, db: AsyncSession = Depends(get_db)):
    """
    Google OAuth 콜백 처리
    
    Google로부터 인증 코드를 받아 토큰으로 교환하고,
    사용자 정보를 DB에 저장한 후 JWT 토큰을 반환합니다.
    
    세션에 저장된 redirect_uri가 있으면 해당 URI로 리다이렉트하고,
    없으면 기본적으로 JSON 응답을 반환합니다.
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
        
        # 세션에서 redirect_uri 확인
        redirect_uri = request.session.get('oauth_redirect_uri')
        
        # 기본 JSON 응답 데이터 구성
        response_data = {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "id": user_id,
                "email": email,
                "name": name
            }
        }
        
        # redirect_uri가 있으면 해당 URI로 리다이렉트
        if redirect_uri:
            from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
            
            # 세션에서 redirect_uri 제거 (한 번만 사용)
            del request.session['oauth_redirect_uri']
            
            # redirect_uri를 파싱하여 기존 쿼리 파라미터 추출
            parsed = urlparse(redirect_uri)
            existing_params = parse_qs(parsed.query)
            
            # 기존 파라미터를 단일 값으로 변환 (parse_qs는 리스트로 반환)
            params = {k: v[0] if isinstance(v, list) and len(v) == 1 else v 
                     for k, v in existing_params.items()}
            
            # token 파라미터 추가 (기존 파라미터 뒤에)
            params['token'] = access_token
            
            # URL 재구성
            new_query = urlencode(params)
            redirect_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment
            ))
            
            return RedirectResponse(url=redirect_url)
        
        # redirect_uri가 없으면 JSON 응답 반환
        return response_data
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"OAuth callback failed: {str(e)}"
        )
