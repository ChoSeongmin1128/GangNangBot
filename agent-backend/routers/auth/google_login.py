"""
GET /auth/google/login - Google OAuth 로그인 시작
"""
from fastapi import APIRouter, HTTPException, Request, Query
import config
from .oauth_config import oauth

router = APIRouter()


@router.get("/google/login")
async def google_login(request: Request, redirect_uri: str = Query(None)):
    """
    Google OAuth 로그인 URL로 리다이렉트
    
    Args:
        redirect_uri: 로그인 완료 후 리다이렉트할 URI
    
    Authlib이 자동으로 State 생성 및 세션 저장을 처리합니다.
    """
    if not config.GOOGLE_CLIENT_ID or not config.GOOGLE_CLIENT_SECRET:
        raise HTTPException(
            status_code=500,
            detail="OAuth credentials not configured"
        )
    
    # 사용자가 지정한 redirect_uri가 있으면 세션에 저장
    if redirect_uri:
        request.session['oauth_redirect_uri'] = redirect_uri
    
    # OAuth 콜백 URI 동적 생성 (현재 요청 도메인 유지)
    # config.OAUTH_REDIRECT_URI가 있으면 그것을 우선 사용하되, 
    # 없거나 동적 처리를 원할 경우 request.url_for 사용
    
    # 1. 기본적으로 현재 요청의 호스트를 기반으로 콜백 URL 생성
    oauth_redirect_uri = str(request.url_for('google_callback'))
    
    # 2. 프로덕션 환경(Cloud Run)에서 HTTPS 강제 처리
    # (로드밸런서 뒤에서는 http로 인식될 수 있음)
    if "localhost" not in oauth_redirect_uri and oauth_redirect_uri.startswith("http://"):
        oauth_redirect_uri = oauth_redirect_uri.replace("http://", "https://")
        
    return await oauth.google.authorize_redirect(request, oauth_redirect_uri)
