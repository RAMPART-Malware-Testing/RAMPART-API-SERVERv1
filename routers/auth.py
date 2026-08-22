from fastapi import APIRouter, Request

from controller.oauth_controller import oauth_callback_controller, oauth_login_controller

router = APIRouter(
    prefix="/api/auth",
    tags=["Auth"]
)


@router.get("/{provider}/login")
async def oauth_login(provider: str, request: Request):
    """Redirects the browser to Google/GitHub's consent screen.

    provider: "google" | "github"
    """
    return await oauth_login_controller(request, provider)


@router.get("/{provider}/callback")
async def oauth_callback(provider: str, request: Request):
    """Google/GitHub redirects back here after the user grants access.

    On success this issues the same `access` JWT the rest of the API already
    expects (7 day expiry). Signing in again with the same provider account
    always resolves to the same `uid`.
    """
    return await oauth_callback_controller(request, provider)
