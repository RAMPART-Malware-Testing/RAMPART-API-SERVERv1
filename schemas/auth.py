from pydantic import BaseModel

class AccessToken(BaseModel):
    token: str

class LoginParame(BaseModel):
    email: str
    password: str

class LoginConfirmParame(BaseModel):
    token: str
    otp: str

class RegisterParame(BaseModel):
    username: str
    email: str
    password: str

class RegisterConfirmParame(BaseModel):
    token: str
    otp: str
    username: str | None = None

class ResetPasswdParame(BaseModel):
    email: str | None = None
    token: str | None = None
    newPasswd: str | None = None

class ResetPasswdConfirmParame(BaseModel):
    token: str
    otp: str
    newPasswd: str

class RefreshTokenParame(BaseModel):
    refresh_token: str

class BridgeTokenParame(BaseModel):
    """Short-lived HS256 token the web app signs with OAUTH_BRIDGE_SECRET once
    it has itself verified the provider. See cores/bridge.py."""
    bridge_token: str

class FirstRunSetupParame(BaseModel):
    username: str
    email: str
    password: str
    confirmPassword: str
