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

class ResetPasswdParame(BaseModel):
    email: str | None = None
    token: str | None = None
    newPasswd: str | None = None

class ResetPasswdConfirmParame(BaseModel):
    token: str
    otp: str
    newPasswd: str


