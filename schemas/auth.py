from pydantic import BaseModel

class AccessToken(BaseModel):
    token: str

class LoginParame(BaseModel):
    username: str
    password: str

class LoginConfirmParame(BaseModel):
    token: str
    otp: str

class RegisterParame(BaseModel):
    username: str
    password: str

class RegisterConfirmParame(BaseModel):
    token: str
    otp: str

class ResetPasswdParame(BaseModel):
    username: str

class ResetPasswdConfirmParame(BaseModel):
    token: str
    otp: str
    newPasswd: str


