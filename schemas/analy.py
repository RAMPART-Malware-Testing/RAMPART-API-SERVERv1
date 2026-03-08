from fastapi import File, Form, UploadFile
from pydantic import BaseModel

class AnalysisReportParams(BaseModel):
    task_id: str
    token: str

class GenerateTokenParams(BaseModel):
    token: str

