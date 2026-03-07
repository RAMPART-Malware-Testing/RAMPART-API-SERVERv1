from pydantic import BaseModel

class AnalysisReportRequest(BaseModel):
    task_id: str

class GenerateTokenParams(BaseModel):
    token: str

