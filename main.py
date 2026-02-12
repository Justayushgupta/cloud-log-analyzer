from fastapi import FastAPI, UploadFile, File
import re
from sqlalchemy import create_engine, Column, Integer, String, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import json


app = FastAPI()
# Database setup
DATABASE_URL = "sqlite:///./logs.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

class LogReport(Base):
    __tablename__ = "log_reports"

    id = Column(Integer, primary_key=True, index=True)
    summary = Column(String)
    risk_level = Column(String)
    severity_score = Column(Integer)
    attack_type = Column(String)
    report_json = Column(Text)




Base.metadata.create_all(bind=engine)
@app.get("/")
def home():
    return {"message": "Cloud Log Analyzer Backend Running"}


@app.get("/reports/")
def get_reports():
    db = SessionLocal()
    reports = db.query(LogReport).all()
    db.close()

    return [
        {
            "id": report.id,
            "summary": report.summary,
            "risk_level": report.risk_level,
            "severity_score": report.severity_score,
            "attack_type": report.attack_type
        }
        for report in reports
    ]


    return {"message": "Cloud Log Analyzer Backend Running"}
@app.post("/upload/")
async def upload_log(file: UploadFile = File(...)):
    content = await file.read()
    log_text = content.decode("utf-8")

    lines = log_text.split("\n")

    failed_attempts = 0
    suspicious_ips = {}

    for line in lines:
        if "failed" in line.lower():
            failed_attempts += 1

        ip_matches = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", line)
        for ip in ip_matches:
            suspicious_ips[ip] = suspicious_ips.get(ip, 0) + 1

    high_risk_ips = [ip for ip, count in suspicious_ips.items() if count > 3]

    # Severity scoring
    severity_score = failed_attempts * 5 + len(high_risk_ips) * 20

    if severity_score > 100:
        severity_score = 100

    if severity_score >= 70:
        risk_level = "CRITICAL"
    elif severity_score >= 40:
        risk_level = "HIGH"
    elif severity_score >= 15:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"
    # Attack classification
    if failed_attempts > 5:
        attack_type = "Brute Force Attack"
    elif len(high_risk_ips) > 0:
        attack_type = "Suspicious IP Activity"
    else:
        attack_type = "Normal Traffic"

    report = {
        "summary": "Log analysis completed successfully.",
        "metrics": {
            "total_failed_attempts": failed_attempts,
            "unique_ips_detected": len(suspicious_ips),
            "high_risk_ips": high_risk_ips
        },
        "risk_assessment": {

                    
            "risk_level": risk_level,
            "severity_score": severity_score,
            "attack_type": attack_type,
            "recommendation": "Immediate investigation required."
            if risk_level in ["HIGH", "CRITICAL"]
            else "System appears stable. Monitor regularly."
        

        }
    }
    db = SessionLocal()

    db_report = LogReport(
        summary=report["summary"],
        risk_level=risk_level,
        severity_score=severity_score,
        attack_type=attack_type,
        report_json=json.dumps(report)
    )

    db.add(db_report)
    db.commit()
    db.close()

    

    return report
