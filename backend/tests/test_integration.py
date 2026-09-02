"""
End-to-end integration test verifying backend and database connections.
"""

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_full_flow():
    # 1. Health check
    res = client.get("/")
    assert res.status_code == 200
    assert res.json()["status"] == "healthy"

    # 2. Get initial counts
    stats_res = client.get("/api/stats/summary")
    assert stats_res.status_code == 200
    initial_emails = stats_res.json()["emails_scanned"]
    initial_incidents = stats_res.json()["total_incidents"]

    # 3. Analyze an email
    sample_email = (
        b"From: \"Executive Payroll\" <payroll@spoofed-company.xyz>\r\n"
        b"To: accountant@internal.corp\r\n"
        b"Subject: URGENT: Update direct deposit credentials\r\n"
        b"Authentication-Results: spf=fail dkim=fail dmarc=fail\r\n"
        b"Received: from suspicious-vps.org (185.123.45.67) by mx.internal.corp\r\n"
        b"\r\n"
        b"Dear team,\r\n"
        b"Your account will be suspended unless you immediately confirm your password and click here to verify credentials."
    )

    res = client.post(
        "/api/analyze",
        files={"file": ("urgent_payroll.eml", sample_email, "message/rfc822")}
    )
    assert res.status_code == 200
    data = res.json()
    assert "risk_score" in data
    assert data["risk_score"] >= 30
    assert "incident_id" in data
    assert data["incident_id"] is not None

    new_inc_id = data["incident_id"]

    # 4. Verify incident appears in incident list
    inc_list_res = client.get("/api/incidents")
    assert inc_list_res.status_code == 200
    inc_items = inc_list_res.json()["items"]
    assert any(inc["numeric_id"] == new_inc_id for inc in inc_items)

    # 5. Verify incident detail endpoint
    inc_detail_res = client.get(f"/api/incidents/{new_inc_id}")
    assert inc_detail_res.status_code == 200
    detail = inc_detail_res.json()
    assert detail["numeric_id"] == new_inc_id
    assert "authStatus" in detail
    assert detail["authStatus"]["SPF"] == "fail"

    # 6. Test triage action: Escalate to Tier 2
    patch_res = client.patch(
        f"/api/incidents/{new_inc_id}",
        json={"status": "escalated", "assigned_to": "Tier 2 Lead"}
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["incident"]["status"] == "Escalated"

    # 7. Test triage action: Mark as False Positive
    patch_fp = client.patch(
        f"/api/incidents/{new_inc_id}",
        json={"status": "false_positive"}
    )
    assert patch_fp.status_code == 200
    assert patch_fp.json()["incident"]["status"] == "False Positive"

    # 8. Test stats and charts
    updated_stats = client.get("/api/stats/summary").json()
    assert updated_stats["emails_scanned"] == initial_emails + 1

    charts_res = client.get("/api/stats/charts")
    assert charts_res.status_code == 200
    charts = charts_res.json()
    assert "verdicts_over_time" in charts
    assert len(charts["verdicts_over_time"]) == 7
    assert "top_terms" in charts
    assert len(charts["top_terms"]) > 0

    # 9. Clean up test records so tests never pollute the live database
    from database import SessionLocal, Incident, AnalyzedEmail
    clean_db = SessionLocal()
    try:
        clean_db.query(Incident).filter(Incident.id == new_inc_id).delete()
        clean_db.query(AnalyzedEmail).filter(AnalyzedEmail.id == data.get("analyzed_email_id")).delete()
        clean_db.commit()
    finally:
        clean_db.close()

    print("All end-to-end integration tests passed and cleaned up successfully!")

if __name__ == "__main__":
    test_full_flow()
