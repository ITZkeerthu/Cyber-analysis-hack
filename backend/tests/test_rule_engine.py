import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.database import Base  # noqa: E402
from app.models import Evidence  # noqa: E402
from app.rule_engine import RuleEngine  # noqa: E402

BASE = datetime(2026, 1, 5, 12, 0, 0)  # noon: inside business hours


@pytest.fixture
def db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def add(db, **kw):
    kw.setdefault("case_id", "C1")
    db.add(Evidence(**kw))
    db.commit()


def test_no_evidence_scores_zero(db):
    result = RuleEngine(db).analyze("C1")
    assert result == {"rule_score": 0.0, "flagged_entities": [], "triggered_rules": []}


def test_failed_login_burst_detected(db):
    for i in range(5):
        add(db, user="alice", action="login_failed", timestamp=BASE + timedelta(seconds=10 * i))
    result = RuleEngine(db).analyze("C1")
    assert "failed_login_burst" in result["triggered_rules"]
    assert result["flagged_entities"][0]["value"] == "alice"


def test_failed_logins_spread_out_not_flagged(db):
    for i in range(5):
        add(db, user="alice", action="login_failed", timestamp=BASE + timedelta(minutes=10 * i))
    assert RuleEngine(db).analyze("C1")["triggered_rules"] == []


def test_suspicious_executable_detected(db):
    add(db, user="bob", action="exec", file_path="C:\\tools\\Mimikatz.exe", timestamp=BASE)
    result = RuleEngine(db).analyze("C1")
    assert "unknown_executable" in result["triggered_rules"]


def test_off_hours_login_detected_and_business_hours_ignored(db):
    add(db, user="carol", action="login", timestamp=BASE.replace(hour=3))
    add(db, user="dave", action="login", timestamp=BASE)
    result = RuleEngine(db).analyze("C1")
    assert "off_hours_access" in result["triggered_rules"]
    flagged = {e["value"] for e in result["flagged_entities"]}
    assert flagged == {"carol"}


def test_multi_ip_logins_detected(db):
    for i, ip in enumerate(["1.1.1.1", "2.2.2.2", "3.3.3.3"]):
        add(db, user="erin", action="login", ip_address=ip, timestamp=BASE + timedelta(minutes=i))
    assert "multi_ip_login" in RuleEngine(db).analyze("C1")["triggered_rules"]


def test_missing_ip_addresses_do_not_count_as_distinct_ips(db):
    add(db, user="erin", action="login", ip_address="1.1.1.1", timestamp=BASE)
    add(db, user="erin", action="login", ip_address=None, timestamp=BASE + timedelta(minutes=1))
    add(db, user="erin", action="login", ip_address="", timestamp=BASE + timedelta(minutes=2))
    assert "multi_ip_login" not in RuleEngine(db).analyze("C1")["triggered_rules"]


def test_rows_without_timestamp_do_not_crash(db):
    add(db, user="frank", action="login", timestamp=None)
    add(db, user="frank", action="login_failed", timestamp=None)
    add(db, user="frank", action="login_failed", timestamp=BASE)
    result = RuleEngine(db).analyze("C1")
    assert 0.0 <= result["rule_score"] <= 1.0


def test_other_cases_are_ignored(db):
    add(db, case_id="OTHER", user="x", action="exec", file_path="mimikatz", timestamp=BASE)
    assert RuleEngine(db).analyze("C1")["triggered_rules"] == []
