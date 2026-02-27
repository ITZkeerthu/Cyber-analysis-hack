from datetime import datetime, timedelta
from typing import List, Dict, Any, Set, Tuple
from collections import defaultdict
from sqlalchemy.orm import Session
from .models import Evidence
from .config import RULE_THRESHOLDS

class RuleEngine:
    def __init__(self, db: Session):
        self.db = db
        self.thresholds = RULE_THRESHOLDS
    
    def analyze(self, case_id: str) -> Dict[str, Any]:
        """Run all forensic rules against evidence."""
        evidence = self.db.query(Evidence).filter(Evidence.case_id == case_id).all()
        
        if not evidence:
            return {
                "rule_score": 0.0,
                "flagged_entities": [],
                "triggered_rules": []
            }
        
        flagged_entities = []
        triggered_rules = []
        total_score = 0.0
        
        # Rule 1: Failed login detection
        failed_login_score, failed_login_entities = self._detect_failed_logins(evidence)
        if failed_login_score > 0:
            triggered_rules.append("failed_login_burst")
            flagged_entities.extend(failed_login_entities)
            total_score += failed_login_score
        
        # Rule 2: Unknown executable detection
        unknown_exec_score, unknown_exec_entities = self._detect_unknown_executables(evidence)
        if unknown_exec_score > 0:
            triggered_rules.append("unknown_executable")
            flagged_entities.extend(unknown_exec_entities)
            total_score += unknown_exec_score
        
        # Rule 3: Off-hours access
        offhours_score, offhours_entities = self._detect_offhours_access(evidence)
        if offhours_score > 0:
            triggered_rules.append("off_hours_access")
            flagged_entities.extend(offhours_entities)
            total_score += offhours_score
        
        # Rule 4: Multiple IP logins
        multi_ip_score, multi_ip_entities = self._detect_multi_ip_logins(evidence)
        if multi_ip_score > 0:
            triggered_rules.append("multi_ip_login")
            flagged_entities.extend(multi_ip_entities)
            total_score += multi_ip_score
        
        # Normalize score to 0-1 range
        max_possible_score = 4.0  # 4 rules max
        normalized_score = min(total_score / max_possible_score, 1.0)
        
        # Remove duplicate entities
        unique_entities = []
        seen = set()
        for entity in flagged_entities:
            key = (entity.get("type"), entity.get("value"))
            if key not in seen:
                seen.add(key)
                unique_entities.append(entity)
        
        return {
            "rule_score": round(normalized_score, 4),
            "flagged_entities": unique_entities,
            "triggered_rules": triggered_rules
        }
    
    def _detect_failed_logins(self, evidence: List[Evidence]) -> Tuple[float, List[Dict]]:
        """Detect >5 failed logins in 2 minutes."""
        failed_logins = defaultdict(list)
        
        for e in evidence:
            if e.action in ["login_failed", "failed_login", "auth_failed", "authentication_failed"]:
                failed_logins[e.user].append(e.timestamp)
        
        flagged = []
        max_score = 0.0
        
        for user, timestamps in failed_logins.items():
            timestamps.sort()
            
            window = timedelta(minutes=self.thresholds["failed_login_window_minutes"])
            threshold = self.thresholds["failed_login_count"]
            
            for i, ts in enumerate(timestamps):
                count = 1
                for j in range(i + 1, len(timestamps)):
                    if timestamps[j] - ts <= window:
                        count += 1
                    else:
                        break
                
                if count >= threshold:
                    severity = min(count / threshold, 3.0)  # Cap at 3x
                    max_score = max(max_score, severity)
                    flagged.append({
                        "type": "user",
                        "value": user,
                        "reason": f"{count} failed logins in {self.thresholds['failed_login_window_minutes']} minutes",
                        "severity": severity
                    })
                    break
        
        return min(max_score, 1.0), flagged
    
    def _detect_unknown_executables(self, evidence: List[Evidence]) -> Tuple[float, List[Dict]]:
        """Detect execution of unknown/suspicious binaries."""
        suspicious_patterns = [
            "mimikatz", "pwdump", "pass-the-hash", "nc.exe", "netcat",
            "mimikatz.exe", "cmd.exe", "powershell.exe -enc", "base64",
            "/tmp/.", "/var/tmp/.", "python -c", "perl -e", "bash -i"
        ]
        
        flagged = []
        max_score = 0.0
        
        for e in evidence:
            file_lower = e.file_path.lower() if e.file_path else ""
            action_lower = e.action.lower() if e.action else ""
            
            for pattern in suspicious_patterns:
                if pattern in file_lower or pattern in action_lower:
                    flagged.append({
                        "type": "file",
                        "value": e.file_path or e.action,
                        "reason": f"Suspicious pattern: {pattern}",
                        "severity": 1.0
                    })
                    max_score = 1.0
                    break
        
        return min(max_score, 1.0), flagged
    
    def _detect_offhours_access(self, evidence: List[Evidence]) -> Tuple[float, List[Dict]]:
        """Detect logins outside business hours (9am-6pm)."""
        flagged = []
        max_score = 0.0
        offhours_users = defaultdict(int)
        
        start_hour = self.thresholds["business_hours_start"]
        end_hour = self.thresholds["business_hours_end"]
        
        for e in evidence:
            if e.action in ["login", "logon", "signin", "authentication"]:
                hour = e.timestamp.hour
                if hour < start_hour or hour >= end_hour:
                    offhours_users[e.user] += 1
        
        for user, count in offhours_users.items():
            severity = min(count / 3, 1.0)  # 3+ off-hours = max severity
            max_score = max(max_score, severity)
            flagged.append({
                "type": "user",
                "value": user,
                "reason": f"{count} off-hours access events",
                "severity": severity
            })
        
        return min(max_score, 1.0), flagged
    
    def _detect_multi_ip_logins(self, evidence: List[Evidence]) -> Tuple[float, List[Dict]]:
        """Detect logins from multiple IPs in short duration."""
        user_ips = defaultdict(lambda: defaultdict(list))
        
        for e in evidence:
            if e.action in ["login", "logon", "signin"]:
                date_key = e.timestamp.date()
                user_ips[e.user][date_key].append(e.ip_address)
        
        flagged = []
        max_score = 0.0
        threshold = self.thresholds["multi_ip_threshold"]
        
        for user, day_ips in user_ips.items():
            for date, ips in day_ips.items():
                unique_ips = set(ips)
                if len(unique_ips) >= threshold:
                    severity = min(len(unique_ips) / threshold, 2.0)
                    max_score = max(max_score, min(severity, 1.0))
                    flagged.append({
                        "type": "user",
                        "value": user,
                        "reason": f"Logins from {len(unique_ips)} different IPs",
                        "severity": min(severity, 1.0)
                    })
        
        return min(max_score, 1.0), flagged