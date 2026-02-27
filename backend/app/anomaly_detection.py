import numpy as np
from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple
from collections import defaultdict
from sqlalchemy.orm import Session
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from .models import Evidence

class AnomalyDetector:
    def __init__(self, db: Session):
        self.db = db
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42
        )
        self.scaler = StandardScaler()
    
    def analyze(self, case_id: str) -> Dict[str, Any]:
        """Run anomaly detection on user behavior."""
        evidence = self.db.query(Evidence).filter(Evidence.case_id == case_id).all()
        
        if not evidence:
            return {
                "anomaly_scores": {},
                "overall_anomaly_score": 0.0,
                "flagged_users": []
            }
        
        # Extract user behavior features
        user_features = self._extract_user_features(evidence)
        
        if len(user_features) < 2:
            return {
                "anomaly_scores": {user: 0.0 for user in user_features.keys()},
                "overall_anomaly_score": 0.0,
                "flagged_users": []
            }
        
        # Calculate anomaly scores
        anomaly_scores = self._calculate_anomaly_scores(user_features)
        
        # Flag users with high anomaly scores
        flagged_users = [
            user for user, score in anomaly_scores.items()
            if score > 0.6
        ]
        
        # Overall anomaly is the max score
        overall_score = max(anomaly_scores.values()) if anomaly_scores else 0.0
        
        return {
            "anomaly_scores": anomaly_scores,
            "overall_anomaly_score": round(overall_score, 4),
            "flagged_users": flagged_users,
            "user_features": {
                user: {
                    "login_frequency": features[0],
                    "access_frequency": features[1],
                    "unique_ip_count": features[2],
                    "time_deviation": features[3]
                }
                for user, features in user_features.items()
            }
        }
    
    def _extract_user_features(self, evidence: List[Evidence]) -> Dict[str, List[float]]:
        """Extract behavioral features per user."""
        user_data = defaultdict(lambda: {
            "timestamps": [],
            "actions": [],
            "ips": set(),
            "files": []
        })
        
        for e in evidence:
            user_data[e.user]["timestamps"].append(e.timestamp)
            user_data[e.user]["actions"].append(e.action)
            user_data[e.user]["ips"].add(e.ip_address)
            if e.file_path:
                user_data[e.user]["files"].append(e.file_path)
        
        features = {}
        
        # Calculate global average hour for time deviation
        all_hours = []
        for data in user_data.values():
            for ts in data["timestamps"]:
                all_hours.append(ts.hour + ts.minute / 60)
        global_avg_hour = np.mean(all_hours) if all_hours else 12.0
        
        for user, data in user_data.items():
            timestamps = sorted(data["timestamps"])
            
            if not timestamps:
                continue
            
            # Feature 1: Login frequency (events per hour)
            time_span = (timestamps[-1] - timestamps[0]).total_seconds() / 3600
            time_span = max(time_span, 0.5)  # At least 30 minutes
            login_freq = len(timestamps) / time_span
            
            # Feature 2: Access frequency (file access events per hour)
            access_actions = [a for a in data["actions"] if a in ["access", "read", "open", "write"]]
            access_freq = len(access_actions) / time_span
            
            # Feature 3: Unique IP count (normalized)
            unique_ips = len(data["ips"])
            
            # Feature 4: Time deviation (std dev from business hours)
            user_hours = [ts.hour + ts.minute / 60 for ts in timestamps]
            time_dev = np.std(user_hours) if len(user_hours) > 1 else 0.0
            time_dev_from_global = abs(np.mean(user_hours) - global_avg_hour) if user_hours else 0.0
            
            features[user] = [
                min(login_freq, 100.0),  # Cap at 100
                min(access_freq, 100.0),
                unique_ips,
                min(time_dev + time_dev_from_global, 12.0)  # Cap at 12 hours
            ]
        
        return features
    
    def _calculate_anomaly_scores(self, user_features: Dict[str, List[float]]) -> Dict[str, float]:
        """Calculate anomaly scores using Isolation Forest."""
        users = list(user_features.keys())
        feature_matrix = np.array([user_features[u] for u in users])
        
        # Normalize features
        scaled_features = self.scaler.fit_transform(feature_matrix)
        
        # Fit and predict
        self.model.fit(scaled_features)
        
        # Get anomaly scores (-1 to 1, where -1 is more anomalous)
        raw_scores = self.model.decision_function(scaled_features)
        
        # Convert to 0-1 scale where 1 is most anomalous
        # decision_function returns negative for outliers
        normalized_scores = {}
        for i, user in enumerate(users):
            # Higher score = more anomalous
            # decision_function: negative = outlier, positive = inlier
            score = -raw_scores[i]  # Flip so outliers have higher scores
            # Normalize to 0-1
            normalized_scores[user] = min(max((score + 0.5) / 1.0, 0.0), 1.0)
        
        return normalized_scores