# Scorer Service - ML-based Risk Scoring
import json
import logging
import os
import time
import asyncio
import numpy as np
from datetime import datetime, timezone
from typing import Dict, Any, List
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
from rich.console import Console
from rich.logging import RichHandler

# Configure rich logging
console = Console()
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(console=console, rich_tracebacks=True)]
)
logger = logging.getLogger(__name__)

# FastAPI app
app = FastAPI(
    title="SecureOps360 Scorer Service",
    description="ML-based risk scoring for security events",
    version="1.0.0"
)

class ScoringRequest(BaseModel):
    event_id: str
    enrichments: Dict[str, Any]
    base_event: Dict[str, Any] = {}

class ScoringResponse(BaseModel):
    event_id: str
    model_score: float
    rule_score: int
    final_score: int
    confidence: float
    model_version: str
    triggered_rules: List[str]

class FeatureExtractor:
    """Extract numerical features from enriched events for ML scoring"""
    
    def __init__(self):
        self.feature_mappings = {
            'high_risk_countries': ['CN', 'RU', 'KP', 'IR', 'XX'],
            'suspicious_asns': [0, 13335, 54321],
            'critical_resources': ['database', 's3', 'rds']
        }
    
    def extract_features(self, event: Dict[str, Any], enrichments: Dict[str, Any]) -> Dict[str, float]:
        """Extract numerical features from event data"""
        try:
            features = {}
            
            # Geo features
            geo = enrichments.get('geo', {})
            features['asn'] = float(geo.get('asn', 0))
            features['is_high_risk_country'] = 1.0 if geo.get('country_code', '') in self.feature_mappings['high_risk_countries'] else 0.0
            
            # Threat intel features
            threat_intel = enrichments.get('threat_intel', {})
            features['rep_score'] = float(threat_intel.get('rep_score', 50)) / 100.0  # Normalize to 0-1
            features['is_malicious'] = 1.0 if threat_intel.get('ip_rep') == 'malicious' else 0.0
            features['is_suspicious'] = 1.0 if threat_intel.get('ip_rep') == 'suspicious' else 0.0
            
            # Asset features
            asset_context = enrichments.get('asset_context', {})
            features['asset_criticality'] = float(asset_context.get('criticality', 1)) / 5.0  # Normalize to 0-1
            features['is_prod_environment'] = 1.0 if asset_context.get('environment') == 'prod' else 0.0
            
            # Time features
            now = datetime.now(timezone.utc)
            features['hour_of_day'] = float(now.hour) / 24.0  # Normalize to 0-1
            features['day_of_week'] = float(now.weekday()) / 7.0  # Normalize to 0-1
            features['is_weekend'] = 1.0 if now.weekday() >= 5 else 0.0
            features['is_business_hours'] = 1.0 if 9 <= now.hour <= 17 else 0.0
            
            # Event type features
            action = event.get('action', '').lower()
            features['is_login_action'] = 1.0 if 'login' in action else 0.0
            features['is_failed_action'] = 1.0 if 'failed' in action or 'fail' in action else 0.0
            features['is_admin_action'] = 1.0 if 'admin' in action or 'root' in action else 0.0
            
            # Resource type features
            resource_type = event.get('resource', {}).get('type', '').lower()
            features['is_critical_resource'] = 1.0 if resource_type in self.feature_mappings['critical_resources'] else 0.0
            
            # Severity hint
            features['severity_hint'] = float(event.get('severity_hint', 1)) / 5.0  # Normalize to 0-1
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features: {str(e)}")
            return {}

class RuleEngine:
    """Rule-based scoring engine"""
    
    def __init__(self):
        self.rules = [
            {
                'name': 'high_risk_country_admin',
                'condition': lambda f: f.get('is_high_risk_country', 0) == 1 and f.get('is_admin_action', 0) == 1,
                'score': 40,
                'description': 'Admin action from high-risk country'
            },
            {
                'name': 'malicious_ip_access',
                'condition': lambda f: f.get('is_malicious', 0) == 1,
                'score': 50,
                'description': 'Access from malicious IP'
            },
            {
                'name': 'failed_login_suspicious_ip',
                'condition': lambda f: f.get('is_failed_action', 0) == 1 and f.get('is_suspicious', 0) == 1,
                'score': 30,
                'description': 'Failed login from suspicious IP'
            },
            {
                'name': 'critical_resource_access',
                'condition': lambda f: f.get('is_critical_resource', 0) == 1 and f.get('is_prod_environment', 0) == 1,
                'score': 20,
                'description': 'Access to critical production resource'
            },
            {
                'name': 'weekend_admin_activity',
                'condition': lambda f: f.get('is_weekend', 0) == 1 and f.get('is_admin_action', 0) == 1,
                'score': 15,
                'description': 'Admin activity during weekend'
            },
            {
                'name': 'high_severity_event',
                'condition': lambda f: f.get('severity_hint', 0) >= 0.8,  # >= 4 out of 5
                'score': 25,
                'description': 'High severity event'
            },
            {
                'name': 'off_hours_activity',
                'condition': lambda f: f.get('is_business_hours', 0) == 0 and f.get('is_critical_resource', 0) == 1,
                'score': 10,
                'description': 'Off-hours access to critical resource'
            }
        ]
    
    def calculate_rule_score(self, features: Dict[str, float]) -> Dict[str, Any]:
        """Calculate rule-based score"""
        try:
            total_score = 0
            triggered_rules = []
            
            for rule in self.rules:
                try:
                    if rule['condition'](features):
                        total_score += rule['score']
                        triggered_rules.append({
                            'name': rule['name'],
                            'score': rule['score'],
                            'description': rule['description']
                        })
                except Exception as e:
                    logger.warning(f"Error evaluating rule {rule['name']}: {str(e)}")
            
            # Cap at 100
            total_score = min(total_score, 100)
            
            return {
                'rule_score': total_score,
                'triggered_rules': triggered_rules,
                'total_rules_checked': len(self.rules)
            }
            
        except Exception as e:
            logger.error(f"Error calculating rule score: {str(e)}")
            return {
                'rule_score': 0,
                'triggered_rules': [],
                'total_rules_checked': len(self.rules)
            }

class MLModel:
    """Mock ML model for risk scoring"""
    
    def __init__(self):
        self.model_version = "1.0.0"
        self.feature_weights = {
            'is_malicious': 0.4,
            'rep_score': 0.3,
            'is_high_risk_country': 0.2,
            'asset_criticality': 0.25,
            'is_prod_environment': 0.15,
            'is_admin_action': 0.3,
            'is_failed_action': 0.2,
            'is_business_hours': -0.1,  # Negative weight (business hours = lower risk)
            'severity_hint': 0.2,
            'is_critical_resource': 0.3,
            'is_suspicious': 0.25
        }
    
    def predict(self, features: Dict[str, float]) -> Dict[str, Any]:
        """Predict risk score using mock model"""
        try:
            # Calculate weighted score
            raw_score = 0.0
            weights_used = 0
            
            for feature, weight in self.feature_weights.items():
                if feature in features:
                    raw_score += features[feature] * weight
                    weights_used += 1
            
            # Apply sigmoid function to get probability
            if weights_used > 0:
                raw_score = raw_score / max(weights_used * 0.1, 1.0)  # Normalize
                probability = 1 / (1 + np.exp(-raw_score))
            else:
                probability = 0.5  # Default if no features
            
            # Convert to 0-100 scale
            model_score = probability * 100
            
            # Calculate confidence based on feature completeness
            feature_completeness = len([f for f in features.values() if f != 0.0]) / len(features) if features else 0
            confidence = min(0.3 + feature_completeness * 0.7, 1.0)
            
            return {
                'model_score': float(model_score),
                'confidence': float(confidence),
                'model_version': self.model_version,
                'features_used': len(features),
                'raw_score': float(raw_score)
            }
            
        except Exception as e:
            logger.error(f"Error in model prediction: {str(e)}")
            return {
                'model_score': 50.0,
                'confidence': 0.1,
                'model_version': self.model_version,
                'features_used': 0,
                'error': str(e)
            }

class RiskScorer:
    """Main risk scoring service"""
    
    def __init__(self):
        self.feature_extractor = FeatureExtractor()
        self.rule_engine = RuleEngine()
        self.ml_model = MLModel()
        
    async def score_event(self, event: Dict[str, Any], enrichments: Dict[str, Any]) -> Dict[str, Any]:
        """Score a single event"""
        start_time = time.time()
        
        try:
            logger.info(f"Scoring event {event.get('event_id', 'unknown')}")
            
            # Extract features
            features = self.feature_extractor.extract_features(event, enrichments)
            logger.debug(f"Extracted {len(features)} features")
            
            # Calculate rule-based score
            rule_result = self.rule_engine.calculate_rule_score(features)
            
            # Calculate ML score
            ml_result = self.ml_model.predict(features)
            
            # Combine scores (weighted combination)
            model_score = ml_result.get('model_score', 50.0)
            rule_score = rule_result.get('rule_score', 0)
            
            # Final score: 70% model, 30% rules
            final_score = min(int((model_score * 0.7) + (rule_score * 0.3)), 100)
            
            processing_time = int((time.time() - start_time) * 1000)
            
            scoring_result = {
                'model_score': model_score,
                'rule_score': rule_score,
                'final_score': final_score,
                'confidence': ml_result.get('confidence', 0.5),
                'model_version': ml_result.get('model_version', 'unknown'),
                'triggered_rules': [rule['name'] for rule in rule_result.get('triggered_rules', [])],
                'features_extracted': len(features),
                'processing_time_ms': processing_time,
                'scored_at': datetime.now(timezone.utc).isoformat()
            }
            
            logger.info(f"Event scored: final_score={final_score}, model={model_score:.1f}, rules={rule_score}")
            return scoring_result
            
        except Exception as e:
            logger.error(f"Error scoring event: {str(e)}")
            return {
                'model_score': 50.0,
                'rule_score': 0,
                'final_score': 50,
                'confidence': 0.1,
                'error': str(e)
            }

# Initialize scorer
scorer = RiskScorer()

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "scorer",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model_version": scorer.ml_model.model_version,
        "environment": os.getenv("ENVIRONMENT", "local")
    }

@app.post("/score", response_model=ScoringResponse)
async def score_event_endpoint(request: ScoringRequest):
    """Score a security event"""
    try:
        # Score the event
        scoring_result = await scorer.score_event(request.base_event, request.enrichments)
        
        return ScoringResponse(
            event_id=request.event_id,
            model_score=scoring_result.get('model_score', 50.0),
            rule_score=scoring_result.get('rule_score', 0),
            final_score=scoring_result.get('final_score', 50),
            confidence=scoring_result.get('confidence', 0.5),
            model_version=scoring_result.get('model_version', '1.0.0'),
            triggered_rules=scoring_result.get('triggered_rules', [])
        )
        
    except Exception as e:
        logger.error(f"Error in score endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "SecureOps360 Scorer Service",
        "version": "1.0.0",
        "status": "running",
        "model_version": scorer.ml_model.model_version,
        "endpoints": {
            "health": "/health",
            "score": "/score"
        }
    }

if __name__ == "__main__":
    logger.info("🚀 Starting SecureOps360 Scorer Service")
    logger.info("Environment: Local Development")
    
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8081,
        reload=True,
        log_level="info"
    )
