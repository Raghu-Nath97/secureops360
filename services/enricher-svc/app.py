# Enricher Service - Threat Intelligence and Context Enrichment
import json
import logging
import os
import time
import asyncio
from datetime import datetime, timezone
from typing import Dict, Any, Optional
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
    title="SecureOps360 Enricher Service",
    description="Event enrichment with threat intelligence and asset context",
    version="1.0.0"
)

class EventRequest(BaseModel):
    event_id: str
    source: str
    actor: Dict[str, Any]
    action: str
    resource: Dict[str, Any]
    severity_hint: int = 1
    payload: Dict[str, Any] = {}

class EventResponse(BaseModel):
    event_id: str
    status: str
    enriched_data: Dict[str, Any]
    processing_time_ms: int

class ThreatIntelligenceService:
    """Mock threat intelligence service for local development"""
    
    async def lookup_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """Look up IP reputation (mock implementation)"""
        try:
            # Simulate processing time
            await asyncio.sleep(0.1)
            
            # Mock logic based on IP patterns
            if ip_address.startswith('10.') or ip_address.startswith('192.168.'):
                reputation = 'clean'
                reputation_score = 10
            elif '127.' in ip_address or '0.0.0.0' in ip_address:
                reputation = 'suspicious'
                reputation_score = 60
            else:
                # Simple hash-based scoring for consistency
                score_hash = sum(ord(c) for c in ip_address) % 100
                if score_hash < 15:
                    reputation = 'malicious'
                    reputation_score = 90
                elif score_hash < 40:
                    reputation = 'suspicious'
                    reputation_score = 60
                else:
                    reputation = 'clean'
                    reputation_score = 15
            
            return {
                'ip_rep': reputation,
                'rep_score': reputation_score,
                'feeds': ['mock_threat_feed'],
                'last_updated': datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error looking up IP reputation for {ip_address}: {str(e)}")
            return {
                'ip_rep': 'unknown',
                'rep_score': 50,
                'feeds': [],
                'error': str(e)
            }

class GeoLocationService:
    """Mock geo-location service for local development"""
    
    async def lookup_ip_location(self, ip_address: str) -> Dict[str, Any]:
        """Get geographical location for IP (mock implementation)"""
        try:
            await asyncio.sleep(0.05)  # Simulate API call
            
            if ip_address.startswith('10.') or ip_address.startswith('192.168.'):
                return {
                    'country': 'US',
                    'country_code': 'US',
                    'region': 'CA',
                    'city': 'San Francisco',
                    'latitude': 37.7749,
                    'longitude': -122.4194,
                    'asn': 13335,
                    'org': 'Private Network'
                }
            else:
                # Mock data based on IP hash
                countries = [
                    {'country': 'United States', 'code': 'US', 'asn': 13335},
                    {'country': 'India', 'code': 'IN', 'asn': 13238},
                    {'country': 'United Kingdom', 'code': 'GB', 'asn': 12345},
                    {'country': 'Germany', 'code': 'DE', 'asn': 54321}
                ]
                selected = countries[hash(ip_address) % len(countries)]
                return {
                    'country': selected['country'],
                    'country_code': selected['code'],
                    'asn': selected['asn'],
                    'org': f'ISP-{selected["code"]}'
                }
                
        except Exception as e:
            logger.error(f"Error looking up geo location for {ip_address}: {str(e)}")
            return {
                'country': 'unknown',
                'country_code': 'XX',
                'asn': 0,
                'org': 'unknown'
            }

class AssetContextService:
    """Mock asset context service for local development"""
    
    async def get_asset_context(self, asset_id: str, asset_type: str) -> Dict[str, Any]:
        """Get asset context (mock implementation)"""
        try:
            await asyncio.sleep(0.02)
            
            # Mock context based on asset type
            context = {
                'asset_id': asset_id,
                'asset_type': asset_type,
                'environment': 'dev' if 'dev' in asset_id or 'test' in asset_id else 'prod',
                'criticality': 3 if asset_type in ['database', 's3'] else 1,
                'owner': 'security-team',
                'tags': {
                    'project': 'secureops360',
                    'managed_by': 'terraform'
                }
            }
            
            return context
            
        except Exception as e:
            logger.error(f"Error getting asset context for {asset_id}: {str(e)}")
            return {
                'asset_id': asset_id,
                'asset_type': asset_type,
                'environment': 'unknown',
                'criticality': 1,
                'owner': 'unknown',
                'tags': {}
            }

class EventEnricher:
    """Main event enrichment service"""
    
    def __init__(self):
        self.threat_intel_service = ThreatIntelligenceService()
        self.geo_service = GeoLocationService()
        self.asset_service = AssetContextService()
        
    async def enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich a single event with threat intelligence and context"""
        start_time = time.time()
        
        try:
            enriched_event = event.copy()
            enrichments = {}
            
            # Extract actor IP if available
            actor_ip = event.get('actor', {}).get('ip')
            if actor_ip:
                logger.info(f"Enriching event {event.get('event_id')} for IP: {actor_ip}")
                
                # Get threat intelligence
                threat_intel = await self.threat_intel_service.lookup_ip_reputation(actor_ip)
                enrichments['threat_intel'] = threat_intel
                
                # Get geo location
                geo_data = await self.geo_service.lookup_ip_location(actor_ip)
                enrichments['geo'] = geo_data
            
            # Get asset context
            resource_id = event.get('resource', {}).get('id')
            resource_type = event.get('resource', {}).get('type')
            
            if resource_id and resource_type:
                asset_context = await self.asset_service.get_asset_context(resource_id, resource_type)
                enrichments['asset_context'] = asset_context
            
            # Add enrichment metadata
            processing_time = int((time.time() - start_time) * 1000)
            enrichments['enrichment_metadata'] = {
                'enriched_at': datetime.now(timezone.utc).isoformat(),
                'enricher_version': '1.0.0',
                'processing_time_ms': processing_time,
                'enrichments_added': len(enrichments)
            }
            
            # Update event with enrichments
            enriched_event['enrichments'] = enrichments
            enriched_event['status'] = 'enriched'
            
            logger.info(f"Successfully enriched event {event.get('event_id')} in {processing_time}ms")
            return enriched_event
            
        except Exception as e:
            logger.error(f"Error enriching event {event.get('event_id')}: {str(e)}")
            # Return original event with error info
            event['enrichment_error'] = str(e)
            return event

# Initialize enricher
enricher = EventEnricher()

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "enricher",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "environment": os.getenv("ENVIRONMENT", "local")
    }

@app.post("/enrich", response_model=EventResponse)
async def enrich_event_endpoint(event_request: EventRequest):
    """Enrich a security event with threat intelligence and context"""
    try:
        start_time = time.time()
        
        # Convert to dict for processing
        event_dict = event_request.dict()
        
        # Enrich the event
        enriched_event = await enricher.enrich_event(event_dict)
        
        processing_time = int((time.time() - start_time) * 1000)
        
        return EventResponse(
            event_id=event_request.event_id,
            status="enriched",
            enriched_data=enriched_event.get('enrichments', {}),
            processing_time_ms=processing_time
        )
        
    except Exception as e:
        logger.error(f"Error in enrich endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "SecureOps360 Enricher Service",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "health": "/health",
            "enrich": "/enrich"
        }
    }

if __name__ == "__main__":
    logger.info("🚀 Starting SecureOps360 Enricher Service")
    logger.info("Environment: Local Development")
    
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8080,
        reload=True,
        log_level="info"
    )
