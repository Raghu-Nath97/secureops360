import json
import logging
import os
import time
import uuid
import boto3
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(logging.INFO)

kinesis_client = boto3.client('kinesis')

def validate_event_schema(event_data):
    """Basic event validation"""
    required_fields = ['source', 'actor', 'action', 'resource']
    
    for field in required_fields:
        if field not in event_data:
            return False, f"Missing required field: {field}"
    
    return True, None

def normalize_event(raw_event, source_ip):
    """Normalize event to standard format"""
    event_id = raw_event.get('event_id', str(uuid.uuid4()))
    
    actor = raw_event.get('actor', {})
    if 'ip' not in actor and source_ip:
        actor['ip'] = source_ip
    
    normalized = {
        'event_id': event_id,
        'source': raw_event.get('source'),
        'received_at': datetime.now(timezone.utc).isoformat(),
        'actor': actor,
        'action': raw_event.get('action'),
        'resource': raw_event.get('resource'),
        'severity_hint': raw_event.get('severity_hint', 1),
        'payload': raw_event.get('payload', {}),
        'schema_ver': '1.0'
    }
    
    return normalized

def send_to_kinesis(event):
    """Send event to Kinesis stream"""
    try:
        stream_name = os.environ.get('KINESIS_STREAM_NAME')
        if not stream_name:
            raise ValueError("KINESIS_STREAM_NAME environment variable not set")
        
        partition_key = f"{event.get('actor', {}).get('id', 'unknown')}#{event.get('source', 'unknown')}"
        
        response = kinesis_client.put_record(
            StreamName=stream_name,
            Data=json.dumps(event),
            PartitionKey=partition_key
        )
        
        logger.info(f"Event sent to Kinesis: {event.get('event_id')}")
        return True
        
    except Exception as e:
        logger.error(f"Error sending to Kinesis: {str(e)}")
        return False

def lambda_handler(event, context):
    """Main Lambda handler"""
    logger.info(f"Received event: {json.dumps(event, default=str)}")
    
    try:
        http_method = event.get('httpMethod', 'GET')
        
        if http_method == 'GET':
            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*'
                },
                'body': json.dumps({
                    'status': 'healthy',
                    'service': 'secureops360-ingest',
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'version': '1.0.0'
                })
            }
        
        if http_method != 'POST':
            return {
                'statusCode': 405,
                'headers': {'Content-Type': 'application/json'},
                'body': json.dumps({'error': 'Method not allowed'})
            }
        
        # Get source IP
        source_ip = event.get('requestContext', {}).get('identity', {}).get('sourceIp')
        
        # Parse request body
        body = event.get('body', '{}')
        if isinstance(body, str):
            try:
                body = json.loads(body)
            except json.JSONDecodeError:
                return {
                    'statusCode': 400,
                    'headers': {'Content-Type': 'application/json'},
                    'body': json.dumps({'error': 'Invalid JSON format'})
                }
        
        # Handle single event or batch
        events_to_process = [body] if isinstance(body, dict) else body
        
        processed_events = []
        errors = []
        
        for i, raw_event in enumerate(events_to_process):
            try:
                is_valid, error_msg = validate_event_schema(raw_event)
                if not is_valid:
                    errors.append({
                        'index': i,
                        'error': error_msg,
                        'event_id': raw_event.get('event_id', 'unknown')
                    })
                    continue
                
                normalized_event = normalize_event(raw_event, source_ip)
                
                success = send_to_kinesis(normalized_event)
                
                if success:
                    processed_events.append({
                        'event_id': normalized_event['event_id'],
                        'status': 'accepted'
                    })
                else:
                    errors.append({
                        'index': i,
                        'error': 'Failed to send to stream',
                        'event_id': normalized_event['event_id']
                    })
                    
            except Exception as e:
                errors.append({
                    'index': i,
                    'error': str(e),
                    'event_id': raw_event.get('event_id', 'unknown')
                })
        
        response_body = {
            'processed': len(processed_events),
            'errors': len(errors),
            'events': processed_events
        }
        
        if errors:
            response_body['errors_detail'] = errors
        
        status_code = 200 if not errors else 207
        
        return {
            'statusCode': status_code,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps(response_body)
        }
        
    except Exception as e:
        logger.error(f"Unhandled error: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({'error': 'Internal server error'})
        }
