#!/usr/bin/env python3
"""
SecureOps360 System Testing Script
Comprehensive end-to-end testing of the deployed platform
"""

import json
import requests
import time
import boto3
import asyncio
import logging
import argparse
from datetime import datetime, timezone
from typing import Dict, List, Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecureOps360Tester:
    def __init__(self, api_endpoint: str, aws_region: str = 'ap-south-1'):
        self.api_endpoint = api_endpoint.rstrip('/')
        self.aws_region = aws_region
        
        # AWS clients
        self.kinesis = boto3.client('kinesis', region_name=aws_region)
        self.dynamodb = boto3.client('dynamodb', region_name=aws_region)
        self.lambda_client = boto3.client('lambda', region_name=aws_region)
        self.cloudwatch = boto3.client('cloudwatch', region_name=aws_region)
        
        self.test_events = self._generate_test_events()
        self.test_results = []
    
    def _generate_test_events(self) -> List[Dict[str, Any]]:
        """Generate test events for various scenarios"""
        return [
            {
                "source": "cloudtrail",
                "actor": {"type": "user", "id": "test@example.com", "ip": "203.0.113.1"},
                "action": "LoginSuccess",
                "resource": {"type": "ec2", "id": "i-1234567890abcdef0"},
                "severity_hint": 1,
                "payload": {"userAgent": "Mozilla/5.0", "mfa": "true"}
            },
            {
                "source": "cloudtrail", 
                "actor": {"type": "user", "id": "admin@example.com", "ip": "198.51.100.1"},
                "action": "LoginFailed",
                "resource": {"type": "database", "id": "prod-db-cluster"},
                "severity_hint": 4,
                "payload": {"userAgent": "curl/7.68.0", "mfa": "false", "attempts": 5}
            },
            {
                "source": "waf",
                "actor": {"type": "ip", "id": "malicious.ip.1.1", "ip": "malicious.ip.1.1"}, 
                "action": "BlockedRequest",
                "resource": {"type": "api", "id": "/api/v1/admin"},
                "severity_hint": 3,
                "payload": {"rule": "SQL_INJECTION", "country": "XX"}
            }
        ]
    
    def test_api_health(self) -> Dict[str, Any]:
        """Test API health endpoint"""
        results = {'test_name': 'api_health', 'passed': 0, 'failed': 0, 'details': []}
        
        try:
            response = requests.get(f"{self.api_endpoint}/health", timeout=10)
            if response.status_code == 200:
                results['passed'] += 1
                results['details'].append("✅ API Health check passed")
                data = response.json()
                results['details'].append(f"   Service: {data.get('service')}")
                results['details'].append(f"   Status: {data.get('status')}")
            else:
                results['failed'] += 1
                results['details'].append(f"❌ API Health check failed ({response.status_code})")
                
        except Exception as e:
            results['failed'] += 1
            results['details'].append(f"❌ API Health check error: {str(e)}")
        
        return results
    
    def test_event_ingestion(self) -> Dict[str, Any]:
        """Test event ingestion"""
        results = {'test_name': 'event_ingestion', 'passed': 0, 'failed': 0, 'details': []}
        
        for i, event in enumerate(self.test_events):
            try:
                response = requests.post(
                    f"{self.api_endpoint}/ingest/events",
                    json=event,
                    timeout=10,
                    headers={'Content-Type': 'application/json'}
                )
                
                if response.status_code in [200, 207]:
                    results['passed'] += 1
                    results['details'].append(f"✅ Event {i+1} ingested successfully")
                else:
                    results['failed'] += 1
                    results['details'].append(f"❌ Event {i+1} failed ({response.status_code})")
                    
            except Exception as e:
                results['failed'] += 1
                results['details'].append(f"❌ Event {i+1} error: {str(e)}")
        
        return results
    
    def test_aws_resources(self) -> Dict[str, Any]:
        """Test AWS resources"""
        results = {'test_name': 'aws_resources', 'passed': 0, 'failed': 0, 'details': []}
        
        # Test Kinesis
        try:
            response = self.kinesis.describe_stream(StreamName='secureops360-dev-events')
            if response['StreamDescription']['StreamStatus'] == 'ACTIVE':
                results['passed'] += 1
                results['details'].append("✅ Kinesis stream is active")
            else:
                results['failed'] += 1
                results['details'].append(f"❌ Kinesis stream status: {response['StreamDescription']['StreamStatus']}")
        except Exception as e:
            results['failed'] += 1
            results['details'].append(f"❌ Kinesis error: {str(e)}")
        
        # Test DynamoDB tables
        tables = ['events_live', 'intel_cache', 'assets_ctx', 'model_metrics']
        for table in tables:
            try:
                response = self.dynamodb.describe_table(TableName=table)
                if response['Table']['TableStatus'] == 'ACTIVE':
                    results['passed'] += 1
                    results['details'].append(f"✅ DynamoDB table {table} is active")
                else:
                    results['failed'] += 1
                    results['details'].append(f"❌ DynamoDB table {table} status: {response['Table']['TableStatus']}")
            except Exception as e:
                results['failed'] += 1
                results['details'].append(f"❌ DynamoDB table {table} error: {str(e)}")
        
        return results
    
    def test_lambda_function(self) -> Dict[str, Any]:
        """Test Lambda function"""
        results = {'test_name': 'lambda_function', 'passed': 0, 'failed': 0, 'details': []}
        
        try:
            response = self.lambda_client.get_function(FunctionName='secureops360-dev-ingest')
            if response['Configuration']['State'] == 'Active':
                results['passed'] += 1
                results['details'].append("✅ Lambda function is active")
                results['details'].append(f"   Runtime: {response['Configuration']['Runtime']}")
                results['details'].append(f"   Memory: {response['Configuration']['MemorySize']}MB")
            else:
                results['failed'] += 1
                results['details'].append(f"❌ Lambda function state: {response['Configuration']['State']}")
                
        except Exception as e:
            results['failed'] += 1
            results['details'].append(f"❌ Lambda function error: {str(e)}")
        
        return results
    
    def run_all_tests(self) -> Dict[str, Any]:
        """Run all system tests"""
        logger.info("🚀 Starting SecureOps360 System Tests")
        
        test_functions = [
            self.test_api_health,
            self.test_event_ingestion,
            self.test_aws_resources,
            self.test_lambda_function
        ]
        
        all_results = []
        total_passed = 0
        total_failed = 0
        
        for test_func in test_functions:
            logger.info(f"Running {test_func.__name__}...")
            result = test_func()
            all_results.append(result)
            total_passed += result['passed']
            total_failed += result['failed']
            
            # Print immediate results
            print(f"\n📋 {result['test_name'].upper()}")
            for detail in result['details']:
                print(f"  {detail}")
        
        # Generate summary
        summary = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'total_tests_passed': total_passed,
            'total_tests_failed': total_failed,
            'success_rate': (total_passed / (total_passed + total_failed) * 100) if (total_passed + total_failed) > 0 else 0,
            'overall_status': 'PASSED' if total_failed == 0 else 'FAILED',
            'test_results': all_results
        }
        
        return summary

def main():
    parser = argparse.ArgumentParser(description='SecureOps360 System Tester')
    parser.add_argument('--api-endpoint', required=True, help='API Gateway endpoint URL')
    parser.add_argument('--region', default='ap-south-1', help='AWS region')
    parser.add_argument('--output', help='Output file for results')
    
    args = parser.parse_args()
    
    tester = SecureOps360Tester(args.api_endpoint, args.region)
    results = tester.run_all_tests()
    
    # Print final summary
    print(f"\n{'='*60}")
    print("🎯 SECUREOPS360 SYSTEM TEST RESULTS")
    print(f"{'='*60}")
    print(f"⏰ Timestamp: {results['timestamp']}")
    print(f"✅ Tests Passed: {results['total_tests_passed']}")
    print(f"❌ Tests Failed: {results['total_tests_failed']}")
    print(f"📊 Success Rate: {results['success_rate']:.1f}%")
    print(f"🎯 Overall Status: {results['overall_status']}")
    print(f"{'='*60}")
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"📁 Results saved to {args.output}")
    
    return results['overall_status'] == 'PASSED'

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
