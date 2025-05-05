#!/usr/bin/env python3
"""
SIEM Integration Module for the Threat Models and MITRE ATT&CK Mapping Tool.

This module provides integration with Security Information and Event Management (SIEM)
systems, allowing for bidirectional data flow between the threat mapping tool
and supported SIEM platforms.

Supported SIEM Platforms:
- Splunk
- Elastic SIEM
- IBM QRadar
"""

import os
import sys
import time
import json
import logging
import requests
import yaml
import pandas as pd
from datetime import datetime, timedelta
import urllib3
from concurrent.futures import ThreadPoolExecutor
from requests.auth import HTTPBasicAuth

# Add the project root to the path so we can import project modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Disable insecure request warnings when verify_ssl is False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SIEMIntegrationBase:
    """Base class for SIEM integrations."""
    
    def __init__(self, config):
        """
        Initialize the SIEM integration base class.
        
        Args:
            config (dict): Configuration dictionary containing SIEM settings
        """
        self.config = config
        self.enabled = config.get('enabled', False)
        self.base_url = config.get('base_url', '')
        self.api_endpoint = config.get('api_endpoint', '')
        self.verify_ssl = config.get('verify_ssl', True)
        self.timeout = config.get('timeout', 30)
        
        if not self.enabled:
            logger.info(f"{self.__class__.__name__} integration is disabled in configuration")
        
        if self.enabled and not self.base_url:
            logger.error(f"Base URL not configured for {self.__class__.__name__}")
            self.enabled = False
    
    def is_available(self):
        """
        Check if the SIEM system is available.
        
        Returns:
            bool: True if available, False otherwise
        """
        if not self.enabled:
            return False
            
        try:
            response = requests.get(
                f"{self.base_url}/api/status",
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Error checking {self.__class__.__name__} availability: {str(e)}")
            return False
    
    def execute_query(self, query, **kwargs):
        """
        Execute a query against the SIEM system.
        
        Args:
            query (str): Query string in the SIEM's query language
            **kwargs: Additional parameters for the query
            
        Returns:
            dict: Query results or None if error
        """
        raise NotImplementedError("Subclasses must implement execute_query")
    
    def get_recent_alerts(self, hours=24, severity=None):
        """
        Get recent alerts from the SIEM system.
        
        Args:
            hours (int): Number of hours to look back
            severity (str, optional): Filter by severity (e.g., "high", "critical")
            
        Returns:
            list: List of alert dictionaries
        """
        raise NotImplementedError("Subclasses must implement get_recent_alerts")
        
    def get_host_data(self, hostname):
        """
        Get data about a specific host from the SIEM.
        
        Args:
            hostname (str): Hostname to look up
            
        Returns:
            dict: Host data or None if not found
        """
        raise NotImplementedError("Subclasses must implement get_host_data")
    
    def push_threat_data(self, threat_data):
        """
        Push threat intelligence data to the SIEM system.
        
        Args:
            threat_data (list): List of threat dictionaries to push
            
        Returns:
            bool: True if successful, False otherwise
        """
        raise NotImplementedError("Subclasses must implement push_threat_data")


class SplunkIntegration(SIEMIntegrationBase):
    """Integration with Splunk SIEM."""
    
    def __init__(self, config):
        """
        Initialize the Splunk integration.
        
        Args:
            config (dict): Configuration dictionary containing Splunk settings
        """
        super().__init__(config)
        self.username = config.get('username', '')
        self.password = config.get('password', '')
        self.app = config.get('app', 'search')
        self.owner = config.get('owner', 'admin')
        
        if self.enabled and (not self.username or not self.password):
            logger.error("Splunk username or password not configured")
            self.enabled = False
    
    def is_available(self):
        """
        Check if Splunk is available.
        
        Returns:
            bool: True if available, False otherwise
        """
        if not self.enabled:
            return False
            
        try:
            headers = {}
            auth = HTTPBasicAuth(self.username, self.password)
            
            response = requests.get(
                f"{self.base_url}/services/server/info",
                headers=headers,
                auth=auth,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Error checking Splunk availability: {str(e)}")
            return False
    
    def execute_query(self, query, earliest_time="-24h", latest_time="now", 
                     max_count=1000, output_mode="json"):
        """
        Execute a Splunk search query.
        
        Args:
            query (str): Splunk search query
            earliest_time (str): Earliest time for the search window
            latest_time (str): Latest time for the search window
            max_count (int): Maximum number of results to return
            output_mode (str): Output format (json, xml, csv)
            
        Returns:
            dict: Search results or None if error
        """
        if not self.enabled:
            logger.warning("Splunk integration is disabled")
            return None
            
        try:
            # Start the search job
            search_url = f"{self.base_url}/services/search/jobs"
            auth = HTTPBasicAuth(self.username, self.password)
            
            # Create the search job
            job_data = {
                'search': query,
                'earliest_time': earliest_time,
                'latest_time': latest_time,
                'output_mode': output_mode,
                'exec_mode': 'normal'
            }
            
            response = requests.post(
                search_url,
                auth=auth,
                data=job_data,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if response.status_code != 201:
                logger.error(f"Failed to create Splunk search job: {response.text}")
                return None
                
            # Get the search job ID
            job_id = response.json()['sid']
            logger.info(f"Created Splunk search job with ID: {job_id}")
            
            # Poll for job completion
            is_done = False
            job_status_url = f"{search_url}/{job_id}"
            
            while not is_done:
                time.sleep(1)  # Wait before checking status
                status_response = requests.get(
                    job_status_url,
                    auth=auth,
                    params={'output_mode': 'json'},
                    verify=self.verify_ssl,
                    timeout=self.timeout
                )
                
                status = status_response.json()
                is_done = status.get('entry', [{}])[0].get('content', {}).get('isDone', False)
                
            # Get the results
            results_url = f"{job_status_url}/results"
            results_response = requests.get(
                results_url,
                auth=auth,
                params={
                    'output_mode': output_mode,
                    'count': max_count
                },
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if results_response.status_code != 200:
                logger.error(f"Failed to get Splunk search results: {results_response.text}")
                return None
                
            return results_response.json()
            
        except Exception as e:
            logger.error(f"Error executing Splunk query: {str(e)}")
            return None
    
    def get_recent_alerts(self, hours=24, severity=None):
        """
        Get recent alerts from Splunk.
        
        Args:
            hours (int): Number of hours to look back
            severity (str, optional): Filter by severity (e.g., "high", "critical")
            
        Returns:
            list: List of alert dictionaries
        """
        # Construct query based on parameters
        query = f'search index=* sourcetype="alert" | sort -_time'
        
        if severity:
            query += f' | search severity="{severity}"'
            
        earliest_time = f"-{hours}h"
        
        # Execute the query
        results = self.execute_query(query, earliest_time=earliest_time)
        
        if not results:
            return []
            
        # Process and normalize the results
        alerts = []
        for result in results.get('results', []):
            alert = {
                'id': result.get('_serial', ''),
                'timestamp': result.get('_time', ''),
                'event_type': result.get('alert_type', 'unknown'),
                'severity': result.get('severity', 'unknown'),
                'source': 'splunk',
                'source_ip': result.get('src_ip', ''),
                'destination_ip': result.get('dest_ip', ''),
                'message': result.get('message', ''),
                'raw_data': result
            }
            alerts.append(alert)
            
        return alerts
    
    def get_host_data(self, hostname):
        """
        Get data about a specific host from Splunk.
        
        Args:
            hostname (str): Hostname to look up
            
        Returns:
            dict: Host data or None if not found
        """
        query = f'search index=* host="{hostname}" | stats count by sourcetype | sort -count'
        
        results = self.execute_query(query, earliest_time="-7d")
        
        if not results or not results.get('results'):
            return None
            
        # Get additional host details
        asset_query = f'search index=* host="{hostname}" | stats values(os) as os values(ip) as ip_addresses first(_time) as first_seen last(_time) as last_seen by host'
        asset_results = self.execute_query(asset_query, earliest_time="-30d")
        
        if asset_results and asset_results.get('results'):
            asset_data = asset_results['results'][0]
        else:
            asset_data = {}
            
        # Compile host data
        host_data = {
            'hostname': hostname,
            'first_seen': asset_data.get('first_seen', ''),
            'last_seen': asset_data.get('last_seen', ''),
            'os': asset_data.get('os', ''),
            'ip_addresses': asset_data.get('ip_addresses', ''),
            'event_count': sum(int(r.get('count', 0)) for r in results.get('results', [])),
            'sourcetypes': [r.get('sourcetype') for r in results.get('results', [])],
            'data_sources': [r.get('sourcetype') for r in results.get('results', [])]
        }
        
        return host_data
    
    def push_threat_data(self, threat_data):
        """
        Push threat intelligence data to Splunk via HEC (HTTP Event Collector).
        
        Args:
            threat_data (list): List of threat dictionaries to push
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.enabled:
            logger.warning("Splunk integration is disabled")
            return False
            
        try:
            # In a real implementation, you would use Splunk's HTTP Event Collector (HEC)
            # This would require an HEC token configured in Splunk
            hec_token = self.config.get('hec_token', '')
            hec_url = f"{self.base_url}/services/collector"
            
            if not hec_token:
                logger.error("Splunk HEC token not configured")
                return False
            
            # Prepare events for Splunk HEC
            headers = {
                'Authorization': f'Splunk {hec_token}',
                'Content-Type': 'application/json'
            }
            
            success = True
            for threat in threat_data:
                event = {
                    'time': int(time.time()),
                    'host': 'threat-intel-tool',
                    'source': 'mitre_attack_mapping',
                    'sourcetype': 'threat_intel',
                    'index': 'threat_intelligence',
                    'event': threat
                }
                
                response = requests.post(
                    hec_url,
                    headers=headers,
                    data=json.dumps(event),
                    verify=self.verify_ssl,
                    timeout=self.timeout
                )
                
                if response.status_code != 200:
                    logger.error(f"Failed to push event to Splunk HEC: {response.text}")
                    success = False
            
            return success
            
        except Exception as e:
            logger.error(f"Error pushing threat data to Splunk: {str(e)}")
            return False


class ElasticSIEMIntegration(SIEMIntegrationBase):
    """Integration with Elastic SIEM."""
    
    def __init__(self, config):
        """
        Initialize the Elastic SIEM integration.
        
        Args:
            config (dict): Configuration dictionary containing Elastic settings
        """
        super().__init__(config)
        self.username = config.get('username', '')
        self.password = config.get('password', '')
        self.index_pattern = config.get('index_pattern', 'threat-*')
        
        if self.enabled and (not self.username or not self.password):
            logger.error("Elastic SIEM username or password not configured")
            self.enabled = False
    
    def is_available(self):
        """
        Check if Elastic SIEM is available.
        
        Returns:
            bool: True if available, False otherwise
        """
        if not self.enabled:
            return False
            
        try:
            auth = HTTPBasicAuth(self.username, self.password)
            
            response = requests.get(
                f"{self.base_url}/_cluster/health",
                auth=auth,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Error checking Elastic SIEM availability: {str(e)}")
            return False
    
    def execute_query(self, query, index=None, size=1000):
        """
        Execute an Elasticsearch query.
        
        Args:
            query (dict): Elasticsearch query DSL
            index (str, optional): Index to query (defaults to configured index_pattern)
            size (int): Maximum number of results to return
            
        Returns:
            dict: Query results or None if error
        """
        if not self.enabled:
            logger.warning("Elastic SIEM integration is disabled")
            return None
            
        try:
            auth = HTTPBasicAuth(self.username, self.password)
            
            if index is None:
                index = self.index_pattern
                
            # Add size to the query if it doesn't contain it
            if isinstance(query, dict) and 'size' not in query:
                query['size'] = size
                
            headers = {'Content-Type': 'application/json'}
            
            response = requests.post(
                f"{self.base_url}/{index}/_search",
                auth=auth,
                headers=headers,
                json=query,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to execute Elasticsearch query: {response.text}")
                return None
                
            return response.json()
            
        except Exception as e:
            logger.error(f"Error executing Elasticsearch query: {str(e)}")
            return None
    
    def get_recent_alerts(self, hours=24, severity=None):
        """
        Get recent alerts from Elastic SIEM.
        
        Args:
            hours (int): Number of hours to look back
            severity (str, optional): Filter by severity (e.g., "high", "critical")
            
        Returns:
            list: List of alert dictionaries
        """
        # Construct Elasticsearch query based on parameters
        time_range = {
            "range": {
                "@timestamp": {
                    "gte": f"now-{hours}h",
                    "lte": "now"
                }
            }
        }
        
        must = [time_range]
        
        if severity:
            must.append({
                "match": {
                    "event.severity": severity
                }
            })
            
        query = {
            "query": {
                "bool": {
                    "must": must
                }
            },
            "sort": [
                {"@timestamp": {"order": "desc"}}
            ],
            "size": 1000
        }
        
        # Execute the query
        results = self.execute_query(query, index="alerts-*")
        
        if not results:
            return []
            
        # Process and normalize the results
        alerts = []
        for hit in results.get('hits', {}).get('hits', []):
            source = hit.get('_source', {})
            alert = {
                'id': hit.get('_id', ''),
                'timestamp': source.get('@timestamp', ''),
                'event_type': source.get('event.type', 'unknown'),
                'severity': source.get('event.severity', 'unknown'),
                'source': 'elastic',
                'source_ip': source.get('source.ip', ''),
                'destination_ip': source.get('destination.ip', ''),
                'message': source.get('message', ''),
                'raw_data': source
            }
            alerts.append(alert)
            
        return alerts
    
    def get_host_data(self, hostname):
        """
        Get data about a specific host from Elastic SIEM.
        
        Args:
            hostname (str): Hostname to look up
            
        Returns:
            dict: Host data or None if not found
        """
        query = {
            "query": {
                "match": {
                    "host.name": hostname
                }
            },
            "aggs": {
                "data_sources": {
                    "terms": {
                        "field": "event.dataset",
                        "size": 20
                    }
                },
                "first_seen": {
                    "min": {
                        "field": "@timestamp"
                    }
                },
                "last_seen": {
                    "max": {
                        "field": "@timestamp"
                    }
                }
            },
            "size": 1
        }
        
        results = self.execute_query(query)
        
        if not results or results.get('hits', {}).get('total', {}).get('value', 0) == 0:
            return None
            
        # Extract aggregation results
        aggs = results.get('aggregations', {})
        data_sources = [bucket.get('key') for bucket in aggs.get('data_sources', {}).get('buckets', [])]
        first_seen = aggs.get('first_seen', {}).get('value_as_string', '')
        last_seen = aggs.get('last_seen', {}).get('value_as_string', '')
        
        # Get the most recent document for this host
        latest_doc = results.get('hits', {}).get('hits', [{}])[0].get('_source', {})
        
        # Compile host data
        host_data = {
            'hostname': hostname,
            'first_seen': first_seen,
            'last_seen': last_seen,
            'os': latest_doc.get('host', {}).get('os', {}).get('name', ''),
            'ip_addresses': latest_doc.get('host', {}).get('ip', ''),
            'event_count': results.get('hits', {}).get('total', {}).get('value', 0),
            'data_sources': data_sources
        }
        
        return host_data
    
    def push_threat_data(self, threat_data):
        """
        Push threat intelligence data to Elastic SIEM.
        
        Args:
            threat_data (list): List of threat dictionaries to push
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.enabled:
            logger.warning("Elastic SIEM integration is disabled")
            return False
            
        try:
            auth = HTTPBasicAuth(self.username, self.password)
            headers = {'Content-Type': 'application/x-ndjson'}
            
            # For bulk indexing
            bulk_data = []
            
            for threat in threat_data:
                # Add the index action
                bulk_data.append(json.dumps({
                    "index": {
                        "_index": "threat-intel",
                        "_id": threat.get('id', None)  # Optional, Elasticsearch can generate an ID
                    }
                }))
                
                # Add the document
                # Format the threat data to match ECS (Elastic Common Schema)
                ecs_threat = {
                    "@timestamp": datetime.now().isoformat(),
                    "threat": {
                        "indicator": {
                            "type": "mitre-attack-technique",
                            "name": threat.get('technique_name', ''),
                            "description": threat.get('description', '')
                        },
                        "framework": "MITRE ATT&CK",
                        "tactic": {
                            "name": threat.get('tactic_name', ''),
                            "id": threat.get('tactic_id', '')
                        },
                        "technique": {
                            "name": threat.get('technique_name', ''),
                            "id": threat.get('technique_id', '')
                        }
                    },
                    "event": {
                        "provider": "mitre_attack_mapping_tool",
                        "dataset": "threat_intel"
                    },
                    "tags": ["threat", "mitre", "technique"]
                }
                
                bulk_data.append(json.dumps(ecs_threat))
            
            # Prepare the bulk request
            bulk_body = "\n".join(bulk_data) + "\n"
            
            # Send bulk data to Elasticsearch
            response = requests.post(
                f"{self.base_url}/_bulk",
                auth=auth,
                headers=headers,
                data=bulk_body,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if response.status_code not in (200, 201):
                logger.error(f"Failed to push threat data to Elastic: {response.text}")
                return False
                
            # Check for errors in response
            response_data = response.json()
            if response_data.get('errors', False):
                for item in response_data.get('items', []):
                    if 'error' in item.get('index', {}):
                        logger.error(f"Error indexing document: {item['index']['error']}")
                return False
                
            return True
            
        except Exception as e:
            logger.error(f"Error pushing threat data to Elastic SIEM: {str(e)}")
            return False


class QRadarIntegration(SIEMIntegrationBase):
    """Integration with IBM QRadar SIEM."""
    
    def __init__(self, config):
        """
        Initialize the QRadar integration.
        
        Args:
            config (dict): Configuration dictionary containing QRadar settings
        """
        super().__init__(config)
        self.api_key = config.get('api_key', '')
        
        if self.enabled and not self.api_key:
            logger.error("QRadar API key not configured")
            self.enabled = False
    
    def is_available(self):
        """
        Check if QRadar is available.
        
        Returns:
            bool: True if available, False otherwise
        """
        if not self.enabled:
            return False
            
        try:
            headers = {
                'SEC': self.api_key,
                'Accept': 'application/json'
            }
            
            response = requests.get(
                f"{self.base_url}/api/system/about",
                headers=headers,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Error checking QRadar availability: {str(e)}")
            return False
    
    def execute_query(self, query, query_type="ariel", timeout_seconds=60):
        """
        Execute a QRadar query.
        
        Args:
            query (str): QRadar AQL query
            query_type (str): Type of query (ariel, qradar)
            timeout_seconds (int): Query timeout in seconds
            
        Returns:
            dict: Query results or None if error
        """
        if not self.enabled:
            logger.warning("QRadar integration is disabled")
            return None
            
        try:
            headers = {
                'SEC': self.api_key,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            
            # Start the search
            search_url = f"{self.base_url}/api/ariel/searches"
            search_data = {
                'query_expression': query,
                'query_language': 'AQL' if query_type == 'ariel' else 'QQL'
            }
            
            response = requests.post(
                search_url,
                headers=headers,
                json=search_data,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if response.status_code != 201:
                logger.error(f"Failed to create QRadar search: {response.text}")
                return None
                
            # Get the search ID
            search_id = response.json().get('search_id')
            logger.info(f"Created QRadar search with ID: {search_id}")
            
            # Poll for search completion
            status_url = f"{search_url}/{search_id}"
            start_time = time.time()
            
            while True:
                # Check if timeout has been reached
                if time.time() - start_time > timeout_seconds:
                    logger.error("QRadar search timed out")
                    return None
                    
                # Get search status
                status_response = requests.get(
                    status_url,
                    headers=headers,
                    verify=self.verify_ssl,
                    timeout=self.timeout
                )
                
                if status_response.status_code != 200:
                    logger.error(f"Failed to get QRadar search status: {status_response.text}")
                    return None
                    
                status = status_response.json().get('status')
                
                if status == 'COMPLETED':
                    break
                elif status == 'EXECUTE' or status == 'WAIT':
                    time.sleep(1)  # Wait before checking again
                else:
                    logger.error(f"QRadar search failed with status: {status}")
                    return None
            
            # Get the search results
            results_url = f"{status_url}/results"
            results_response = requests.get(
                results_url,
                headers=headers,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if results_response.status_code != 200:
                logger.error(f"Failed to get QRadar search results: {results_response.text}")
                return None
                
            return results_response.json()
            
        except Exception as e:
            logger.error(f"Error executing QRadar query: {str(e)}")
            return None
    
    def get_recent_alerts(self, hours=24, severity=None):
        """
        Get recent alerts from QRadar.
        
        Args:
            hours (int): Number of hours to look back
            severity (str, optional): Filter by severity (e.g., "high", "critical")
            
        Returns:
            list: List of alert dictionaries
        """
        # Convert severity string to QRadar severity level
        severity_map = {
            'low': '1,2,3',
            'medium': '4,5,6',
            'high': '7,8',
            'critical': '9,10'
        }
        
        severity_clause = ""
        if severity and severity.lower() in severity_map:
            severity_level = severity_map[severity.lower()]
            severity_clause = f" AND severity IN ({severity_level})"
        
        # Construct AQL query
        start_time = int((datetime.now() - timedelta(hours=hours)).timestamp() * 1000)
        query = f"SELECT DATEFORMAT(starttime, 'YYYY-MM-dd HH:mm:ss') as timestamp, " \
                f"QIDNAME(qid) as event_name, " \
                f"CATEGORYNAME(category) as category, " \
                f"LOGSOURCENAME(logsourceid) as log_source, " \
                f"sourceip, destinationip, username, severity, magnitude, " \
                f"eventcount as count " \
                f"FROM events " \
                f"WHERE starttime > {start_time}{severity_clause} " \
                f"ORDER BY starttime DESC"
        
        # Execute the query
        results = self.execute_query(query)
        
        if not results:
            return []
            
        # Process and normalize the results
        alerts = []
        for event in results.get('events', []):
            alert = {
                'id': event.get('eventid', ''),
                'timestamp': event.get('timestamp', ''),
                'event_type': event.get('event_name', 'unknown'),
                'category': event.get('category', ''),
                'severity': event.get('severity', 'unknown'),
                'source': 'qradar',
                'source_ip': event.get('sourceip', ''),
                'destination_ip': event.get('destinationip', ''),
                'username': event.get('username', ''),
                'magnitude': event.get('magnitude', ''),
                'count': event.get('count', 1),
                'log_source': event.get('log_source', ''),
                'raw_data': event
            }
            alerts.append(alert)
            
        return alerts
    
    def get_host_data(self, hostname):
        """
        Get data about a specific host from QRadar.
        
        Args:
            hostname (str): Hostname to look up
            
        Returns:
            dict: Host data or None if not found
        """
        if not self.enabled:
            logger.warning("QRadar integration is disabled")
            return None
            
        try:
            # First, try to get the asset by name
            headers = {
                'SEC': self.api_key,
                'Accept': 'application/json'
            }
            
            # Search for the asset
            asset_url = f"{self.base_url}/api/asset_model/assets"
            params = {
                'filter': f'domain_id=0 and (hostname="{hostname}" or interfaces contains("{hostname}"))'
            }
            
            response = requests.get(
                asset_url,
                headers=headers,
                params=params,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to get QRadar asset data: {response.text}")
                return None
                
            assets = response.json()
            
            if not assets:
                logger.warning(f"No asset found for hostname: {hostname}")
                return None
                
            # Get the first matching asset
            asset = assets[0]
            
            # Get additional data from events
            query = f"SELECT DATEFORMAT(MIN(starttime), 'YYYY-MM-dd HH:mm:ss') as first_seen, " \
                    f"DATEFORMAT(MAX(starttime), 'YYYY-MM-dd HH:mm:ss') as last_seen, " \
                    f"COUNT(*) as event_count " \
                    f"FROM events " \
                    f"WHERE sourceip='{asset.get('interfaces', [{}])[0].get('ip_address', '')}' " \
                    f"OR destinationip='{asset.get('interfaces', [{}])[0].get('ip_address', '')}'"
            
            event_results = self.execute_query(query)
            
            if not event_results or not event_results.get('events'):
                event_data = {
                    'first_seen': '',
                    'last_seen': '',
                    'event_count': 0
                }
            else:
                event_data = event_results['events'][0]
            
            # Compile host data
            host_data = {
                'hostname': hostname,
                'first_seen': event_data.get('first_seen', ''),
                'last_seen': event_data.get('last_seen', ''),
                'os': asset.get('primary_os', {}).get('name', ''),
                'ip_addresses': [interface.get('ip_address') for interface in asset.get('interfaces', [])],
                'event_count': event_data.get('event_count', 0),
                'asset_id': asset.get('id', ''),
                'risk_score': asset.get('risk_score', 0),
                'vulnerabilities': asset.get('vulnerability_count', 0)
            }
            
            return host_data
            
        except Exception as e:
            logger.error(f"Error getting host data from QRadar: {str(e)}")
            return None
    
    def push_threat_data(self, threat_data):
        """
        Push threat intelligence data to QRadar using the Reference Data API.
        
        Args:
            threat_data (list): List of threat dictionaries to push
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.enabled:
            logger.warning("QRadar integration is disabled")
            return False
            
        try:
            headers = {
                'SEC': self.api_key,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            
            # Check if reference set exists, create if not
            ref_set_name = "MITRE_ATT&CK_Techniques"
            ref_sets_url = f"{self.base_url}/api/reference_data/sets"
            
            # Get existing reference sets
            response = requests.get(
                ref_sets_url,
                headers=headers,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to get QRadar reference sets: {response.text}")
                return False
                
            # Check if our reference set exists
            ref_sets = response.json()
            ref_set_exists = any(ref_set.get('name') == ref_set_name for ref_set in ref_sets)
            
            # Create reference set if it doesn't exist
            if not ref_set_exists:
                create_data = {
                    'name': ref_set_name,
                    'element_type': 'ALNIC',  # Alphanumeric
                    'timeout_type': 'FIRST_SEEN',
                    'time_to_live': '30 days'
                }
                
                create_response = requests.post(
                    ref_sets_url,
                    headers=headers,
                    json=create_data,
                    verify=self.verify_ssl,
                    timeout=self.timeout
                )
                
                if create_response.status_code not in (200, 201):
                    logger.error(f"Failed to create QRadar reference set: {create_response.text}")
                    return False
            
            # Add threat data to reference set
            success = True
            
            # Create a map reference map for additional data
            map_name = "MITRE_ATT&CK_Technique_Details"
            map_url = f"{self.base_url}/api/reference_data/maps"
            
            # Check if map exists
            response = requests.get(
                map_url,
                headers=headers,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to get QRadar reference maps: {response.text}")
                return False
                
            # Check if our map exists
            ref_maps = response.json()
            map_exists = any(ref_map.get('name') == map_name for ref_map in ref_maps)
            
            # Create map if it doesn't exist
            if not map_exists:
                create_data = {
                    'name': map_name,
                    'element_type': 'ALNIC',  # Alphanumeric
                    'key_label': 'technique_id',
                    'value_label': 'technique_details',
                    'timeout_type': 'FIRST_SEEN',
                    'time_to_live': '30 days'
                }
                
                create_response = requests.post(
                    map_url,
                    headers=headers,
                    json=create_data,
                    verify=self.verify_ssl,
                    timeout=self.timeout
                )
                
                if create_response.status_code not in (200, 201):
                    logger.error(f"Failed to create QRadar reference map: {create_response.text}")
                    return False
            
            # Add each threat to the reference set and map
            for threat in threat_data:
                technique_id = threat.get('technique_id', '')
                
                if not technique_id:
                    continue
                
                # Add to reference set
                set_url = f"{ref_sets_url}/{ref_set_name}"
                set_data = {
                    'value': technique_id
                }
                
                set_response = requests.post(
                    set_url,
                    headers=headers,
                    json=set_data,
                    verify=self.verify_ssl,
                    timeout=self.timeout
                )
                
                if set_response.status_code not in (200, 201):
                    logger.error(f"Failed to add technique to QRadar reference set: {set_response.text}")
                    success = False
                
                # Add to reference map
                map_url = f"{self.base_url}/api/reference_data/maps/{map_name}"
                
                # Create a JSON string with technique details
                technique_details = {
                    'technique_name': threat.get('technique_name', ''),
                    'tactic_name': threat.get('tactic_name', ''),
                    'tactic_id': threat.get('tactic_id', ''),
                    'description': threat.get('description', ''),
                    'source': threat.get('source', 'mitre_attack_mapping_tool'),
                    'timestamp': datetime.now().isoformat()
                }
                
                map_data = {
                    'key': technique_id,
                    'value': json.dumps(technique_details)
                }
                
                map_response = requests.post(
                    map_url,
                    headers=headers,
                    json=map_data,
                    verify=self.verify_ssl,
                    timeout=self.timeout
                )
                
                if map_response.status_code not in (200, 201):
                    logger.error(f"Failed to add technique to QRadar reference map: {map_response.text}")
                    success = False
            
            return success
            
        except Exception as e:
            logger.error(f"Error pushing threat data to QRadar: {str(e)}")
            return False
