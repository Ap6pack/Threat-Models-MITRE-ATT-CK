#!/usr/bin/env python3
"""
SOAR Integration Module for the Threat Models and MITRE ATT&CK Mapping Tool.

This module provides integration with Security Orchestration, Automation, and Response (SOAR)
platforms, allowing for automated incident response based on mapped threat intelligence.

Supported SOAR Platforms:
- TheHive
- Cortex XSOAR (Demisto)
- Swimlane
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


class SOARIntegrationBase:
    """Base class for SOAR integrations."""
    
    def __init__(self, config):
        """
        Initialize the SOAR integration base class.
        
        Args:
            config (dict): Configuration dictionary containing SOAR settings
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
        Check if the SOAR platform is available.
        
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
    
    def create_case(self, title, description, severity, tags=None, artifacts=None):
        """
        Create a case in the SOAR platform.
        
        Args:
            title (str): Case title
            description (str): Case description
            severity (str): Case severity (low, medium, high, critical)
            tags (list, optional): List of tags
            artifacts (list, optional): List of artifacts
            
        Returns:
            str: Case ID if successful, None otherwise
        """
        raise NotImplementedError("Subclasses must implement create_case")
    
    def update_case(self, case_id, updates):
        """
        Update a case in the SOAR platform.
        
        Args:
            case_id (str): Case ID
            updates (dict): Updates to apply
            
        Returns:
            bool: True if successful, False otherwise
        """
        raise NotImplementedError("Subclasses must implement update_case")
    
    def get_case(self, case_id):
        """
        Get a case from the SOAR platform.
        
        Args:
            case_id (str): Case ID
            
        Returns:
            dict: Case data if successful, None otherwise
        """
        raise NotImplementedError("Subclasses must implement get_case")
    
    def search_cases(self, query):
        """
        Search for cases in the SOAR platform.
        
        Args:
            query (dict): Search query
            
        Returns:
            list: List of matching cases
        """
        raise NotImplementedError("Subclasses must implement search_cases")
    
    def create_task(self, case_id, title, description, status="New"):
        """
        Create a task in a case.
        
        Args:
            case_id (str): Case ID
            title (str): Task title
            description (str): Task description
            status (str): Task status
            
        Returns:
            str: Task ID if successful, None otherwise
        """
        raise NotImplementedError("Subclasses must implement create_task")
    
    def execute_playbook(self, case_id, playbook_id):
        """
        Execute a playbook on a case.
        
        Args:
            case_id (str): Case ID
            playbook_id (str): Playbook ID
            
        Returns:
            str: Execution ID if successful, None otherwise
        """
        raise NotImplementedError("Subclasses must implement execute_playbook")


class TheHiveIntegration(SOARIntegrationBase):
    """Integration with TheHive SOAR platform."""
    
    def __init__(self, config):
        """
        Initialize TheHive integration.
        
        Args:
            config (dict): Configuration dictionary containing TheHive settings
        """
        super().__init__(config)
        self.api_key = config.get('api_key', '')
        
        if self.enabled and not self.api_key:
            logger.error("TheHive API key not configured")
            self.enabled = False
    
    def is_available(self):
        """
        Check if TheHive is available.
        
        Returns:
            bool: True if available, False otherwise
        """
        if not self.enabled:
            return False
            
        try:
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get(
                f"{self.base_url}/api/alert",
                headers=headers,
                params={'range': '0-1'},  # Just get one alert to check availability
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            return response.status_code in (200, 204)
        except Exception as e:
            logger.error(f"Error checking TheHive availability: {str(e)}")
            return False
    
    def create_case(self, title, description, severity, tags=None, artifacts=None):
        """
        Create a case in TheHive.
        
        Args:
            title (str): Case title
            description (str): Case description
            severity (str): Case severity (low, medium, high, critical)
            tags (list, optional): List of tags
            artifacts (list, optional): List of artifacts
            
        Returns:
            str: Case ID if successful, None otherwise
        """
        if not self.enabled:
            logger.warning("TheHive integration is disabled")
            return None
            
        try:
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            # Map severity to TheHive severity (1-4)
            severity_map = {
                'low': 1,
                'medium': 2,
                'high': 3,
                'critical': 4
            }
            
            hive_severity = severity_map.get(severity.lower(), 2)
            
            # Prepare case data
            case_data = {
                'title': title,
                'description': description,
                'severity': hive_severity,
                'tags': tags or [],
                'tlp': 2,  # TLP:AMBER
                'pap': 2,  # PAP:AMBER
                'status': 'New',
                'flag': False
            }
            
            # Create the case
            response = requests.post(
                f"{self.base_url}/api/case",
                headers=headers,
                json=case_data,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if response.status_code != 201:
                logger.error(f"Failed to create case in TheHive: {response.text}")
                return None
                
            case_id = response.json().get('id')
            logger.info(f"Created case in TheHive with ID: {case_id}")
            
            # Add artifacts if provided
            if artifacts and case_id:
                self._add_artifacts(case_id, artifacts)
                
            return case_id
            
        except Exception as e:
            logger.error(f"Error creating case in TheHive: {str(e)}")
            return None
    
    def _add_artifacts(self, case_id, artifacts):
        """
        Add artifacts to a case in TheHive.
        
        Args:
            case_id (str): Case ID
            artifacts (list): List of artifact dictionaries
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not artifacts:
            return True
            
        try:
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            success = True
            
            for artifact in artifacts:
                # Map artifact type to TheHive dataType
                data_type_map = {
                    'ip': 'ip',
                    'domain': 'domain',
                    'url': 'url',
                    'email': 'mail',
                    'hash': 'hash',
                    'file': 'file',
                    'technique': 'other'
                }
                
                artifact_type = artifact.get('type', 'other')
                data_type = data_type_map.get(artifact_type, 'other')
                
                # Prepare artifact data
                artifact_data = {
                    'dataType': data_type,
                    'data': artifact.get('value', ''),
                    'message': artifact.get('description', ''),
                    'tags': artifact.get('tags', []),
                    'ioc': artifact.get('ioc', False),
                    'tlp': 2,  # TLP:AMBER
                    'pap': 2   # PAP:AMBER
                }
                
                # Create the artifact
                response = requests.post(
                    f"{self.base_url}/api/case/{case_id}/artifact",
                    headers=headers,
                    json=artifact_data,
                    verify=self.verify_ssl,
                    timeout=self.timeout
                )
                
                if response.status_code != 201:
                    logger.error(f"Failed to add artifact to TheHive case: {response.text}")
                    success = False
            
            return success
            
        except Exception as e:
            logger.error(f"Error adding artifacts to TheHive case: {str(e)}")
            return False
    
    def update_case(self, case_id, updates):
        """
        Update a case in TheHive.
        
        Args:
            case_id (str): Case ID
            updates (dict): Updates to apply
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.enabled:
            logger.warning("TheHive integration is disabled")
            return False
            
        try:
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            # Map severity if provided
            if 'severity' in updates:
                severity_map = {
                    'low': 1,
                    'medium': 2,
                    'high': 3,
                    'critical': 4
                }
                updates['severity'] = severity_map.get(updates['severity'].lower(), updates['severity'])
            
            # Update the case
            response = requests.patch(
                f"{self.base_url}/api/case/{case_id}",
                headers=headers,
                json=updates,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to update case in TheHive: {response.text}")
                return False
                
            logger.info(f"Updated case in TheHive with ID: {case_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating case in TheHive: {str(e)}")
            return False
    
    def get_case(self, case_id):
        """
        Get a case from TheHive.
        
        Args:
            case_id (str): Case ID
            
        Returns:
            dict: Case data if successful, None otherwise
        """
        if not self.enabled:
            logger.warning("TheHive integration is disabled")
            return None
            
        try:
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            # Get the case
            response = requests.get(
                f"{self.base_url}/api/case/{case_id}",
                headers=headers,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to get case from TheHive: {response.text}")
                return None
                
            return response.json()
            
        except Exception as e:
            logger.error(f"Error getting case from TheHive: {str(e)}")
            return None
    
    def search_cases(self, query):
        """
        Search for cases in TheHive.
        
        Args:
            query (dict): Search query
            
        Returns:
            list: List of matching cases
        """
        if not self.enabled:
            logger.warning("TheHive integration is disabled")
            return []
            
        try:
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            # TheHive uses a specific query format
            search_query = {
                'query': query
            }
            
            # Search for cases
            response = requests.post(
                f"{self.base_url}/api/case/_search",
                headers=headers,
                json=search_query,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to search cases in TheHive: {response.text}")
                return []
                
            return response.json()
            
        except Exception as e:
            logger.error(f"Error searching cases in TheHive: {str(e)}")
            return []
    
    def create_task(self, case_id, title, description, status="Waiting"):
        """
        Create a task in a case in TheHive.
        
        Args:
            case_id (str): Case ID
            title (str): Task title
            description (str): Task description
            status (str): Task status
            
        Returns:
            str: Task ID if successful, None otherwise
        """
        if not self.enabled:
            logger.warning("TheHive integration is disabled")
            return None
            
        try:
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json'
            }
            
            # Map status to TheHive status
            status_map = {
                'New': 'Waiting',
                'In Progress': 'InProgress',
                'Completed': 'Completed',
                'Canceled': 'Cancel'
            }
            
            hive_status = status_map.get(status, 'Waiting')
            
            # Prepare task data
            task_data = {
                'title': title,
                'description': description,
                'status': hive_status,
                'flag': False
            }
            
            # Create the task
            response = requests.post(
                f"{self.base_url}/api/case/{case_id}/task",
                headers=headers,
                json=task_data,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if response.status_code != 201:
                logger.error(f"Failed to create task in TheHive: {response.text}")
                return None
                
            task_id = response.json().get('id')
            logger.info(f"Created task in TheHive with ID: {task_id}")
            return task_id
            
        except Exception as e:
            logger.error(f"Error creating task in TheHive: {str(e)}")
            return None
    
    def execute_playbook(self, case_id, playbook_id):
        """
        Execute a playbook on a case in TheHive.
        
        Args:
            case_id (str): Case ID
            playbook_id (str): Playbook ID
            
        Returns:
            str: Execution ID if successful, None otherwise
        """
        # TheHive doesn't have built-in playbooks, but we can simulate this
        # by creating a series of tasks based on a predefined template
        if not self.enabled:
            logger.warning("TheHive integration is disabled")
            return None
            
        try:
            # Get playbook definition (in a real implementation, this would be loaded from a file)
            playbooks = {
                'mitre_investigation': [
                    {
                        'title': 'Initial Triage',
                        'description': 'Perform initial triage of the incident'
                    },
                    {
                        'title': 'Collect Evidence',
                        'description': 'Collect evidence related to the detected techniques'
                    },
                    {
                        'title': 'Analyze Indicators',
                        'description': 'Analyze indicators of compromise'
                    },
                    {
                        'title': 'Containment Actions',
                        'description': 'Perform containment actions to limit the impact'
                    },
                    {
                        'title': 'Remediation',
                        'description': 'Implement remediation steps'
                    }
                ]
            }
            
            playbook = playbooks.get(playbook_id)
            
            if not playbook:
                logger.error(f"Playbook {playbook_id} not found")
                return None
                
            # Create tasks for each step in the playbook
            task_ids = []
            for step in playbook:
                task_id = self.create_task(
                    case_id,
                    step['title'],
                    step['description']
                )
                if task_id:
                    task_ids.append(task_id)
            
            if not task_ids:
                logger.error("Failed to create any tasks for the playbook")
                return None
                
            # Return a comma-separated list of task IDs as the "execution ID"
            execution_id = ','.join(task_ids)
            logger.info(f"Executed playbook {playbook_id} on case {case_id}, created tasks: {execution_id}")
            return execution_id
            
        except Exception as e:
            logger.error(f"Error executing playbook in TheHive: {str(e)}")
            return None


class DemistoIntegration(SOARIntegrationBase):
    """Integration with Cortex XSOAR (Demisto) SOAR platform."""
    
    def __init__(self, config):
        """
        Initialize Demisto integration.
        
        Args:
            config (dict): Configuration dictionary containing Demisto settings
        """
        super().__init__(config)
        self.api_key = config.get('api_key', '')
        
        if self.enabled and not self.api_key:
            logger.error("Demisto API key not configured")
            self.enabled = False
    
    def is_available(self):
        """
        Check if Demisto is available.
        
        Returns:
            bool: True if available, False otherwise
        """
        if not self.enabled:
            return False
            
        try:
            headers = {
                'Authorization': self.api_key,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            
            response = requests.get(
                f"{self.base_url}/health",
                headers=headers,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Error checking Demisto availability: {str(e)}")
            return False
    
    def create_case(self, title, description, severity, tags=None, artifacts=None):
        """
        Create a case (incident) in Demisto.
        
        Args:
            title (str): Case title
            description (str): Case description
            severity (str): Case severity (low, medium, high, critical)
            tags (list, optional): List of tags
            artifacts (list, optional): List of artifacts
            
        Returns:
            str: Case ID if successful, None otherwise
        """
        if not self.enabled:
            logger.warning("Demisto integration is disabled")
            return None
            
        try:
            headers = {
                'Authorization': self.api_key,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            
            # Map severity to Demisto severity (0-4)
            severity_map = {
                'low': 1,
                'medium': 2,
                'high': 3,
                'critical': 4
            }
            
            demisto_severity = severity_map.get(severity.lower(), 2)
            
            # Prepare incident data
            incident_data = {
                'name': title,
                'details': description,
                'severity': demisto_severity,
                'labels': [{'type': tag, 'value': tag} for tag in (tags or [])],
                'createInvestigation': True,
                'type': 'MITRE ATT&CK'
            }
            
            # Create the incident
            response = requests.post(
                f"{self.base_url}/incident",
                headers=headers,
                json=incident_data,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if response.status_code != 201:
                logger.error(f"Failed to create incident in Demisto: {response.text}")
                return None
                
            incident_id = response.json().get('id')
            logger.info(f"Created incident in Demisto with ID: {incident_id}")
            
            # Add artifacts if provided
            if artifacts and incident_id:
                self._add_artifacts(incident_id, artifacts)
                
            return incident_id
            
        except Exception as e:
            logger.error(f"Error creating incident in Demisto: {str(e)}")
            return None
    
    def _add_artifacts(self, incident_id, artifacts):
        """
        Add artifacts to an incident in Demisto.
        
        Args:
            incident_id (str): Incident ID
            artifacts (list): List of artifact dictionaries
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not artifacts:
            return True
            
        try:
            headers = {
                'Authorization': self.api_key,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            
            success = True
            
            for artifact in artifacts:
                # Map artifact type to Demisto indicator type
                indicator_type_map = {
                    'ip': 'IP',
                    'domain': 'Domain',
                    'url': 'URL',
                    'email': 'Email',
                    'hash': 'File MD5',
                    'file': 'File Name',
                    'technique': 'MITRE ATT&CK'
                }
                
                artifact_type = artifact.get('type', 'other')
                indicator_type = indicator_type_map.get(artifact_type, 'Other')
                
                # Prepare indicator data
                indicator_data = {
                    'indicator': artifact.get('value', ''),
                    'type': indicator_type,
                    'reputation': 'Suspicious',
                    'comment': artifact.get('description', ''),
                    'relatedIncidents': [incident_id],
                    'tags': artifact.get('tags', [])
                }
                
                # Create the indicator
                response = requests.post(
                    f"{self.base_url}/indicator/create",
                    headers=headers,
                    json=indicator_data,
                    verify=self.verify_ssl,
                    timeout=self.timeout
                )
                
                if response.status_code != 200:
                    logger.error(f"Failed to add indicator to Demisto incident: {response.text}")
                    success = False
            
            return success
            
        except Exception as e:
            logger.error(f"Error adding indicators to Demisto incident: {str(e)}")
            return False
    
    def update_case(self, case_id, updates):
        """
        Update a case (incident) in Demisto.
        
        Args:
            case_id (str): Case ID
            updates (dict): Updates to apply
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.enabled:
            logger.warning("Demisto integration is disabled")
            return False
            
        try:
            headers = {
                'Authorization': self.api_key,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            
            # Map severity if provided
            if 'severity' in updates:
                severity_map = {
                    'low': 1,
                    'medium': 2,
                    'high': 3,
                    'critical': 4
                }
                updates['severity'] = severity_map.get(updates['severity'].lower(), updates['severity'])
            
            # Map field names to Demisto field names
            field_map = {
                'title': 'name',
                'description': 'details',
                'status': 'status'
            }
            
            demisto_updates = {}
            for key, value in updates.items():
                demisto_key = field_map.get(key, key)
                demisto_updates[demisto_key] = value
            
            # Update the incident
            response = requests.post(
                f"{self.base_url}/incident/update/{case_id}",
                headers=headers,
                json=demisto_updates,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to update incident in Demisto: {response.text}")
                return False
                
            logger.info(f"Updated incident in Demisto with ID: {case_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating incident in Demisto: {str(e)}")
            return False
    
    def get_case(self, case_id):
        """
        Get a case (incident) from Demisto.
        
        Args:
            case_id (str): Case ID
            
        Returns:
            dict: Case data if successful, None otherwise
        """
        if not self.enabled:
            logger.warning("Demisto integration is disabled")
            return None
            
        try:
            headers = {
                'Authorization': self.api_key,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            
            # Get the incident
            response = requests.get(
                f"{self.base_url}/incident/{case_id}",
                headers=headers,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to get incident from Demisto: {response.text}")
                return None
                
            return response.json()
            
        except Exception as e:
            logger.error(f"Error getting incident from Demisto: {str(e)}")
            return None
    
    def search_cases(self, query):
        """
        Search for cases (incidents) in Demisto.
        
        Args:
            query (dict): Search query
            
        Returns:
            list: List of matching cases
        """
        if not self.enabled:
            logger.warning("Demisto integration is disabled")
            return []
            
        try:
            headers = {
                'Authorization': self.api_key,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            
            # Demisto uses a specific query format
            filter_fields = []
            for key, value in query.items():
                filter_fields.append({
                    'field': key,
                    'value': value
                })
            
            search_query = {
                'filter': {
                    'query': '',
                    'period': {
                        'by': 'day',
                        'fromValue': 7,
                        'toValue': 0
                    },
                    'filters': filter_fields
                }
            }
            
            # Search for incidents
            response = requests.post(
                f"{self.base_url}/incidents/search",
                headers=headers,
                json=search_query,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to search incidents in Demisto: {response.text}")
                return []
                
            return response.json().get('data', [])
            
        except Exception as e:
            logger.error(f"Error searching incidents in Demisto: {str(e)}")
            return []
    
    def create_task(self, case_id, title, description, status="Not Started"):
        """
        Create a task in an incident in Demisto.
        
        Args:
            case_id (str): Case ID
            title (str): Task title
            description (str): Task description
            status (str): Task status
            
        Returns:
            str: Task ID if successful, None otherwise
        """
        if not self.enabled:
            logger.warning("Demisto integration is disabled")
            return None
            
        try:
            headers = {
                'Authorization': self.api_key,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            
            # Map status to Demisto status
            status_map = {
                'New': 'Not Started',
                'In Progress': 'In Progress',
                'Completed': 'Completed',
                'Canceled': 'Canceled'
            }
            
            demisto_status = status_map.get(status, 'Not Started')
            
            # Prepare task data
            task_data = {
                'incidentId': case_id,
                'title': title,
                'description': description,
                'status': demisto_status
            }
            
            # Create the task
            response = requests.post(
                f"{self.base_url}/incident/task",
                headers=headers,
                json=task_data,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to create task in Demisto: {response.text}")
                return None
                
            task_id = response.json().get('id')
            logger.info(f"Created task in Demisto with ID: {task_id}")
            return task_id
                        
        except Exception as e:
            logger.error(f"Error creating task in Demisto: {str(e)}")
            return None
    
    def execute_playbook(self, case_id, playbook_id):
        """
        Execute a playbook on an incident in Demisto.
        
        Args:
            case_id (str): Case ID
            playbook_id (str): Playbook ID
            
        Returns:
            str: Execution ID if successful, None otherwise
        """
        if not self.enabled:
            logger.warning("Demisto integration is disabled")
            return None
            
        try:
            headers = {
                'Authorization': self.api_key,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }
            
            # Prepare playbook execution data
            execution_data = {
                'incidentId': case_id,
                'playbookId': playbook_id,
                'args': {}  # Optional arguments for the playbook
            }
            
            # Execute the playbook
            response = requests.post(
                f"{self.base_url}/playbook/run",
                headers=headers,
                json=execution_data,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to execute playbook in Demisto: {response.text}")
                return None
                
            execution_id = response.json().get('id')
            logger.info(f"Executed playbook {playbook_id} on incident {case_id} with execution ID: {execution_id}")
            return execution_id
            
        except Exception as e:
            logger.error(f"Error executing playbook in Demisto: {str(e)}")
            return None


class SwimlaneIntegration(SOARIntegrationBase):
    """Integration with Swimlane SOAR platform."""
    
    def __init__(self, config):
        """
        Initialize Swimlane integration.
        
        Args:
            config (dict): Configuration dictionary containing Swimlane settings
        """
        super().__init__(config)
        self.username = config.get('username', '')
        self.password = config.get('password', '')
        self.app_id = config.get('app_id', '')
        
        if self.enabled and (not self.username or not self.password):
            logger.error("Swimlane username or password not configured")
            self.enabled = False
        
        if self.enabled and not self.app_id:
            logger.error("Swimlane app ID not configured")
            self.enabled = False
    
    def is_available(self):
        """
        Check if Swimlane is available.
        
        Returns:
            bool: True if available, False otherwise
        """
        if not self.enabled:
            return False
            
        try:
            # Get JWT token
            auth_data = {
                'username': self.username,
                'password': self.password
            }
            
            auth_response = requests.post(
                f"{self.base_url}/api/auth/login",
                json=auth_data,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if auth_response.status_code != 200:
                logger.error(f"Failed to authenticate with Swimlane: {auth_response.text}")
                return False
                
            # If we can get a token, the service is available
            return True
            
        except Exception as e:
            logger.error(f"Error checking Swimlane availability: {str(e)}")
            return False
    
    def _get_auth_token(self):
        """
        Get authentication token from Swimlane.
        
        Returns:
            str: JWT token if successful, None otherwise
        """
        try:
            auth_data = {
                'username': self.username,
                'password': self.password
            }
            
            auth_response = requests.post(
                f"{self.base_url}/api/auth/login",
                json=auth_data,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if auth_response.status_code != 200:
                logger.error(f"Failed to authenticate with Swimlane: {auth_response.text}")
                return None
                
            return auth_response.json().get('token')
            
        except Exception as e:
            logger.error(f"Error getting Swimlane auth token: {str(e)}")
            return None
    
    def create_case(self, title, description, severity, tags=None, artifacts=None):
        """
        Create a case in Swimlane.
        
        Args:
            title (str): Case title
            description (str): Case description
            severity (str): Case severity (low, medium, high, critical)
            tags (list, optional): List of tags
            artifacts (list, optional): List of artifacts
            
        Returns:
            str: Case ID if successful, None otherwise
        """
        if not self.enabled:
            logger.warning("Swimlane integration is disabled")
            return None
            
        try:
            # Get auth token
            token = self._get_auth_token()
            if not token:
                return None
                
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            
            # Map severity to Swimlane severity
            severity_map = {
                'low': 'Low',
                'medium': 'Medium',
                'high': 'High',
                'critical': 'Critical'
            }
            
            swimlane_severity = severity_map.get(severity.lower(), 'Medium')
            
            # Prepare case data
            case_data = {
                'applicationId': self.app_id,
                'values': {
                    'name': title,
                    'description': description,
                    'severity': swimlane_severity,
                    'status': 'New',
                    'tags': tags or []
                }
            }
            
            # Create the case
            response = requests.post(
                f"{self.base_url}/api/app/{self.app_id}/record",
                headers=headers,
                json=case_data,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to create case in Swimlane: {response.text}")
                return None
                
            case_id = response.json().get('id')
            logger.info(f"Created case in Swimlane with ID: {case_id}")
            
            # Add artifacts if provided
            if artifacts and case_id:
                self._add_artifacts(case_id, artifacts, token)
                
            return case_id
            
        except Exception as e:
            logger.error(f"Error creating case in Swimlane: {str(e)}")
            return None
    
    def _add_artifacts(self, case_id, artifacts, token=None):
        """
        Add artifacts to a case in Swimlane.
        
        Args:
            case_id (str): Case ID
            artifacts (list): List of artifact dictionaries
            token (str, optional): Auth token
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not artifacts:
            return True
            
        try:
            # Get auth token if not provided
            if not token:
                token = self._get_auth_token()
                if not token:
                    return False
                    
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            
            success = True
            
            # Get the current case
            response = requests.get(
                f"{self.base_url}/api/app/{self.app_id}/record/{case_id}",
                headers=headers,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to get case from Swimlane: {response.text}")
                return False
                
            case = response.json()
            
            # Get the current artifacts
            current_artifacts = case.get('values', {}).get('artifacts', [])
            
            # Add new artifacts
            for artifact in artifacts:
                current_artifacts.append({
                    'type': artifact.get('type', 'other'),
                    'value': artifact.get('value', ''),
                    'description': artifact.get('description', ''),
                    'tags': artifact.get('tags', [])
                })
            
            # Update the case with new artifacts
            case['values']['artifacts'] = current_artifacts
            
            update_response = requests.put(
                f"{self.base_url}/api/app/{self.app_id}/record/{case_id}",
                headers=headers,
                json=case,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if update_response.status_code != 200:
                logger.error(f"Failed to update case with artifacts in Swimlane: {update_response.text}")
                return False
                
            return True
            
        except Exception as e:
            logger.error(f"Error adding artifacts to Swimlane case: {str(e)}")
            return False
    
    def update_case(self, case_id, updates):
        """
        Update a case in Swimlane.
        
        Args:
            case_id (str): Case ID
            updates (dict): Updates to apply
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.enabled:
            logger.warning("Swimlane integration is disabled")
            return False
            
        try:
            # Get auth token
            token = self._get_auth_token()
            if not token:
                return False
                
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            
            # Get the current case
            response = requests.get(
                f"{self.base_url}/api/app/{self.app_id}/record/{case_id}",
                headers=headers,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to get case from Swimlane: {response.text}")
                return False
                
            case = response.json()
            
            # Map severity if provided
            if 'severity' in updates:
                severity_map = {
                    'low': 'Low',
                    'medium': 'Medium',
                    'high': 'High',
                    'critical': 'Critical'
                }
                updates['severity'] = severity_map.get(updates['severity'].lower(), updates['severity'])
            
            # Map field names to Swimlane field names
            field_map = {
                'title': 'name',
                'description': 'description',
                'status': 'status'
            }
            
            # Update the case values
            for key, value in updates.items():
                swimlane_key = field_map.get(key, key)
                case['values'][swimlane_key] = value
            
            # Update the case
            update_response = requests.put(
                f"{self.base_url}/api/app/{self.app_id}/record/{case_id}",
                headers=headers,
                json=case,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if update_response.status_code != 200:
                logger.error(f"Failed to update case in Swimlane: {update_response.text}")
                return False
                
            logger.info(f"Updated case in Swimlane with ID: {case_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating case in Swimlane: {str(e)}")
            return False
    
    def get_case(self, case_id):
        """
        Get a case from Swimlane.
        
        Args:
            case_id (str): Case ID
            
        Returns:
            dict: Case data if successful, None otherwise
        """
        if not self.enabled:
            logger.warning("Swimlane integration is disabled")
            return None
            
        try:
            # Get auth token
            token = self._get_auth_token()
            if not token:
                return None
                
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            
            # Get the case
            response = requests.get(
                f"{self.base_url}/api/app/{self.app_id}/record/{case_id}",
                headers=headers,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to get case from Swimlane: {response.text}")
                return None
                
            return response.json()
            
        except Exception as e:
            logger.error(f"Error getting case from Swimlane: {str(e)}")
            return None
    
    def search_cases(self, query):
        """
        Search for cases in Swimlane.
        
        Args:
            query (dict): Search query
            
        Returns:
            list: List of matching cases
        """
        if not self.enabled:
            logger.warning("Swimlane integration is disabled")
            return []
            
        try:
            # Get auth token
            token = self._get_auth_token()
            if not token:
                return []
                
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            
            # Swimlane uses a specific query format
            search_query = {
                'applicationId': self.app_id,
                'filters': []
            }
            
            # Add filters for each query parameter
            for key, value in query.items():
                search_query['filters'].append({
                    'fieldId': key,
                    'operator': 'equals',
                    'value': value
                })
            
            # Search for cases
            response = requests.post(
                f"{self.base_url}/api/app/{self.app_id}/records/search",
                headers=headers,
                json=search_query,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to search cases in Swimlane: {response.text}")
                return []
                
            return response.json()
            
        except Exception as e:
            logger.error(f"Error searching cases in Swimlane: {str(e)}")
            return []
    
    def create_task(self, case_id, title, description, status="Not Started"):
        """
        Create a task in a case in Swimlane.
        
        Args:
            case_id (str): Case ID
            title (str): Task title
            description (str): Task description
            status (str): Task status
            
        Returns:
            str: Task ID if successful, None otherwise
        """
        if not self.enabled:
            logger.warning("Swimlane integration is disabled")
            return None
            
        try:
            # Get auth token
            token = self._get_auth_token()
            if not token:
                return None
                
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            
            # Get the current case
            response = requests.get(
                f"{self.base_url}/api/app/{self.app_id}/record/{case_id}",
                headers=headers,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to get case from Swimlane: {response.text}")
                return None
                
            case = response.json()
            
            # Map status to Swimlane status
            status_map = {
                'New': 'Not Started',
                'In Progress': 'In Progress',
                'Completed': 'Completed',
                'Canceled': 'Canceled'
            }
            
            swimlane_status = status_map.get(status, 'Not Started')
            
            # Get the current tasks
            current_tasks = case.get('values', {}).get('tasks', [])
            
            # Create a new task
            task = {
                'id': str(time.time()),  # Use timestamp as ID
                'title': title,
                'description': description,
                'status': swimlane_status,
                'created': datetime.now().isoformat(),
                'assignee': self.username
            }
            
            # Add the task to the case
            current_tasks.append(task)
            case['values']['tasks'] = current_tasks
            
            # Update the case
            update_response = requests.put(
                f"{self.base_url}/api/app/{self.app_id}/record/{case_id}",
                headers=headers,
                json=case,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if update_response.status_code != 200:
                logger.error(f"Failed to add task to case in Swimlane: {update_response.text}")
                return None
                
            logger.info(f"Created task in Swimlane case {case_id} with ID: {task['id']}")
            return task['id']
            
        except Exception as e:
            logger.error(f"Error creating task in Swimlane: {str(e)}")
            return None
    
    def execute_playbook(self, case_id, playbook_id):
        """
        Execute a playbook on a case in Swimlane.
        
        Args:
            case_id (str): Case ID
            playbook_id (str): Playbook ID
            
        Returns:
            str: Execution ID if successful, None otherwise
        """
        if not self.enabled:
            logger.warning("Swimlane integration is disabled")
            return None
            
        try:
            # Get auth token
            token = self._get_auth_token()
            if not token:
                return None
                
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            
            # Prepare playbook execution data
            execution_data = {
                'playbookId': playbook_id,
                'recordIds': [case_id]
            }
            
            # Execute the playbook
            response = requests.post(
                f"{self.base_url}/api/playbook/execute",
                headers=headers,
                json=execution_data,
                verify=self.verify_ssl,
                timeout=self.timeout
            )
            
            if response.status_code != 200:
                logger.error(f"Failed to execute playbook in Swimlane: {response.text}")
                return None
                
            execution_id = response.json().get('id')
            logger.info(f"Executed playbook {playbook_id} on case {case_id} with execution ID: {execution_id}")
            return execution_id
            
        except Exception as e:
            logger.error(f"Error executing playbook in Swimlane: {str(e)}")
            return None


class SOARManager:
    """Manager class for SOAR integrations."""
    
    def __init__(self, config):
        """
        Initialize the SOAR manager.
        
        Args:
            config (dict): Configuration dictionary
        """
        self.config = config
        self.soar_config = config.get('soar', {})
        
        # Initialize SOAR integrations
        self.integrations = {
            'thehive': TheHiveIntegration(self.soar_config.get('thehive', {})),
            'demisto': DemistoIntegration(self.soar_config.get('demisto', {})),
            'swimlane': SwimlaneIntegration(self.soar_config.get('swimlane', {}))
        }
        
        # Log the enabled integrations
        enabled_integrations = [name for name, integration in self.integrations.items() if integration.enabled]
        if enabled_integrations:
            logger.info(f"Enabled SOAR integrations: {', '.join(enabled_integrations)}")
        else:
            logger.warning("No SOAR integrations are enabled")
    
    def get_enabled_soars(self):
        """
        Get a list of enabled SOAR integrations.
        
        Returns:
            list: List of enabled SOAR integration names
        """
        return [name for name, integration in self.integrations.items() if integration.enabled]
    
    def create_case_in_all(self, title, description, severity, tags=None, artifacts=None):
        """
        Create a case in all enabled SOAR platforms.
        
        Args:
            title (str): Case title
            description (str): Case description
            severity (str): Case severity (low, medium, high, critical)
            tags (list, optional): List of tags
            artifacts (list, optional): List of artifacts
            
        Returns:
            dict: Dictionary mapping SOAR platform names to case IDs
        """
        case_ids = {}
        
        for name, integration in self.integrations.items():
            if integration.enabled:
                try:
                    case_id = integration.create_case(title, description, severity, tags, artifacts)
                    if case_id:
                        case_ids[name] = case_id
                        logger.info(f"Created case in {name} with ID: {case_id}")
                    else:
                        logger.error(f"Failed to create case in {name}")
                except Exception as e:
                    logger.error(f"Error creating case in {name}: {str(e)}")
        
        return case_ids
    
    def update_case_in_all(self, case_ids, updates):
        """
        Update a case in all enabled SOAR platforms.
        
        Args:
            case_ids (dict): Dictionary mapping SOAR platform names to case IDs
            updates (dict): Updates to apply
            
        Returns:
            dict: Dictionary mapping SOAR platform names to success status
        """
        results = {}
        
        for name, case_id in case_ids.items():
            if name in self.integrations and self.integrations[name].enabled:
                try:
                    success = self.integrations[name].update_case(case_id, updates)
                    results[name] = success
                    if success:
                        logger.info(f"Updated case in {name} with ID: {case_id}")
                    else:
                        logger.error(f"Failed to update case in {name} with ID: {case_id}")
                except Exception as e:
                    logger.error(f"Error updating case in {name}: {str(e)}")
                    results[name] = False
        
        return results
    
    def get_case_from_all(self, case_ids):
        """
        Get a case from all enabled SOAR platforms.
        
        Args:
            case_ids (dict): Dictionary mapping SOAR platform names to case IDs
            
        Returns:
            dict: Dictionary mapping SOAR platform names to case data
        """
        results = {}
        
        for name, case_id in case_ids.items():
            if name in self.integrations and self.integrations[name].enabled:
                try:
                    case_data = self.integrations[name].get_case(case_id)
                    results[name] = case_data
                    if case_data:
                        logger.info(f"Retrieved case from {name} with ID: {case_id}")
                    else:
                        logger.error(f"Failed to retrieve case from {name} with ID: {case_id}")
                except Exception as e:
                    logger.error(f"Error retrieving case from {name}: {str(e)}")
                    results[name] = None
        
        return results
    
    def search_cases_in_all(self, query):
        """
        Search for cases in all enabled SOAR platforms.
        
        Args:
            query (dict): Search query
            
        Returns:
            dict: Dictionary mapping SOAR platform names to search results
        """
        results = {}
        
        for name, integration in self.integrations.items():
            if integration.enabled:
                try:
                    search_results = integration.search_cases(query)
                    results[name] = search_results
                    logger.info(f"Found {len(search_results)} cases in {name} matching query")
                except Exception as e:
                    logger.error(f"Error searching cases in {name}: {str(e)}")
                    results[name] = []
        
        return results
    
    def create_task_in_all(self, case_ids, title, description, status="New"):
        """
        Create a task in all enabled SOAR platforms.
        
        Args:
            case_ids (dict): Dictionary mapping SOAR platform names to case IDs
            title (str): Task title
            description (str): Task description
            status (str): Task status
            
        Returns:
            dict: Dictionary mapping SOAR platform names to task IDs
        """
        task_ids = {}
        
        for name, case_id in case_ids.items():
            if name in self.integrations and self.integrations[name].enabled:
                try:
                    task_id = self.integrations[name].create_task(case_id, title, description, status)
                    if task_id:
                        task_ids[name] = task_id
                        logger.info(f"Created task in {name} for case {case_id} with ID: {task_id}")
                    else:
                        logger.error(f"Failed to create task in {name} for case {case_id}")
                except Exception as e:
                    logger.error(f"Error creating task in {name}: {str(e)}")
        
        return task_ids
    
    def execute_playbook_in_all(self, case_ids, playbook_id):
        """
        Execute a playbook in all enabled SOAR platforms.
        
        Args:
            case_ids (dict): Dictionary mapping SOAR platform names to case IDs
            playbook_id (str): Playbook ID
            
        Returns:
            dict: Dictionary mapping SOAR platform names to execution IDs
        """
        execution_ids = {}
        
        for name, case_id in case_ids.items():
            if name in self.integrations and self.integrations[name].enabled:
                try:
                    execution_id = self.integrations[name].execute_playbook(case_id, playbook_id)
                    if execution_id:
                        execution_ids[name] = execution_id
                        logger.info(f"Executed playbook {playbook_id} in {name} for case {case_id} with execution ID: {execution_id}")
                    else:
                        logger.error(f"Failed to execute playbook {playbook_id} in {name} for case {case_id}")
                except Exception as e:
                    logger.error(f"Error executing playbook in {name}: {str(e)}")
        
        return execution_ids


class ThreatResponseWorkflow:
    """Class for automated threat response workflows."""
    
    def __init__(self, config):
        """
        Initialize the threat response workflow.
        
        Args:
            config (dict): Configuration dictionary
        """
        self.config = config
        self.workflow_config = config.get('threat_response', {})
        self.enabled = self.workflow_config.get('enabled', False)
        
        # Initialize SOAR manager
        self.soar_manager = SOARManager(config)
        
        if not self.enabled:
            logger.info("Threat response workflow is disabled")
    
    def run(self, threat_data=None):
        """
        Run the automated threat response workflow.
        
        Args:
            threat_data (list, optional): Threat data for correlation
            
        Returns:
            dict: Workflow results
        """
        if not self.enabled:
            logger.warning("Threat response workflow is disabled")
            return {'enabled': False}
            
        try:
            logger.info("Starting automated threat response workflow")
            
            results = {
                'enabled': True,
                'timestamp': datetime.now().isoformat(),
                'threat_data_count': len(threat_data) if threat_data else 0,
                'cases': {},
                'tasks': {},
                'playbooks': {}
            }
            
            # Check if we have threat data
            if not threat_data:
                logger.warning("No threat data provided for threat response workflow")
                return results
            
            # Group threats by tactic
            threats_by_tactic = {}
            for threat in threat_data:
                tactic = threat.get('tactic_name', 'Unknown')
                if tactic not in threats_by_tactic:
                    threats_by_tactic[tactic] = []
                threats_by_tactic[tactic].append(threat)
            
            # Process each tactic
            for tactic, threats in threats_by_tactic.items():
                # Create case title and description
                title = f"MITRE ATT&CK {tactic} Techniques Detected"
                description = f"The following MITRE ATT&CK techniques associated with the {tactic} tactic have been detected:\n\n"
                
                for threat in threats:
                    description += f"- {threat.get('technique_name', 'Unknown')} ({threat.get('technique_id', 'Unknown')}): {threat.get('description', 'No description')}\n"
                
                # Add recommended actions
                description += "\n## Recommended Actions\n"
                description += f"1. Investigate systems for indicators of {tactic} activities\n"
                description += "2. Review logs for suspicious activities related to the detected techniques\n"
                description += "3. Implement countermeasures for the detected techniques\n"
                
                # Create tags
                tags = ['mitre', 'threat_intel', f"tactic:{tactic}"]
                tags.extend([f"technique:{t.get('technique_id', 'unknown')}" for t in threats])
                
                # Create artifacts for the techniques
                artifacts = []
                for threat in threats:
                    artifacts.append({
                        'type': 'technique',
                        'value': threat.get('technique_id', 'Unknown'),
                        'description': threat.get('description', ''),
                        'tags': ['mitre', 'technique'],
                        'ioc': False
                    })
                
                # Create cases in all enabled SOAR platforms
                case_ids = self.soar_manager.create_case_in_all(
                    title,
                    description,
                    'medium',  # Default severity
                    tags,
                    artifacts
                )
                
                # Store case IDs in results
                results['cases'][tactic] = case_ids
                
                # Create tasks for each case
                if case_ids:
                    # Create investigation task
                    task_ids = self.soar_manager.create_task_in_all(
                        case_ids,
                        f"Investigate {tactic} Techniques",
                        f"Investigate systems for indicators of {tactic} activities related to the detected techniques.",
                        "New"
                    )

                    # Store task IDs in results
                    results['tasks'][tactic] = task_ids
                    
                    # Execute playbook for each case
                    execution_ids = self.soar_manager.execute_playbook_in_all(
                        case_ids,
                        'mitre_investigation'  # Default playbook ID
                    )
                    
                    # Store execution IDs in results
                    results['playbooks'][tactic] = execution_ids
            
            logger.info(f"Completed threat response workflow for {len(threats_by_tactic)} tactics")
            return results
            
        except Exception as e:
            logger.error(f"Error running threat response workflow: {str(e)}")
            return {
                'enabled': True,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def get_status(self, case_ids):
        """
        Get the status of cases created by the workflow.
        
        Args:
            case_ids (dict): Dictionary mapping tactics to case IDs
            
        Returns:
            dict: Status information
        """
        if not self.enabled:
            logger.warning("Threat response workflow is disabled")
            return {'enabled': False}
            
        try:
            status = {
                'enabled': True,
                'timestamp': datetime.now().isoformat(),
                'cases': {}
            }
            
            # Get status for each tactic
            for tactic, tactic_case_ids in case_ids.items():
                status['cases'][tactic] = self.soar_manager.get_case_from_all(tactic_case_ids)
            
            return status
            
        except Exception as e:
            logger.error(f"Error getting threat response workflow status: {str(e)}")
            return {
                'enabled': True,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def update_cases(self, case_ids, updates):
        """
        Update cases created by the workflow.
        
        Args:
            case_ids (dict): Dictionary mapping tactics to case IDs
            updates (dict): Updates to apply
            
        Returns:
            dict: Update results
        """
        if not self.enabled:
            logger.warning("Threat response workflow is disabled")
            return {'enabled': False}
            
        try:
            results = {
                'enabled': True,
                'timestamp': datetime.now().isoformat(),
                'updates': {}
            }
            
            # Update cases for each tactic
            for tactic, tactic_case_ids in case_ids.items():
                results['updates'][tactic] = self.soar_manager.update_case_in_all(tactic_case_ids, updates)
            
            return results
            
        except Exception as e:
            logger.error(f"Error updating threat response workflow cases: {str(e)}")
            return {
                'enabled': True,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
