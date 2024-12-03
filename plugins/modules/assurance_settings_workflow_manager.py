#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module to perform operations on global pool, reserve pool and network in Cisco Catalyst Center."""
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = ['Muthu Rakesh, Madhan Sankaranarayanan, Megha Kandari']

DOCUMENTATION = r"""
---
module: assurance_settings_workflow_manager
short_description: Resource module for managing assurance settings and issue resolution in Cisco Catalyst Center
description: This module allows the management of assurance settings and issues in Cisco DNA Center. 
- It supports creating, updating, and deleting configurations for issue settings, health scores, ICAP settings, path trace, and other network assurance functionalities. 
- This module interacts with Cisco DNA Center's Assurance settings to configure thresholds, rules, KPIs, and more for health score monitoring and issue resolution.
version_added: '6.6.0'
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author: Madhan Sankaranarayanan (@madhansansel)
options:
  config_verify:
    description: Set to `True` to enable configuration verification on Cisco DNA Center after applying the playbook config. This will ensure that the system validates the configuration state after the change is applied.
    type: bool
    default: False
  state:
    description: Specifies the desired state for the configuration. If `merged`, the module will create or update the configuration, adding new settings or modifying existing ones. If `deleted`, it will remove the specified settings.
    type: str
    choices: ["merged", "deleted"]
    default: merged
 config:
    description: A list of settings and parameters to be applied. It consists of different sub-configurations for managing assurance settings such as issue settings, health score, ICAP settings, path trace, issue resolution, and command execution.
    type: list
    elements: dict
    required: true
    suboptions:
      assurance_user_defined_issue_settings:
        description: Manages the issue settings for assurance in Cisco DNA Center. You can configure the name, description, severity, priority, and rules that govern network issues.
        type: list
        elements: dict
        suboptions:
          - name:
              description: The name of the issue setting, used for identification in the system. Required when creating a new setting or updating an existing one.
              type: str
              required: true
          - description:
              description: A text description for the issue. Helps to explain the nature of the issue for clarity in reports and dashboards.
              type: str
          - rules:
              description: A set of rules that define the parameters for triggering the issue. It includes severity, facility, mnemonic, pattern, occurrences, and duration.
              type: list
              elements: dict
              suboptions:
                - severity:
                    description: The severity level of the issue. Common values are 1 (Critical) to 5 (Informational).
                    type: int
                - facility:
                    description: The facility type that the rule applies to. This could refer to a system component like redundancy or power.
                    type: str
                - mnemonic:
                    description: A mnemonic value representing the issue, which could be a system-generated identifier or label for the issue.
                    type: str b
                - pattern:
                    description: The pattern or regular expression used to detect the issue.
                    type: str
                - occurrences:
                    description: The number of times the issue pattern must occur to trigger the issue.
                    type: int
                - duration_in_minutes:
                    description: The duration, in minutes, for which the issue pattern must persist to be considered valid.
                    type: int
          - is_enabled:
              description: Boolean value to enable or disable the issue setting.
              type: bool
          - priority:
              description: Specifies the priority of the issue. Typically, values are "P1", "P2", "P3", etc.
              type: str
          - is_notification_enabled:
              description: Boolean value to specify if notifications for this issue setting should be enabled.
              type: bool
          - prev_name:
              description: The previous name of the issue setting (used when updating an existing issue setting).
              type: str
      assurance_healthscore:
        description: Configures the health score settings for network devices. Defines thresholds for KPIs like CPU utilization, memory, etc.
        type: list
        elements: dict
        suboptions:
          - kpi_name:
              description: The name of the Key Performance Indicator (KPI) to be monitored (e.g., cpu_utilization_threshold).
              type: str
          - device_family:
              description: Specifies the device family to which the health score applies (e.g., switches, routers, hubs).
              type: str
          - include_for_overall_health:
              description: Boolean value indicating whether this KPI should be included in the overall health score calculation.
              type: bool
          - threshold_value:
              description: The threshold value that, when exceeded, will affect the health score.
              type: int
          - synchronize_to_issue_threshold:
              description: Boolean value indicating whether the threshold should synchronize with issue resolution thresholds.
              type: bool
      assurance_icap_settings:
        description: Configures ICAP settings for capturing client and network device information for onboarding and monitoring.
        type: list
        elements: dict
        suboptions:
          - captureType:
              description: The type of ICAP capture to be performed (e.g., onboarding).
              type: str
          - durationInMins:
              description: The duration of the ICAP capture session in minutes.
              type: int
          - clientMac:
              description: The MAC address of the client device for which the capture is being performed.
              type: str
          - wlcId:
              description: The ID of the Wireless LAN Controller (WLC) involved in the ICAP capture.
              type: str
          - apId:
              description: The ID of the Access Point (AP) for the capture.
              type: str
          - slot:
              description: List of slot numbers for the capture session.
              type: list
              elements: int
          - otaBand:
              description: The OTA band (e.g., 5GHz, 2.4GHz) for the capture.
              type: str
          - otaChannel:
              description: The OTA channel (e.g., 36, 40) for the capture.
              type: int
          - otaChannelWidth:
              description: The width of the OTA channel (e.g., 20MHz, 40MHz).
              type: int
      assurance_pathtrace:
        description: Configures network path trace settings for monitoring the paths between source and destination IP addresses.
        type: list
        elements: dict
        suboptions:
          - sourceIP:
              description: The source IP address for the path trace. This is a required field.
              type: str
          - destIP:
              description: The destination IP address for the path trace. This is a required field.
              type: str
          - controlPath:
              description: Boolean value to specify whether the path trace should include the control path (optional).
              type: bool
          - destPort:
              description: The destination port for the path trace (optional).
              type: str
          - inclusions:
              description: A list of optional inclusions for the path trace, such as QOS statistics or additional details.
              type: list
              elements: str
          - periodicRefresh:
              description: Boolean value to enable periodic refresh for the path trace.
              type: bool
          - protocol:
              description: The protocol to use for the path trace, e.g., TCP, UDP (optional).
              type: str
          - sourcePort:
              description: The source port for the path trace (optional).
              type: str
      assurance_issue_resolution:
        description: List of issues to resolve in the assurance system. These issues are identified by their issue names.
        type: list
        elements: dict
        suboptions:
          - issue_name:
              description: The name of the issue to be resolved.
              type: str
      assurance_ignore_issue:
        description: List of issues to be ignored in the assurance system. These issues are identified by their issue names.
        type: list
        elements: dict
        suboptions:
          - issue_name:
              description: The name of the issue to be ignored.
              type: str
      assurance_execute_suggested_commands:
        description: Executes suggested commands for network devices as part of the issue resolution process.
        type: list
        elements: dict
        suboptions:
          - entity_type:
              description: The type of entity (e.g., Networkdevice, Switch, etc.) for which the command is being executed.
              type: str
          - entity_value:
              description: The value associated with the entity (e.g., device name or ID).
              type: str      
requirements:
- dnacentersdk >= 2.9.3
- python >= 3.9
notes:
 - SDK Method used are
    issues.AssuranceSettings.get_all_the_custom_issue_definitions_based_on_the_given_filters,
    issues.AssuranceSettings.creates_a_new_user_defined_issue_definitions,
    issues.AssuranceSettings.deletes_an_existing_custom_issue_definition,
    issues.AssuranceSettings.resolve_the_given_lists_of_issues,
    issues.AssuranceSettings.ignore_the_given_list_of_issues,
    issues.AssuranceSettings.execute_suggested_action_commands,
    sensors.AssuranceSettings.get_icap_configuration_status_per_network_device,
    sensors.AssuranceSettings.get_device_deployment_status_count,
    sensors.AssuranceSettings.creates_an_icap_configuration_intent_for_preview_approve,
    sensors.AssuranceSettings.discards_the_icap_configuration_intent_by_activity_id,
    path_trace.AssuranceSettings.retrieves_all_previous_pathtraces_summary,
    path_trace.AssuranceSettings.initiate_a_new_pathtrace,
    path_trace.AssuranceSettings.delete_pathtrace_by_id,
    devices.AssuranceSettings.get_all_healthscore_definitions_for_given_filters,
    devices.AssuranceSettings.update_health_score_definitions

 - Paths used are
    post /dna/intent/api/api/v1/customIssueDefinitions,
    post/ dna/intent/api/v1/assuranceIssues/resolve
    post/ dna/intent/api/v1/execute-suggested-actions-commands
    post/ /dna/intent/api/v1/assuranceIssues/ignore
    post /dna/intent/api/v1/healthScoreDefinitions/${id},
    post /dna/intent/api/v1/flow-analysis/${flowAnalysisId},
    post /dna/intent/api/v1/flow-analysis,
    post /dna/intent/api/v1/healthScoreDefinitions/bulkUpdate
    put /dna/intent/api/v1/systemIssueDefinitions/${id}
    post /dna/intent/api/v1/assuranceIssues/resolve
    delete /dna/intent/api/v1/flow-analysis/{flowAnalysisId}
    delete /dna/intent/api/v1/customIssueDefinitions/{id}
    delete /dna/intent/api/v1/flow-analysis/{flowAnalysisId}
  """ 


EXAMPLES = r"""
---
- hosts: dnac_servers
  vars_files:
    - credentials.yml
  gather_facts: no
  connection: local
  tasks:
    - name: Create issue settings
      cisco.dnac.assurance_settings_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log: True
        dnac_log_level: DEBUG
        dnac_log_append: True
        state: merged
        config_verify: True
        config:
        - assurance_user_defined_issue_settings:
          - name: “test"
            description: “testing"
            rules:
              - severity: 5
                facility: “redundancy"
                mnemonic: “peer monitor event"
                pattern: “issue test"
                occurrences: 1
                duration_in_minutes: 2
            is_enabled: false
            priority: “P1"
            is_notification_enabled: false

    - name: update issue settings
      cisco.dnac.assurance_settings_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log: True
        dnac_log_level: DEBUG
        dnac_log_append: True
        state: merged
        config_verify: True
        config:
        - assurance_user_defined_issue_settings:
          - prv_name: “test”
            name: “test issue"
            description: “testing"
            rules:
              - severity: 5
                facility: “redundancy"
                mnemonic: “peer monitor event"
                pattern: “issue test"
                occurrences: 1
                duration_in_minutes: 2
            is_enabled: false
            priority: “P1"
            is_notification_enabled: false

    - name: Delete issue settings
      cisco.dnac.assurance_settings_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log_level: DEBUG
        dnac_log: True
        state: deleted
        config_verify: True
        config:
        - assurance_user_defined_issue_settings:
          - name: “test"         
---
- hosts: dnac_servers
  vars_files:
    - credentials.yml
  gather_facts: no
  connection: local
  tasks:
    - name: Update healthscore and threshold settings
      cisco.dnac.assurance_health_threshold_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log: true
        dnac_log_level: debug
        dnac_log_append: true
        state: merged
        config_verify: true
        config:
        - assurance_healthscore:
          - kpi_name: cpu_utilization_threshold #required field
            device_family: switch and hubs #required field
            include_for_overall_health: true
            threshold_value: 90
            synchronize_to_issue_threshold: false

---
  - hosts: dnac_servers
    vars_files:
      - credentials.yml
    gather_facts: no
    connection: local
    tasks:
      - name: Create icap settings
        cisco.dnac.assurance_health_threshold_workflow_manager:
          dnac_host: "{{ dnac_host }}"
          dnac_port: "{{ dnac_port }}"
          dnac_username: "{{ dnac_username }}"
          dnac_password: "{{ dnac_password }}"
          dnac_verify: "{{ dnac_verify }}"
          dnac_debug: "{{ dnac_debug }}"
          dnac_version: "{{ dnac_version }}"
          dnac_log: true
          dnac_log_level: debug
          dnac_log_append: true
          state: merged
          config_verify: true
          config:
            - assurance_icap_settings:
                - captureType: "onboarding"
                  durationInMins: 30
                  clientMac: "client_mac_id" #required field
                  wlcId: "wlc_id" #required field
                  apId: "ap_id" #required field
                  slot:
                    - 1
                    - 2
                  otaBand: "5GHz"
                  otaChannel: 36
                  otaChannelWidth: 20

---
- hosts: dnac_servers
  vars_files:
    - credentials.yml
  gather_facts: no
  connection: local
  tasks:
    - name: Resolving Issues
      cisco.dnac.assurance_settings_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log: true
        dnac_log_level: debug
        dnac_log_append: true
        state: merged
        config_verify: true
        config:
          - assurance_issue_resolution:
              - issue_name: "issue_1" #required field
              - issue_name: "issue_2"

    - name: Ignoring issues
      cisco.dnac.assurance_settings_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log: true
        dnac_log_level: debug
        dnac_log_append: true        
        state: merged
        config_verify: true
        config:
          - assurance_ignore_issue:
               - issue_name: "issue_1" #required field
               - issue_name: "issue_2"

    - name: Execute suggested commands
      cisco.dnac.assurance_settings_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log: true
        dnac_log_level: debug
        dnac_log_append: true
        state: merged
        config_verify: true
        config:
          - assurance_execute_suggested_commands:
              - entity_type: "string" #required field
                entity_value: "Networkdevice" #required field         

- hosts: dnac_servers
  vars_files:
    - credentials.yml
  gather_facts: no
  connection: local
  tasks:
    - name: Create path trace
      cisco.dnac.assurance_settings_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log: true
        dnac_log_level: DEBUG
        dnac_log_append: true
        state: merged
        config_verify: true
        config:
        - assurance_pathtrace:
          sourceIP: "204.1.2.4" #required field
          destIP: "204.192.6.200" #required field
          controlPath: false #optional field
          destPort: "80"
          inclusions: 
            - "QOS-STATS"
          periodicRefresh: true
          protocol: "TCP"
          sourcePort: "443"

    - name: Delete path trace by id
      cisco.dnac.path_trace_workflow_manager:
        dnac_host: "{{ dnac_host }}"
        dnac_port: "{{ dnac_port }}"
        dnac_username: "{{ dnac_username }}"
        dnac_password: "{{ dnac_password }}"
        dnac_verify: "{{ dnac_verify }}"
        dnac_debug: "{{ dnac_debug }}"
        dnac_version: "{{ dnac_version }}"
        dnac_log_level: DEBUG
        dnac_log: true
        state: deleted
        config_verify: true
        config: 
        - assurance_pathtrace:
        - sourceIP: "204.1.2.4" #required field
          destIP: "204.192.6.200" #required field
     """

RETURN = r"""

#Case 1: Successful creation of issue
Response: create
{
    "response": {
        "id": "string",
        "name": "string",
        "description": "string",
        "profileId": "string",
        "triggerId": "string",
        "rules": [
            {
                "type": "string",
                "severity": "integer",
                "facility": "string",
                "mnemonic": "string",
                "pattern": "string",
                "occurrences": "integer",
                "durationInMinutes": "integer"
            }
        ],
        "isEnabled": "boolean",
        "priority": "string",
        "isDeletable": "boolean",
        "isNotificationEnabled": "boolean",
        "createdTime": "integer",
        "lastUpdatedTime": "integer"
    }
}
 
#Case 2: Successful updation of issue 
Response: update
{
    "response": {
        "id": "string",
        "name": "string",
        "description": "string",
        "profileId": "string",
        "triggerId": "string",
        "rules": [
            {
                "type": "string",
                "severity": "integer",
                "facility": "string",
                "mnemonic": "string",
                "pattern": "string",
                "occurrences": "integer",
                "durationInMinutes": "integer"
            }
        ],
        "isEnabled": "boolean",
        "priority": "string",
        "isDeletable": "boolean",
        "isNotificationEnabled": "boolean",
        "createdTime": "integer",
        "lastUpdatedTime": "integer"
    }
}

#Case 3: Successful deletion of issue
Response: Delete
" "

#Case 4: Successful updation of healthcare
Response: Update
{
    "response": {
        "id": "string",
        "name": "string",
        "displayName": "string",
        "deviceFamily": "string",
        "description": "string",
        "includeForOverallHealth": "boolean",
        "definitionStatus": "string",
        "thresholdValue": "number",
        "synchronizeToIssueThreshold": "boolean",
        "lastModified": "string"
    },
    "version": "string"
}

#Case 5: Successful creation of trace path
Response: Create
{
    "response": {
        "flowAnalysisId": "string",
        "taskId": "string",
        "url": "string"
    },
    "version": "string"
}

#Case 6: Successful deletion of trace path
Response: Delete
{
    "response": {
        "taskId": "any",
        "url": "string"
    },
    "version": "string"
}

#Case 7: Successful deletion of trace path
Response: Delete
{
    "response": {
        "taskId": "any",
        "url": "string"
    },
    "version": "string"
}

#Case 8: Successful creation of Icap settings
Response: Create
{
     "response": { 
         "taskId": "string",
          "url": "string"
},
"version": "string"
}

#Case 9: Successful deletion of Icap settings
Response: delete
{
      "response": { 
          "taskId": "string",
           "url": "string"
},
"version": "string"
}

#Case 10: Successfully Resolved issue
Response: Update
{
    "response": {
        "successfulIssueIds": [
            "string"
        ],
        "failureIssueIds": [
            "string"
        ]
    },
    "version": "string"}

#Case 11: Successfully ignored issue
Response: Update
{
    "response": {
        "successfulIssueIds": [
            "string"
        ],
        "failureIssueIds": [
            "string"
        ]
    },
    "version": "string"
}

#Case 12: Successfully executed commands of issue
Response: Update
[
    {
        "actionInfo": "string",
        "stepsCount": "integer",
        "entityId": "string",
        "hostname": "string",
        "stepsDescription": "string",
        "command": "string",
        "commandOutput": {}
    }
]
"""

import copy
import re
import time
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
    get_dict_result,
    dnac_compare_equality,
)


class AssuranceSettings(DnacBase):
    """Class containing member attributes for Assurance setting workflow manager module"""

    def __init__(self, module):
        super().__init__(module)
        self.result["response"] = [
            {"assurance_user_defined_issue_settings": {"response": {}, "msg": {}}},
            {"assurance_system_issue_settings": {"response": {}, "msg": {}}},
            {"assurance_healthscore": {"response": {}, "msg": {}}}
        ]
        self.supported_states = ["merged", "deleted"]
        self.create_issue, self.update_issue, self.no_update_issue = [], [], []

    def validate_input(self):
        """
        Validate the fields provided in the playbook.
        Checks the configuration provided in the playbook against a predefined specification
        to ensure it adheres to the expected structure and data types.

        Parameters:
            self: The instance of the class containing the 'config' attribute to be validated.

        Returns:
            The method updates these attributes of the instance:
                - self.msg: A message describing the validation result.
                - self.status: The status of the validation ('success' or 'failed').
                - self.validated_config: If successful, a validated version of the 'config' parameter.
        """

        # Specification for validation
        temp_spec = {
            'assurance_user_defined_issue_settings': {
                'type': 'list',
                'elements': 'dict',
                'name': {'type': 'str', 'required': True},
                'description': {'type': 'str'},
                'rules': {
                    'type': 'list',
                    'elements': 'dict',
                    'severity': {'type': 'int','choices': [0,1,2,3,4,5,6], 'required': True},
                    'facility': {'type': 'str'},
                    'mnemonic': {'type': 'str'},
                    'pattern': {'type': 'str', 'required': True},
                    'occurrences': {'type': 'int'},
                    'duration_in_minutes': {'type': 'int'}
                },
                'is_enabled': {'type': 'bool', 'default': True},
                'priority': {'type': 'str', 'choices': ['P1', 'P2', 'P3', 'P4']},
                'is_notification_enabled': {'type': 'bool', 'default': False},
                'prev_name': {'type': 'str'}
            },
            'assurance_healthscore': {
                'type': 'list',
                'elements': 'dict',
                'kpi_name': {'type': 'str', 'required': True},
                'device_family': {'type': 'str', 'required': True},
                'include_for_overall_health': {'type': 'bool', 'required': True},
                'threshold_value': {'type': 'int', 'required': False},
                'synchronize_to_issue_threshold': {'type': 'bool', 'required': False}
            }
        }

        if not self.config:
            self.msg = "The playbook configuration is empty or missing."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        # Validate configuration against the specification
        valid_temp, invalid_params = validate_list_of_dicts(self.config, temp_spec)

        if invalid_params:
            self.msg = "The playbook contains invalid parameters: {0}".format(
                invalid_params)
            self.result['response'] = self.msg
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        self.validated_config = valid_temp
        self.msg = "Successfully validated playbook configuration parameters using 'validate_input': {0}".format(
            str(valid_temp))
        self.log(self.msg, "INFO")

        return self

    def assurance_obj_params(self, get_object):
        """
        Get the required comparison obj_params value

        Parameters:
            get_object (str) - identifier for the required obj_params

        Returns:
            obj_params (list) - obj_params value for comparison.
        """

        try:
            if get_object == "assurance_user_defined_issue_settings":
                obj_params = [
                    ("name", "name"),
                    ("description", "description"),
                    ("rules", "rules"),
                    ("is_enabled", "is_enabled"),
                    ("priority", "priority"),
                    ("is_notification_enabled", "is_notification_enabled")
                ]
            elif get_object == "assurance_system_issue_settings":
                obj_params = [
                    ("name", "name"),
                    ("synchronizeToHealthThreshold", "synchronizeToHealthThreshold"),
                    ("priority", "priority"),
                    ("issueEnabled", "issueEnabled"),
                    ("thresholdValue", "thresholdValue"),
                ]
            elif get_object == "assurance_healthscore":
                obj_params = [
                    ("kpi_name", "kpi_name"),
                    ("device_family", "device_family")
                    ("include_for_overall_health", "include_for_overall_health"),
                    ("threshold_value", "threshold_value")
                    ("synchronize_to_issue_threshold", "synchronize_to_issue_threshold")
                ]
            else:
                raise ValueError("Received an unexpected value for 'get_object': {0}"
                                 .format(get_object))
        except Exception as msg:
            self.log("Received exception: {0}".format(msg), "CRITICAL")

        return obj_params

    def get_want(self, config):
        """
        Retrieve and store import, tagging, distribution, and activation details from playbook configuration.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): The configuration dictionary containing image import and other details.
        Returns:
            self: The current instance of the class with updated 'want' attributes.
        Raises:
            AnsibleFailJson: If an incorrect import type is specified.
        Description:
            This function parses the playbook configuration to extract information related to image
            import, tagging, distribution, and activation. It stores these details in the 'want' dictionary
            for later use in the Ansible module.
        """
        self.log(config)
        want = {}
        want["assurance_user_defined_issue_settings"] = config.get("assurance_user_defined_issue_settings")
        want["assurance_system_issue_settings"] = config.get("assurance_system_issue_settings")
        want["assurance_healthscore"] = config.get("assurance_healthscore")

        self.want = want
        self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

        return self

    def get_have(self, config):
        """
        Get the current Global Pool Reserved Pool and Network details from Cisco Catalyst Center

        Parameters:
            config (dict) - Playbook details containing Global Pool,
            Reserved Pool, and Network Management configuration.

        Returns:
            self - The current object with updated Global Pool,
            Reserved Pool, and Network information.
        """
        # self.log(config)
        assurance_user_defined_issue_details = config.get("assurance_user_defined_issue_settings")
        assurance_system_issue_details = config.get("assurance_system_issue_settings")
        assurance_healthscore_details = config.get("assurance_healthscore")

        if assurance_user_defined_issue_details is not None:
            self.get_have_assurance_user_issue(assurance_user_defined_issue_details).check_return_status()

        # if assurance_system_issue_details is not None:
        #     self.get_have_assurance_issue(assurance_system_issue_details).check_return_status()
        
        # if assurance_healthscore_details is not None:
        #     self.get_have_assurance_healthscore(assurance_healthscore_details)

        self.log("Current State (have): {0}".format(self.have), "INFO")
        self.msg = "Successfully retrieved the details from the system"
        self.status = "success"
        return self

    def get_have_assurance_healthscore(self, assurance_healthscore_details):
        """
        Get the current Global Pool Reserved Pool and Network details from Cisco Catalyst Center

        Parameters:
            config (dict) - Playbook details containing Global Pool,
            Reserved Pool, and Network Management configuration.

        Returns:
            self - The current object with updated Global Pool,
            Reserved Pool, and Network information.
        """
        assurance_healthscore = []

    def assurance_issues_exists(self, name):
        """
        Check if the Assurance issues with the given name exists

        Parameters:
            name (str) - The name of the Assurance issues to check for existence

        Returns:
            dict - A dictionary containing information about the Global Pool's existence:
            - 'exists' (bool): True if the Assurance issues exists, False otherwise.
            - 'id' (str or None): The ID of the Global Pool if it exists, or None if it doesn't.
            - 'details' (dict or None): Details of the Global Pool if it exists, else None.
        """
        self.log(name)
        assurance_issue = {
            "exists": False,
            "assurance_issue_details": None,
            "id": None
        }
        value = 1
        while True:
            try:
                response = self.dnac._exec(
                    family="issues",
                    function= "get_all_the_custom_issue_definitions_based_on_the_given_filters",
                    params={"name":name}
            )
                self.log(response)
            except Exception as msg:
                match = re.search(r'status_code:\s*(\d+)', str(msg))
                if match and int(match.group(1)) == 404:
                    return  {'response': [], 'message': 'There is no assurance issue present in the system for the given input.'}
                 
                else:
                    self.msg = (
                    "Exception occurred while getting the assurance issue details with name '{name}': {msg}" .format(
                        name=name, msg=msg))
                    self.log(str(msg), "ERROR")
                    self.status = "failed"
                    return self

            if not isinstance(response, dict):
                self.msg = "Failed to retrieve the assurance issue details - Response is not a dictionary"
                self.log(self.msg, "CRITICAL")
                self.status = "failed"
                return self.check_return_status()

            all_assurance_issue_details = response.get("response")
            assurance_issue_details = get_dict_result(
                all_assurance_issue_details, "ipPoolName", name)
            if assurance_issue_details: 
                self.log("Assurance issue found with name '{0}': {1}".format(
                    name, assurance_issue_details), "INFO")
                assurance_issue.update({"exists": True})
                assurance_issue.update({"id": assurance_issue_details.get("id")})
                assurance_issue["assurance_issue_details"] = assurance_issue_details
                break


        self.log("Formatted assurance issue details: {0}".format(
            assurance_issue), "DEBUG")
        return assurance_issue

    def get_have_assurance_user_issue(self, assurance_user_defined_issue_settings):
        """
        Get the current Global Pool information from
        Cisco Catalyst Center based on the provided playbook details.
        check this API using check_return_status.

        Parameters:
            global_pool_details (dict) - Playbook details containing Global Pool configuration.

        Returns:
            self - The current object with updated information.
        """
        Assurance_issue = []
        Assurance_issue_index = 0
        for issues_setting in assurance_user_defined_issue_settings:
            name = issues_setting.get("name")
            if name is None:
                self.msg = "Missing required parameter 'name' in assurance_user_defined_issue_settings"
                self.status = "failed"
                return self

            name_length = len(name)
            if name_length > 100:
                self.msg = "The length of the '{0}' in assurance_user_defined_issue_settings should be less or equal to 100. Invalid_config: {1}".format(
                    name, issues_setting)
                self.status = "failed"
                return self

            if " " in name:
                self.msg = "The 'name' in assurance_user_defined_issue_settings should not contain any spaces."
                self.status = "failed"
                return self

            pattern = r'^[\w\-./]+$'
            if not re.match(pattern, name):
                self.msg = "The 'name' in assurance_user_defined_issue_settings should contain only letters, numbers and -_./ characters."
                self.status = "failed"
                return self

            # If the Assurance issue doesn't exist and a previous name is provided
            # Else try using the previous name
            Assurance_issue.append(self.assurance_issues_exists(name))
            self.log(Assurance_issue[0])
            # self.log(Assurance_issue_index)
           
            self.log("Assurance issue details of '{0}': {1}".format(
                name, Assurance_issue[Assurance_issue_index]), "DEBUG")
            prev_name = issues_setting.get("prev_name")
            self.log(prev_name)
            if Assurance_issue[Assurance_issue_index].get("exists") is False and \
                    prev_name is not None:
                Assurance_issue.pop()
                Assurance_issue.append(self.assurance_issue_exists(prev_name))
                if Assurance_issue[Assurance_issue_index].get("exists") is False:
                    self.msg = "Prev name {0} doesn't exist in global_pool_details".format(
                        prev_name)
                    self.status = "failed"
                    return self

                Assurance_issue[Assurance_issue_index].update({"prev_name": name})
            Assurance_issue_index += 1

        self.log("Assurance issue details: {0}".format(Assurance_issue), "DEBUG")
        self.have.update({"assurance_user_defined_issue_settings": Assurance_issue})
        self.msg = "Collecting the assurance issue details from the Cisco Catalyst Center"
        return self

    def get_diff_merged(self, config):
        """
        Update or create Global Pool, Reserve Pool, and
        Network configurations in Cisco Catalyst Center based on the playbook details

        Parameters:
            config (list of dict) - Playbook details containing
            Global Pool, Reserve Pool, and Network Management information.

        Returns:
            self - The current object with Global Pool, Reserved Pool, Network Servers information.
        """
        assurance_user_defined_issue_details = config.get("assurance_user_defined_issue_settings")
        if assurance_user_defined_issue_details is not None:
            self.create_assurance_issue(assurance_user_defined_issue_details).check_return_status()

        return self
    
    def create_assurance_issue(self, assurance_details):
        """
        Update/Create Global Pool in Cisco Catalyst Center with fields provided in playbook

        Parameters:
            global_pool (list of dict) - Global Pool playbook details

        Returns:
            self - The current object with Global Pool, Reserved Pool, Network Servers information.
        """

        create_assurance_issue = []
        update_assurance_issue = []
        assurance_index = 0
        result_assurance_issue = self.result.get("response")[0].get("assurance_user_defined_issue_settings")
        # self.log(result_assurance_issue)
        # self.log(result_assurance_issue.get("msg"))
        want_assurance_issue = self.want.get("assurance_user_defined_issue_settings")
        self.log(want_assurance_issue[assurance_index])
        self.log(want_assurance_issue[assurance_index].get("name"))
        self.log("Assurance issue playbook details: {0}".format(
            assurance_details), "DEBUG")
        for item in self.have.get("assurance_user_defined_issue_settings"):
            result_assurance_issue.get("msg").update(
                {want_assurance_issue[assurance_index].get("name"): {}})
            if item.get("exists") is True:
                update_assurance_issue.append(want_assurance_issue[assurance_index])
            else:
                create_assurance_issue.append(want_assurance_issue[assurance_index])

            assurance_index += 1

        # Check create_global_pool; if yes, create the global pool
        # if create_assurance_issue:
        for issue in create_assurance_issue:
            self.log("Assurance issue(s) details to be created: {0}".format(
                issue), "INFO")  
            user_issue_params = {
                "name": issue.get("name"),
                "description": issue.get("description"),
                "rules": [
                    {
                        "severity": rule.get("severity"),
                        "facility": rule.get("facility"),
                        "mnemonic": rule.get("mnemonic"),
                        "pattern": rule.get("pattern"),
                        "occurrences": rule.get("occurrences"),
                        "durationInMinutes": rule.get("duration_in_minutes")
                    }
                    for rule in issue.get("rules", [])
                ],
                "isEnabled": issue.get("is_enabled"),
                "priority": issue.get("priority"),
                "isNotificationEnabled": issue.get("is_notification_enabled")
            }

            try:
                response = self.dnac._exec(
                    family="issues",
                    function="creates_a_new_user_defined_issue_definitions",
                    op_modifies=True,
                    params= user_issue_params
                )
            except Exception as msg:
                self.msg = (
                    "Exception occurred while creating the user defined issue: {msg}"
                    .format(msg=msg)
                )
                self.log(str(msg), "ERROR")
                self.status = "failed"
                return self

            if response.get("response"):
                response_data = response.get("response")
                if "name" in response_data:
                    self.log(
                        "Successfully created user defined issue with these details: {0}"
                        .format(response_data),
                        "INFO"
                    )
                # for item in issue:
                #     name = item.get("name")
                #     self.log(
                #         "User Defined Issue '{0}' created successfully.".format(name),
                #         "INFO")
                    result_assurance_issue.get("response").update(
                        {"created": issue})
                    result_assurance_issue.get("msg").update(
                        {response_data.get("name"): "User Defined Issue Created Successfully"})

        if update_assurance_issue:
            self.update_user_defined_issue(assurance_details, update_assurance_issue)

        self.msg =(
            "user defined issues operation completed successfully.",
            "INFO")
        self.status = "Success"
        return self

    def update_user_defined_issue(self, assurance_details, update_assurance_issue):
        # if update_assurance_issue:
            result_assurance_issue = self.result.get("response")[0].get("assurance_user_defined_issue_settings")
            final_update_user_defined_issue = []
        #     # Pool exists, check update is required
            for item in update_assurance_issue:
                name = item.get("name")
                for issue in self.have.get("assurance_user_defined_issue_settings"):
                    if issue.get("exists") and (issue.get("assurance_issue_details").get(
                            "name") == name or issue.get("prev_name") == name):
                        # have_assurance_user_issue = self.have.get("assurance_user_defined_issue_settings")
                        self.log(issue.get("assurance_issue_details"))
                        # issue.get("assurance_issue_details").pop("rules")
                        # want_assurance_user_issue = self.want.get("assurance_user_defined_issue_settings")
                        self.log(item)
                        # item.pop("rules")
                        user_issue_obj_params = self.assurance_obj_params("assurance_user_defined_issue_settings")
                        if not self.requires_update(issue.get("assurance_issue_details"), item, user_issue_obj_params):
                        # if not self.requires_update(
                        #         issue.get("details"), item, self.global_pool_obj_params):
                            self.log(
                                "Assurance issue '{0}' doesn't require an update".format(name), "INFO")
                            result_assurance_issue.get("msg").update(
                                {name: "Assurance issue doesn't require an update"})
                        elif item not in final_update_user_defined_issue:
                            final_update_user_defined_issue.append(item)

            # if final_update_user_defined_issue:
            self.log(final_update_user_defined_issue)
            for issue in final_update_user_defined_issue:
                # self.log("User defined issues requires update", "INFO")
                # self.log(issue)
                # for item in self.want.get("assurance_user_defined_issue_settings"):
                #     if item.get("name") == issue.get(name):
                #         name = item.get("name")

                # if issue.get("prev_name"):
                #     name = issue.get("prev_name")
                # else:
                #     name = issue.get("name")
                for id in self.have.get("assurance_user_defined_issue_settings"):
                    # userdefined issue(s) needs update
                    self.log(id.get("id"))
                    user_issue_params = {
                        # "id": id.get("id"), 
                                        "id": "3475ce45-368c-452e-8f7a-6e96b220e42a",
                                        "payload":
                                        {
                                            "name": issue.get("name"),
                                            #  "name": "MAC_newname",
                                            "description": issue.get("description"),
                                            "rules": [
                                                {
                                                    "severity": rule.get("severity"),
                                                    "facility": rule.get("facility"),
                                                    "mnemonic": rule.get("mnemonic"),
                                                    "pattern": rule.get("pattern"),
                                                    "occurrences": rule.get("occurrences"),
                                                    "durationInMinutes": rule.get("duration_in_minutes")
                                                }
                                                for rule in issue.get("rules", [])
                                            ],
                                            "isEnabled": issue.get("is_enabled"),
                                            "priority": issue.get("priority"),
                                            "isNotificationEnabled": issue.get("is_notification_enabled")
                                            }
                                        }

                    self.log("Desired State for user issue (want): {0}".format(
                        user_issue_params), "DEBUG")

                    try:
                        response = self.dnac._exec(
                            family="issues",
                            function="updates_an_existing_custom_issue_definition_based_on_the_provided_id",
                            op_modifies=True,
                            params=user_issue_params,
                        )
                        self.log("response")
                        self.log(response)
                    except Exception as msg:
                        self.msg = (
                            "Exception occurred while updating the user defined: {msg}" .format(
                                msg=msg))
                        self.log(str(msg), "ERROR")
                        self.status = "failed"
                        return self

                # self.check_execution_response_status(
                #     response, "update_global_pool").check_return_status()
                if response.get("response"):
                    response_data = response.get("response")
                    if "name" in response_data:
                        self.log(
                            "Successfully created user defined issue with these details: {0}"
                            .format(response_data),
                            "INFO"
                        )
                    # for item in issue:
                    #     name = item.get("name")
                    #     self.log(
                    #         "User Defined Issue '{0}' created successfully.".format(name),
                    #         "INFO")
                # for item in user_issue_params:
                #     name = item.get("name")
                #     self.log(
                #         "User defined issue '{0}' Updated successfully.".format(name), "INFO")
                    result_assurance_issue.get("response").update(
                        {"User defined issue Details": item})
                    result_assurance_issue.get("msg").update(
                        {name: "User defined Updated Successfully"})
                    
            # self.log(
            #     "Global pool configuration operations completed successfully.",
            #     "INFO")
            return self


    # def verify_diff_merged(self, config):
    #     """
    #     Validating the Cisco Catalyst Center configuration with the playbook details
    #     when state is merged (Create/Update).

    #     Parameters:
    #         config (dict) - Playbook details containing Assurance issue.

    #     Returns:
    #         self - The current object with Global Pool, Reserved Pool, Network Servers information.
    #     """

    #     self.all_reserved_pool_details = {}
    #     self.get_have(config)
    #     self.log("Current State (have): {0}".format(self.have), "INFO")
    #     self.log("Requested State (want): {0}".format(self.want), "INFO")
    #     if config.get("global_pool_details") is not None:
    #         global_pool_index = 0
    #         self.log("Desired State of global pool (want): {0}"
    #                  .format(self.want.get("wantGlobal")), "DEBUG")
    #         self.log("Current State of global pool (have): {0}"
    #                  .format(self.have.get("globalPool")), "DEBUG")
    #         for item in self.want.get("wantGlobal").get(
    #                 "settings").get("ippool"):
    #             global_pool_details = self.have.get(
    #                 "globalPool")[global_pool_index].get("details")
    #             if not global_pool_details:
    #                 self.msg = "The global pool is not created with the config: {0}".format(
    #                     item)
    #                 self.status = "failed"
    #                 return self

    #             if self.requires_update(
    #                     global_pool_details,
    #                     item,
    #                     self.global_pool_obj_params):
    #                 self.msg = "Global Pool Config is not applied to the Cisco Catalyst Center"
    #                 self.status = "failed"
    #                 return self

    #             global_pool_index += 1

    #         self.log("Successfully validated global pool(s).", "INFO")
    #         self.result.get("response")[0].get(
    #             "globalPool").update({"Validation": "Success"})

    #     if config.get("reserve_pool_details") is not None:
    #         reserve_pool_index = 0
    #         self.log("Desired State for reserve pool (want): {0}"
    #                  .format(self.want.get("wantReserve")), "DEBUG")
    #         self.log("Current State for reserve pool (have): {0}"
    #                  .format(self.have.get("reservePool")), "DEBUG")
    #         for item in self.want.get("wantReserve"):
    #             reserve_pool_details = self.have.get(
    #                 "reservePool")[reserve_pool_index].get("details")
    #             if not reserve_pool_details:
    #                 self.msg = "The reserve pool is not created with the config: {0}".format(
    #                     item)
    #                 self.status = "failed"
    #                 return self

    #             if self.requires_update(
    #                     reserve_pool_details,
    #                     item,
    #                     self.reserve_pool_obj_params):
    #                 self.msg = "Reserved Pool Config is not applied to the Cisco Catalyst Center"
    #                 self.status = "failed"
    #                 return self

    #             reserve_pool_index += 1

    #         self.log("Successfully validated the reserved pool(s)", "INFO")
    #         self.result.get("response")[1].get(
    #             "reservePool").update({"Validation": "Success"})

    #     network_management_details = config.get("network_management_details")
    #     if network_management_details is not None:
    #         network_management_index = 0
    #         for item in network_management_details:
    #             if self.requires_update(
    #                     self.have.get("network")[network_management_index].get("net_details"),
    #                     self.want.get("wantNetwork")[network_management_index],
    #                     self.network_obj_params):
    #                 self.msg = "Network Functions Config is not applied to the Cisco Catalyst Center"
    #                 self.status = "failed"
    #                 return self

    #             self.log("Successfully validated the network functions '{0}'."
    #                      .format(item.get("site_name")), "INFO")
    #             network_management_index += 1

    #         self.result.get("response")[2].get(
    #             "network").update({"Validation": "Success"})

    #     self.msg = "Successfully validated the Global Pool, Reserve Pool and the Network Functions."
    #     self.status = "success"
    #     return self


def main():
    """main entry point for module execution"""

    # Define the specification for module arguments
    element_spec = {
        "dnac_host": {"type": 'str', "required": True},
        "dnac_port": {"type": 'str', "default": '443'},
        "dnac_username": {"type": 'str', "default": 'admin', "aliases": ['user']},
        "dnac_password": {"type": 'str', "no_log": True},
        "dnac_verify": {"type": 'bool', "default": 'True'},
        "dnac_version": {"type": 'str', "default": '2.2.3.3'},
        "dnac_debug": {"type": 'bool', "default": False},
        "dnac_log": {"type": 'bool', "default": False},
        "dnac_log_level": {"type": 'str', "default": 'WARNING'},
        "dnac_log_file_path": {"type": 'str', "default": 'dnac.log'},
        "dnac_log_append": {"type": 'bool', "default": True},
        "config_verify": {"type": 'bool', "default": False},
        "dnac_api_task_timeout": {"type": 'int', "default": 1200},
        "dnac_task_poll_interval": {"type": 'int', "default": 2},
        "config": {"type": 'list', "required": True, "elements": 'dict'},
        "state": {"default": 'merged', "choices": ['merged', 'deleted']},
        "validate_response_schema": {"type": 'bool', "default": True},
    }

    # Create an AnsibleModule object with argument specifications
    module = AnsibleModule(argument_spec=element_spec,
                            supports_check_mode=False)
    ccc_assurance = AssuranceSettings(module)
    state = ccc_assurance.params.get("state")

    if state not in ccc_assurance.supported_states:
        ccc_assurance.status = "invalid"
        ccc_assurance.msg = "State {0} is invalid".format(state)
        ccc_assurance.check_return_status()

    ccc_assurance.validate_input().check_return_status()
    config_verify = ccc_assurance.params.get("config_verify")

    for config in ccc_assurance.validated_config:
        ccc_assurance.reset_values()
        # ccc_assurance.input_data_validation(config).check_return_status()
        
        ccc_assurance.get_want(config).check_return_status()
        ccc_assurance.get_have(config).check_return_status()
        ccc_assurance.get_diff_state_apply[state](config).check_return_status()
        # if config_verify:
        #     ccc_assurance.verify_diff_state_apply[state](config).check_return_status()

if __name__ == "__main__":
    main()

