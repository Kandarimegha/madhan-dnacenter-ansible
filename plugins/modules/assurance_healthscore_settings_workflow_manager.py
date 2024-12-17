#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module to perform operations on global pool, reserve pool and network in Cisco Catalyst Center."""
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = ['Madhan Sankaranarayanan, Megha Kandari']

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
          - name:
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
          - name: cpu_utilization_threshold #required field
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


class Healthscore(DnacBase):
    """Class containing member attributes for Assurance setting workflow manager module"""

    def __init__(self, module):
        super().__init__(module)
        self.supported_states = ["merged", "deleted"]
        self.result["response"] = [
            {"assurance_healthscore_settings": {"response": {}, "msg": {}}},
        ]
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
            'assurance_healthscore': {
                'type': 'list',
                'elements': 'dict',
                'name': {'type': 'str', 'required': True},
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
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

        self.validated_config = valid_temp
        self.msg = "Successfully validated playbook configuration parameters using 'validate_input': {0}".format(
            str(valid_temp))
        self.log(self.msg, "INFO")

        return self

    def healthscore_obj_params(self, get_object):
        """
        Get the required comparison obj_params value

        Parameters:
            get_object (str) - identifier for the required obj_params

        Returns:
            obj_params (list) - obj_params value for comparison.
        """

        try:
            if get_object == "assurance_healthscore_settings":
                obj_params = [
                    ("name", "name"),
                    ("device_family", "device_family"),
                    ("include_for_overall_health", "include_for_overall_health"),
                    ("threshold_value", "threshold_value"),
                    ("synchronize_to_issue_threshold", "synchronize_to_issue_threshold"),
                ]
            else:
                raise ValueError("Received an unexpected value for 'get_object': {0}"
                                 .format(get_object))
        except Exception as msg:
            self.log("Received exception: {0}".format(msg), "CRITICAL")

        return obj_params

    def get_want(self, config):
        """
        Retrieve and store assurance healthscore details from playbook configuration.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): The configuration dictionary containing image import and other details.
        Returns:
            self: The current instance of the class with updated 'want' attributes.
        Raises:
            AnsibleFailJson: If an incorrect import type is specified.

        """

        want = {}
        want["assurance_healthscore"] = config.get("assurance_healthscore")
        if "kpi_name" in want:
            want["name"] = want.pop("kpi_name")
        self.want = want
        self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

        return self

    # def get_have(self, config):
    #     """
    #     Get the current Assurance healthscore details from Cisco Catalyst Center

    #     Parameters:
    #         config (dict) - Playbook details containing Global Pool,
    #         Reserved Pool, and Network Management configuration.

    #     Returns:
    #         self - The current object with updated Global Pool,
    #         Reserved Pool, and Network information.
    #     """
    #     self.log(config)
    #     assurance_healthscore_details = config.get("assurance_healthscore")

    #     if assurance_healthscore_details is not None:
    #         self.get_have_assurance_healthscore(assurance_healthscore_details).check_return_status()

    #     # self.log("Current State (have): {0}".format(self.have), "INFO")
    #     self.msg = "Successfully retrieved the details from the system"
    #     self.status = "success"
    #     return self

    # def get_have(self, config):
    #     """
    #     Get the current assurance healthscore and associated information from the Cisco Catalyst Center 
    #     based on the provided playbook details.
    #     """
    #     assurance_healthscore_details = config.get("assurance_healthscore")
    #     self.log(assurance_healthscore_details)
    #     # assurance_healthscore_details = assurance_healthscore_details.get("assurance_healthscore")
    #     have = []
    #     healthscore_index = 0

    #     for healthscore_details in assurance_healthscore_details:
    #         device_family = healthscore_details.get("device_family")
    #         if not device_family:
    #             self.msg = "Missing required parameter 'device_family' in assurance_healthscore settings"
    #             self.status = "failed"
    #             return self

    #         kpi_details = self.get_kpi_details(device_family, healthscore_details)
    #         self.log(kpi_details)
    #         if not kpi_details:
    #             self.msg = "No KPI details found for device family '{0}'".format(device_family)
    #             self.status = "failed"
    #             return self
            
    #         # include_for_overall_health = healthscore_details.get("include_for_overall_health")
    #         # threshold_value = healthscore_details.get("threshold_value")
    #         # synchronize_to_issue_threshold = healthscore_details.get("synchronize_to_issue_threshold")

    #         # if include_for_overall_health is None:
    #         #     self.msg = "Missing required parameters for kpi_name '{0}' in assurance_healthscore settings".format(kpi_name)
    #         #     self.status = "failed"
    #         #     return self

    #         # healthscore_info = {
    #         #     "kpi_name": kpi_name,
    #         #     "device_family": device_family,
    #         #     "threshold_value": threshold_value,
    #         #     "include_for_overall_health": include_for_overall_health,
    #         #     "synchronize_to_issue_threshold": synchronize_to_issue_threshold,
    #         # }
    #         have.append(kpi_details)
    #         healthscore_index += 1
    #     # self.have.update({"assuranceHealthscore": healthscore_list})
    #     # Mapping camelCase keys to snake_case replacements with updated values
    #         key_replacements = {
    #             'deviceFamily': ('device_family', 'ROUTER'),
    #             'includeForOverallHealth': ('include_for_overall_health', True),
    #             'thresholdValue': ('threshold_value', 90),
    #             'synchronizeToIssueThreshold': ('synchronize_to_issue_threshold', False)
    #         }

    #         # Replace keys and update values
    #         for old_key, (new_key, new_value) in key_replacements.items():
    #             if old_key in have:
    #                 # Remove old key, add new key with the updated value
    #                 have[new_key] = new_value
    #                 del have[old_key]
    #                 self.have = have
    #     self.log("Current State (have): {0}".format(self.have), "INFO")
    #     self.msg = "Successfully retrieved the details from the system"
    #     self.status = "success"
    #     return self

    #     # self.msg = "Successfully fetched Assurance healthscore from the Cisco Catalyst Center."
    #     # self.status = "success"
    #     # return self

    def get_have(self, config):
        """
        Get the current assurance healthscore and associated information from the Cisco Catalyst Center 
        based on the provided playbook details.
        """
        assurance_healthscore_details = config.get("assurance_healthscore")
        self.log(assurance_healthscore_details)

        if not assurance_healthscore_details:
            self.msg = "No assurance_healthscore details provided in the configuration."
            self.status = "failed"
            return self

        have = []

        for healthscore_details in assurance_healthscore_details:
            if "kpi_name" in healthscore_details:
                healthscore_details["name"] = healthscore_details.pop("kpi_name")
            device_family = healthscore_details.get("device_family")
            if not device_family:
                self.msg = "Missing required parameter 'device_family' in assurance_healthscore settings."
                self.status = "failed"
                return self
            self.log(assurance_healthscore_details)
            kpi_details = self.get_kpi_details(device_family, healthscore_details)
            self.log(kpi_details)

            if not kpi_details:
                self.msg = "No KPI details found for device family '{0}'".format(device_family)
                self.status = "failed"
                return self

            # Append the KPI details to `have` for further processing
            have.append(kpi_details)

        # Replace camelCase keys with snake_case in all entries of the `have` list
        key_replacements = {
            'deviceFamily': 'device_family',
            'includeForOverallHealth': 'include_for_overall_health',
            'thresholdValue': 'threshold_value',
            'synchronizeToIssueThreshold': 'synchronize_to_issue_threshold'
        }

        for item in have:
            for old_key, new_key in key_replacements.items():
                if old_key in item:
                    item[new_key] = item.pop(old_key)

        # Save the final state in `self.have`
        self.have = have

        self.log("Current State (have): {0}".format(self.have), "INFO")
        self.msg = "Successfully retrieved the details from the system."
        self.status = "success"
        return self

    def get_kpi_details(self, device_family, healthscore_details):
        """
        Retrieve the KPI name based on the device family by calling the 'Get all health score definitions for given filters' API.
        """
        self.log("Retrieving KPI for device family '{0}'".format(device_family))

        param = {
            "deviceType": device_family,
            "id": healthscore_details.get("id"),
    }

        try:
            response = self.dnac._exec(
                family="devices",
                function="get_all_health_score_definitions_for_given_filters",
                params=param
            )
        except Exception as msg:
            self.msg = "Exception occurred while getting KPI details: {0}".format(msg)
            self.log(self.msg, "ERROR")
            self.status = "failed"
            return None

        if not isinstance(response, dict):
            self.msg = "Failed to retrieve KPI details - Response is not a dictionary"
            self.log(self.msg, "CRITICAL")
            self.status = "failed"
            return None

        kpi_details = response.get("response")
        self.log(kpi_details)
        if not kpi_details:
            self.msg = "No KPI details found for device family '{0}'".format(device_family)
            self.log(self.msg, "ERROR")
            self.status = "failed"
            return None
        self.log(healthscore_details)

        for kpi in kpi_details:
            self.log("KPI_check")
            self.log(kpi)
            self.log(device_family)
            self.log( healthscore_details.get("name"))


            if kpi.get("deviceFamily") == device_family and kpi.get("name") == healthscore_details.get("name"):
                self.log("KPI details for device family '{0}' and KPI '{1}': {2}".format(device_family, healthscore_details.get("name"), kpi), "INFO")
                return kpi

        self.msg = "No KPI found for device family '{0}' and KPI name '{1}'".format(device_family, kpi_details)
        self.log(self.msg, "ERROR")
        self.status = "failed"
        return None

    def get_diff_merged(self, config):
        """
        Update Assurance healthscore configurations in Cisco Catalyst Center based on the playbook details

        Parameters:
            config (list of dict) - Playbook details containing
            Assurance healthscore information.

        Returns:
            self - The current object with Assurance Issue information.
        """
        assurance_healthscore_details = config.get("assurance_healthscore")

        if assurance_healthscore_details is not None:
            self.update_healthscore_settings(assurance_healthscore_details).check_return_status()   

        return self

    def update_healthscore_settings(self, assurance_healthscore_details):

        updated_healthscore_settings = []
        result_healthscore_settings = self.result.get("response")[0].get("assurance_healthscore_settings")

        for healthscore_setting in assurance_healthscore_details:
            name = healthscore_setting.get("name")
            if name is None:
                self.msg = "Missing required parameter 'name' in assurance_healthscore_details"
                self.status = "failed"
                return self

            healthscore_obj_params = self.healthscore_obj_params("assurance_healthscore_settings")
            for item in self.have:
                self.log(item)
                self.log(healthscore_setting)
                if not self.requires_update(item, healthscore_setting, healthscore_obj_params):
                    self.log(
                        "Healthscore setting '{0}' doesn't require an update".format(name), "INFO")
                    result_healthscore_settings.get("msg").update(
                        {name: "Healthscore setting doesn't require an update"})
                elif healthscore_setting not in updated_healthscore_settings:
                        updated_healthscore_settings.append(healthscore_setting)

            if updated_healthscore_settings:
                healthscore_params = {
                    "id": item.get("id"),
                    "payload": {
                        "includeForOverallHealth": healthscore_setting.get("include_for_overall_health"),
                        "thresholdValue": healthscore_setting.get("threshold_value"),
                        "synchronizeToIssueThreshold": healthscore_setting.get("synchronize_to_issue_threshold"),
                    }
                }

                self.log(f"Preparing update for healthscore settings '{name}' with params: {healthscore_params}", "DEBUG")

                try:
                    self.log("hi")
                    response = self.dnac._exec(
                        family="devices",
                        function="update_health_score_definition_for_the_given_id",
                        op_modifies=True,
                        params=healthscore_params,
                    )
                    self.log(response)
                    if response.get("response"):
                        response_data = response.get("response")
                        self.log(f"Successfully updated healthscore settings '{name}' with details: {response_data}", "INFO")
                        updated_healthscore_settings.append(response_data)
                    else:
                        self.log(f"Failed to update system issue '{name}'", "ERROR")

                except Exception as e:
                    self.msg = "Exception occurred while updating the healthscore settings '{0}':".format(str(name))
                    self.log(self.msg, "ERROR")
                    self.status = "failed"
                    return self
                result_healthscore_settings.get("response").update(
                            {"system issue": updated_healthscore_settings})
                result_healthscore_settings.get("msg").update(
                {response_data.get("name"): "System issue Updated Successfully"})
                self.msg = "Successfully updated system-defined issue details."
                self.result['changed'] = True

        # Update the `have` object with the updated system issue details
        # self.have.update({"assurance_system_issue_settings": updated_healthscore_settings})
        
        self.status = "success"
        return self

    def verify_diff_merged(self, config):
        """
        Validating the Cisco Catalyst Center configuration with the playbook details
        when state is merged (Create/Update).

        Parameters:
            config (dict) - Playbook details containing Assurance healthscore setting.

        Returns:
            self - The current object with Assurance healthscore information.
        """

        self.all_assurance_healthscore_details = {}
        self.get_have(config)
        self.log("Current State (have): {0}".format(self.have), "INFO")
        self.log("Requested State (want): {0}".format(self.want.get("assurance_healthscore")), "INFO")
        if config.get("assurance_healthscore") is not None:
            assurance_healthscore_index = 0
            self.log("Desired State of assurance healthscore issue settings (want): {0}"
                     .format(self.want.get("assurance_healthscore")), "DEBUG")
            self.log("Current State of assurance healthscore issue settings (have): {0}"
                     .format(self.have), "DEBUG")
            for item in self.want.get("assurance_healthscore"):
                assurance_healthscore_details = self.have[assurance_healthscore_index]
                self.log(assurance_healthscore_details)
                self.log(item)

                # if not assurance_healthscore_details:
                #     self.msg = "The Assurance healthscore config is not set in cisco catalyst center : {0}".format(
                #         item)
                #     self.status = "failed"
                #     return self
                healthscore_obj_params = self.healthscore_obj_params("assurance_healthscore_settings")

                if not self.requires_update(assurance_healthscore_details, item, healthscore_obj_params):

                    self.msg = "Assurance healthscore Config is not applied to the Cisco Catalyst Center"
                    self.status = "failed"
                    return self

                
                assurance_healthscore_index += 1

                self.log("Successfully validated Assurance healthscore setting(s).", "INFO")
                self.result.get("response")[0].get(
                    "assurance_healthscore_settings").update({"Validation": "Success"})

        self.msg = "Successfully validated the Assurance user defined issue."
        self.status = "success"
        return self

    def get_dict_result(data, key, value):
        """
    This function extracts the result from the dictionary where key matches the value.
    Ensure that both deviceFamily and name are matched.
        """
        result = None
        for item in data:
            if item.get(key) == value:
            # Make sure the correct name is also matched, not just deviceFamily
                if item.get("name") == value:
                    result = item
                    break
        return result

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
    ccc_assurance = Healthscore(module)
    state = ccc_assurance.params.get("state")

    if state not in ccc_assurance.supported_states:
        ccc_assurance.status = "invalid"
        ccc_assurance.msg = "State {0} is invalid".format(state)
        ccc_assurance.check_return_status()

    ccc_assurance.validate_input().check_return_status()
    config_verify = ccc_assurance.params.get("config_verify")

    for config in ccc_assurance.validated_config:
        ccc_assurance.reset_values()
        ccc_assurance.get_want(config).check_return_status()
        ccc_assurance.get_have(config).check_return_status()
        ccc_assurance.get_diff_state_apply[state](config).check_return_status()
        # if config_verify:
        #     ccc_assurance.verify_diff_state_apply[state](config).check_return_status()

        module.exit_json(**ccc_assurance.result)

if __name__ == "__main__":
    main()

