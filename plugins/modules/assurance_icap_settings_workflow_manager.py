#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Ansible module to perform operations on Assurance ICAP settings in Cisco Catalyst Center."""
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = ['Megha Kandari, Madhan Sankaranarayanan']

DOCUMENTATION = r"""
---
module: assurance_icap_settings_workflow_manager
short_description: Manage ICAP settings in Cisco Catalyst Center
description:
  - Configures ICAP settings for capturing client and network device information for onboarding and monitoring.
  - This module interacts with Cisco DNA Center's Assurance settings to configure ICAP settings.
version_added: '6.6.0'
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author:
  - Megha Kandari (@kandarimegha)
  - Madhan Sankaranarayanan (@madhansansel)
options:
  config_verify:
   description: Set to True to verify the Cisco Catalyst Center after applying the playbook config.
   type: bool
   default: False
  state:
    description:
      - The state of Cisco Catalyst Center after module completion.
    type: str
    choices: ["merged", "deleted"]
    default: merged
  config:
    description:
      - List of details of global pool, reserved pool, network being managed.
    type: list
    elements: dict
    required: true
    suboptions:
      assurance_icap_settings:
        description:
          - Configures ICAP settings for capturing client and network device information for onboarding and monitoring.
        type: list
        elements: dict
        suboptions:
          capture_type:
            description: The type of ICAP capture to be performed (e.g., onboarding).
            type: str
          duration_in_mins:
            description: The duration of the ICAP capture session in minutes.
            type: int
          client_mac:
            description: The MAC address of the client device for which the capture is being performed.
            type: str
          wlc_id:
            description: The ID of the Wireless LAN Controller (WLC) involved in the ICAP capture.
            type: str
          ap_id:
            description: The ID of the Access Point (AP) for the capture.
            type: str
          slot:
            description: List of slot numbers for the capture session.
            type: list
            elements: int
          ota_band:
            description: The OTA band (e.g., 5GHz, 2.4GHz) for the capture.
            type: str
          ota_channel:
            description: The OTA channel (e.g., 36, 40) for the capture.
            type: int
          ota_channel_width:
            description: The width of the OTA channel (e.g., 20MHz, 40MHz).
            type: int
          deploy:
            description: The deployment is required or not (e.g., True, False).
            type: bool
          generates_the_device_cli:
            description: Generation of the device CLI is required or not (e.g., True, False).
            type: bool
requirements:
  - dnacentersdk >= 2.9.3
  - python >= 3.9
notes:
  - SDK Method used are
    sensors.AssuranceSettings.get_i_cap_configuration_status_per_network_device,
    sensors.AssuranceSettings.get_device_deployment_status_count,
    sensors.AssuranceSettings.creates_an_icap_configuration_intent_for_preview_approve,
    sensors.AssuranceSettings.discards_the_icap_configuration_intent_by_activity_id
    sensors.AssuranceSettings.deploys_the_i_cap_configuration_intent_by_activity_id_v1
    sensors.AssuranceSettings.creates_ai_cap_configuration_workflow_for_i_capintent_to_remove_the_i_cap_configuration_on_the_device_v1
    sensors.AssuranceSettings.retrieves_the_devices_clis_of_the_i_capintent_v1
  - Paths used are
    GET /dna/intent/api/v1/icapSettings/configurationModels/{previewActivityId}/networkDeviceStatusDetails
    POST /dna/intent/api/v1/icapSettings/{previewActivityId}/networkDevices/{networkDeviceId}/config
    POST /dna/intent/api/icapSettings/configurationModels
    DELETE /dna/intent/api/v1/icapSettings/configurationModels/{previewActivityId}
    GET /dna/intent/api/v1/icapSettings/configurationModels/{previewAcitivityId}/networkDevices/{networkDeviceId}/config
    POST /dna/intent/api/v1/icapSettings/configurationModels/{previewActivityId}/deploy
    GET /dna/intent/api/v1/icap
"""

EXAMPLES = r"""
---
  - hosts: dnac_servers
    vars_files:
      - credentials.yml
    gather_facts: no
    connection: local
    tasks:
      - name: Create icap settings
        cisco.dnac.assurance_icap_settings_workflow_manager:
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
                  clientMac: client_mac_id  #required field
                  wlcId: wlc_id  #required field
                  apId: ap_id  #required field
                  slot:
                    - 1
                    - 2
                  otaBand: 5GHz
                  otaChannel: 36
                  otaChannelWidth: 20
    """

RETURN = r"""
#Case 1: Successful creation/deletion of Icap settings
response_1:
  description: A dictionary or list with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
          "taskId": "string",
           "url": "string"
    },
    "version": "string"
    }

"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
)


class Icap(DnacBase):
    """Class containing member attributes for icap setting workflow manager module"""

    def __init__(self, module):
        super().__init__(module)
        self.supported_states = ["merged", "deleted"]
        self.result["response"] = [
            {"assurance_icap_settings": {"response": {}, "msg": {}}},
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
        temp_spec = {
            'assurance_icap_settings': {
                'type': 'list',
                'elements': 'dict',
                'capture_type': {'type': 'str', 'required': True},
                'duration_in_mins': {'type': int, 'required': True},
                'client_mac': {'type': 'str', 'required': True},
                'wlc_id': {'type': 'str', 'required': False},
                'ap_id': {'type': 'str', 'required': False},
                'slot': {'type': list, 'required': False},
                'ota_band': {'type': 'str', 'required': False},
                'ota_channel': {'type': int, 'required': True},
                'ota_channel_width': {'type': int, 'required': True},

            }
        }

        if not self.config:
            self.msg = "The playbook configuration is empty or missing."
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

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

    def icap_obj_params(self, get_object):
        """
        Get the required comparison obj_params value

        Parameters:
            get_object (str) - identifier for the required obj_params

        Returns:
            obj_params (list) - obj_params value for comparison.
        """

        try:
            if get_object == "assurance_icap_settings":
                obj_params = [
                    ("capture_type", "capture_type"),
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
        Retrieve and store assurance icap details from playbook configuration.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): The configuration dictionary containing image import and other details.
        Returns:
            self: The current instance of the class with updated 'want' attributes.
        Raises:
            AnsibleFailJson: If an incorrect import type is specified.

        """

        want = {}
        want["assurance_icap_settings"] = config.get("assurance_icap_settings")
        self.want = want
        self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

        return self

    def get_have(self, config):
        """
        Get the current icap associated information from the Cisco Catalyst Center
        based on the provided playbook details.
        """
        assurance_icap_settings = config.get("assurance_icap_settings")
        self.log(assurance_icap_settings)
        if assurance_icap_settings:
            self.get_have_icap(assurance_icap_settings)

    def get_diff_merged(self, config):
        """
        Create Assurance ICAP configurations in Cisco Catalyst Center based on the playbook details

        Parameters:
            config (list of dict) - Playbook details containing
            Assurance icap information.

        Returns:
            self - The current object with Assurance icap information.
        """
        assurance_icap_settings = config.get("assurance_icap_settings")

        if assurance_icap_settings is not None:
            self.create_icap(assurance_icap_settings).check_return_status()
            # self.generates_the_device_clis(assurance_icap_settings)
        return self

    def generates_the_device_clis(self, assurance_icap_details, preview_activity_id):
        """
        Generate device CLI configurations for ICAP intent in Cisco Catalyst Center.

        This method processes ICAP details to create device CLI configurations, monitor the task,
        and handle success or failure. It cleans up if the task fails.

        Parameters:
            assurance_icap_details (dict): ICAP details including WLC ID, capture type, and description.
            preview_activity_id (str): ID of the preview activity associated with the ICAP task.

        Returns:
            self: The current object with the operation result and status message.

        Raises:
            Exception: If an error occurs during the CLI generation or task management.
        """
        network_device_id = assurance_icap_details.get("wlc_id")
        for icap in assurance_icap_details:
            capture_type = icap.get("capture_type")
            preview_description = icap.get("preview_description")
            if capture_type is None:
                self.msg = "Missing required parameter 'capture_type' in assurance_icap_settings"
                self.status = "failed"
                return self

            icap_params = {
                'previewActivityId': preview_activity_id,
                'networkDeviceId': network_device_id,
            }

            try:
                task_name = "generates_the_devices_clis_of_the_i_cap_configuration_intent_v1"
                payload = {"payload": icap_params}
                task_id = self.get_taskid_post_api_call("sensors", task_name, payload)

                if not task_id:
                    self.msg = "Unable to retrieve the task_id for the task '{0}'.".format(task_name)
                    self.set_operation_result("failed", False, self.msg, "ERROR")
                    return self

                success_msg = "Generated the devices cli's of icap config '{0}'  successfully in the Cisco Catalyst Center".format(preview_description)
                failure_msg = "Failed to generate the devices cli's of icap config '{0}' in the Cisco Catalyst Center".format(preview_description)
                self.get_task_status_from_task_by_id(
                    task_id=task_id,
                    task_name=task_name,
                    failure_msg=failure_msg,
                    success_msg=success_msg
                )
                if self.status == "failed":
                    self.log("Task failed. Calling delete function to clean up.", "ERROR")
                    self.delete_icap_config(task_id, capture_type)
                    return self

            except Exception as e:
                self.msg = "An exception occurred while creating ICAP config in Cisco Catalyst Center: {0}".format(str(e))
                self.log(self.msg, "ERROR")
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

        self.msg = "Successfully set ICAP config."
        self.set_operation_result("success", True, self.msg, "INFO")

    def retrieves_the_device_clis(self, assurance_icap_details, preview_activity_id):
        """
        Retrieve device CLI configurations for an ICAP intent from Cisco DNAC.

        Parameters:
            assurance_icap_details (dict): ICAP details including WLC ID.
            preview_activity_id (str): Preview activity ID.

        Returns:
            list or self: CLI configurations if successful, or self with error status.

        Raises:
            Exception: If an error occurs during retrieval.
        """
        network_device_id = assurance_icap_details.get("wlc_id")
        try:
            response = self.dnac._exec(
                family="sensors",
                function="retrieves_the_devices_clis_of_the_i_capintent_v1",
                op_modifies=False,
                params={'previewActivityId': preview_activity_id, 'networkDeviceId': network_device_id}
            )
            response = response.get("response")
            if response:
                return response
        except Exception as msg:
            self.msg = (
                "Exception occurred while performing icap: {msg}"
                .format(msg=msg)
            )
            self.log(str(msg), "ERROR")
            self.status = "failed"
            return self

    def deploy_icap_config(self, assurance_icap_details, preview_activity_id):
        """
        Deploy an ICAP configuration intent in Cisco Catalyst Center.

        This method deploys the specified ICAP configuration based on the provided details and
        preview activity ID. It handles task creation, monitors task status, and logs success or failure.

        Parameters:
            assurance_icap_details (dict): ICAP details including preview description.
            preview_activity_id (str): Preview activity ID.

        Returns:
            self: The current object with operation result and status message.
        """
        try:
            preview_description = assurance_icap_details.get("preview_description")
            self.log("Requested payload for deploying {0}".format(preview_description), "DEBUG")
            payload = {'previewActivityId': preview_activity_id}
            task_name = "deploys_the_given_i_cap_configuration_intent_without_preview_and_approve_v1"
            task_id = self.get_taskid_post_api_call("sensors", task_name, payload)

            if not task_id:
                self.msg = "Unable to retrieve the task_id for the task '{0}'.".format(task_name)
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            success_msg = "deployed icap config '{0}' successfully in the Cisco Catalyst Center".format(preview_description)
            self.log(success_msg, "DEBUG")
            self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)

        except Exception as e:
            self.msg = "An exception occured while deploying icap config '{0}' in Cisco Catalyst Center: {1}".format(preview_description, str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR")

        return self

    def icap_configuration_status_per_network_device(self, preview_activity_id):
        """
        Retrieve ICAP configuration status for network devices from Cisco DNAC.

        This method fetches the ICAP configuration status for devices based on the provided preview
        activity ID and returns the status details.

        Parameters:
            preview_activity_id (str): The preview activity ID to associate with the task.

        Returns:
            list or self: List of status details if successful, or self with error status if an exception occurs.
        """
        try:
            response = self.dnac._exec(
                family="sensors",
                function="get_i_cap_configuration_status_per_network_device_v1",
                op_modifies=False,
                params={'previewActivityId': preview_activity_id}
            )
            response = response.get("response")
            if response:
                return response
        except Exception as msg:
            self.msg = (
                "Exception occurred while performing icap operation: {msg}"
                .format(msg=msg)
            )
            self.log(str(msg), "ERROR")
            self.status = "failed"
            return self

    def create_icap(self, assurance_icap_details):
        """
        Creates an ICAP configuration in the Cisco Catalyst Center, monitors its task status, and takes appropriate actions
        based on the result of the task. If the task fails, a cleanup function is called to delete the configuration.
        If the task succeeds, the next step in the workflow is executed.

        Args:
            assurance_icap_details (list): A list of dictionaries containing the details for ICAP configuration. Each
                dictionary must include the following keys:
                - "capture_type" (str): The type of ICAP capture (e.g., "onboarding").

        Workflow:
            The general guideline for the preview-approve workflow is as follows:

            Step 1: Use the POST API to initiate the intent request. The intent is not deployed to the device yet.
            The TaskResponse body contains the taskId (UUID), referred to as `previewActivityId` in all subsequent APIs.
            At any step, the DELETE `/dna/intent/api/v1/icapSettings/configurationModels/{previewActivityId}` API
            can be used to discard or cancel the intent. A discarded intent completes the preview-approve workflow,
            meaning the ICAP intent is not applied to the device. The API response body includes a URL to GET the task status,
            which must be checked for successful completion before proceeding to the next step. If the task fails,
            the preview-approve workflow process is completed.

            Step 2: Use GET `/dna/intent/api/v1/icapSettings/configurationModels/{previewActivityId}/networkDeviceStatusDetails`
            to check for potential conflicts.

            Step 3: Use POST `/dna/intent/api/v1/icapSettings/{previewActivityId}/networkDevices/{networkDeviceId}/config`
            to generate device CLIs for the preview-approve process. The response body contains a task ID and a URL
            to check the task status. This task must successfully complete before using the GET API to view CLIs.
            If the task fails, the preview-approve workflow ends. Multiple POST requests, each with a different
            `networkDeviceId` (corresponding to the `wlcId` value in the initial POST API), can be used to generate
            CLIs for multiple devices. Each POST request's task must be checked before proceeding.
            If any task fails, the DELETE `/dna/intent/api/v1/icapSettings/configurationModels/{previewActivityId}`
            should be used to discard the activity.

            Step 4: Use GET `/dna/intent/api/v1/icapSettings/configurationModels/{previewActivityId}/networkDevices/{networkDeviceId}/config`
            to view the CLIs that will be applied to the device.

            Step 5: Use POST `/dna/intent/api/v1/icapSettings/configurationModels/{previewActivityId}/deploy`
            to push the intent to the device. This step completes the preview-approve workflow.
            This POST returns a task, which should be checked for its status.

            NOTE: ONBOARDING, FULL, OTA, and SPECTRUM have durations. A "disable" task is automatically scheduled to
            remove the ICAP intent when the duration expires. Use GET `/dna/intent/api/v1/icap` to retrieve the "disable"
            task ID. This task ID can be used to preview the CLIs of the "disable" task. However, steps in the preview-approve
            workflow are not available after the duration expires.

        Returns:
            self: Returns the instance of the class with updated `status` and `msg` attributes.

        Raises:
            Exception: If an unexpected error occurs during the process, it is logged, and the operation is marked as failed.

        Notes:
            - The method uses `get_task_status_from_task_by_id` to validate the progress and result of the task.
            - The `delete_icap_config` and `next_function` methods should be implemented to handle cleanup and further actions, respectively.
            - Logs are generated at each step to provide insights into the workflow.

        Example:
            assurance_icap_details = [
                {
                    "capture_type": "onboarding"
                }
            ]
            instance.create_icap(assurance_icap_details)
        """
        # create_icap_settings = []
        result_icap_settings = self.result.get("response")[0].get("assurance_icap_settings")

        for icap in assurance_icap_details:
            capture_type = icap.get("capture_type")
            if capture_type is None:
                self.msg = "Missing required parameter 'capture_type' in assurance_icap_settings"
                # self.status = "failed"
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            icap_params = {
                "previewDescription": "test",
                "captureType": "onboarding",
                "duration_in_mins": 30,
                "client_mac": "client_mac_id",
                "wlc_id": "wlc_id",
                "ap_id": "ap_id",
                "slot": [1, 2],
                "ota_band": "5GHz",
                "ota_channel": 36,
                "ota_channel_width": 20
            }

            try:
                task_name = "creates_an_i_cap_configuration_intent_for_preview_approve_v1"
                payload = {"payload": icap_params}
                task_id = self.get_taskid_post_api_call("sensors", task_name, payload)

                if not task_id:
                    self.msg = "Unable to retrieve the task_id for the task '{0}'.".format(task_name)
                    self.set_operation_result("failed", False, self.msg, "ERROR")
                    return self

                success_msg = "ICAP Configuration '{0}' set successfully in the Cisco Catalyst Center".format(capture_type)
                failure_msg = "Failed to set ICAP Configuration '{0}' in the Cisco Catalyst Center".format(capture_type)

                self.get_task_status_from_task_by_id(
                    task_id=task_id,
                    task_name=task_name,
                    failure_msg=failure_msg,
                    success_msg=success_msg
                )
                preview_activity_id = self.get_preview_id(task_id)
                if self.status == "failed":
                    self.log("Task failed. Calling delete function to clean up.", "ERROR")
                    self.delete_icap_config(preview_activity_id, capture_type)
                    return self
                else:
                    self.log("Task succeeded. Proceeding to the next function.", "INFO")
                    result_icap_settings.get("response").update(
                        {"created icap configuration": icap})
                    result_icap_settings.get("msg").update(
                        {icap.get("preview_description"): "Icap configuration Created Successfully"})
                    self.set_operation_result("success", True, self.msg, "INFO")
                    self.icap_configuration_status_per_network_device(self, preview_activity_id)
                    if icap.get("generates_the_device_cli"):
                        self.generates_the_device_clis(icap, preview_activity_id)
                        self.retrieves_the_device_clis(icap, preview_activity_id)
                    if icap.get("deploy"):
                        self.deploy_icap_config(icap, preview_activity_id)
            except Exception as e:
                self.msg = "An exception occurred while creating ICAP config in Cisco Catalyst Center: {0}".format(str(e))
                self.log(self.msg, "ERROR")
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

        self.msg = "Successfully set ICAP config."
        self.set_operation_result("success", True, self.msg, "INFO")
        return self

    def get_preview_id(self, task_id):
        """
        Retrieves the previewActivityId associated with a given task ID by monitoring the task status
        through the Cisco Catalyst Center API.

        Args:
            task_id (str): The unique identifier of the task for which the previewActivityId is to be retrieved.

        Returns:
            str: The previewActivityId if successfully retrieved from the task response.
            None: If an exception occurs or the previewActivityId cannot be retrieved.
        """
        try:
            response = self.dnac._exec(
                family="task",
                function="get_tasks_by_id",
                params={"id": task_id}
            )
            response = response.get("response")
            preview_activity_id = response.get("previewActivityId")
            return preview_activity_id
        except Exception as e:
            self.msg = "An exception occurred while getting preview Activity ID from task ID: {0}".format(str(e))
            self.log(self.msg, "ERROR")
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return None

    def delete_icap_config(self, preview_activity_id, capture_type):
        """
        Discards an ICAP configuration intent in Cisco Catalyst Center using the task ID.

        Args:
            task_id (str): The unique identifier of the task associated with the ICAP configuration intent.
            capture_type (str): The type of ICAP configuration being discarded (e.g., onboarding, spectrum, etc.).

        Returns:
            self (object): Returns the current instance of the class with updated status and message attributes.

        Description:
            This method retrieves the `previewActivityId` using the provided task ID, then initiates the discard operation
            for the ICAP configuration intent in Cisco Catalyst Center. It monitors the task's status and updates the
            instance attributes with the operation's result.

        Workflow:
            1. Retrieve `previewActivityId` using the provided task ID by calling `get_preview_id`.
            2. Send a POST request to the appropriate API endpoint to discard the ICAP configuration intent.
            3. Monitor the task status for success or failure using `get_task_status_from_task_by_id`.
            4. On success, update the instance's result with details of the discarded ICAP configuration.
            5. On failure or exception, log the error, update the operation result, and return the instance.

        Example:
            instance = delete_icap_config(task_id="12345", capture_type="onboarding")
            if instance.status == "success":
                print("ICAP configuration discarded successfully.")
            else:
                print("Failed to discard ICAP configuration.")
        """
        result_icap_settings = self.result.get("response")[0].get("assurance_icap_settings")
        # Get previewActivityId for deletion by task ID
        # preview_activity_id = self.get_preview_id(task_id)
        try:
            task_name = "discards_the_i_cap_configuration_intent_by_activity_id_v1"
            payload = {"payload": preview_activity_id}
            task_id = self.get_taskid_post_api_call("sensors", task_name, payload)

            if not task_id:
                self.msg = "Unable to retrieve the task_id for the task '{0}'.".format(task_name)
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            success_msg = "ICAP Configuration '{0}' discarded successfully in the Cisco Catalyst Center".format(capture_type)
            failure_msg = "Failed to discard ICAP Configuration '{0}' in the Cisco Catalyst Center".format(capture_type)

            self.get_task_status_from_task_by_id(
                task_id=task_id,
                task_name=task_name,
                failure_msg=failure_msg,
                success_msg=success_msg
            )
            result_icap_settings.get("response").update(
                {"discarded icap configuration": capture_type})
            result_icap_settings.get("msg").update(
                {capture_type: "ICAP configuration discarded successfully."})
            self.msg = "Successfully discarded ICAP config."
            self.set_operation_result("success", False, self.msg, "INFO")
            return self

        except Exception as e:
            self.msg = "An exception occurred while discarding ICAP config in Cisco Catalyst Center: {0}".format(str(e))
            self.log(self.msg, "ERROR")
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

    def verify_diff_merged(self, config):
        """
    Validating the Cisco Catalyst Center ICAP configuration with the playbook details
    when state is merged (Create).

    Parameters:
        config (dict) - Playbook details containing ICAP configuration.

    Returns:
        self - The current object with ICAP configuration information.
        """

        self.all_assurance_icap_details = {}
        self.get_have(config)
        self.log("Current State (have): {0}".format(self.have), "INFO")
        self.log("Requested State (want): {0}".format(self.want.get("assurance_icap_settings")), "INFO")

        if config.get("assurance_icap_settings") is not None:
            icap_index = 0
            self.log("Desired State of ICAP configuration (want): {0}"
                     .format(self.want.get("assurance_icap_settings")), "DEBUG")
            self.log("Current State of ICAP configuration (have): {0}"
                     .format(self.have), "DEBUG")

            for item in self.want.get("assurance_icap_settings"):
                icap_details = self.have[icap_index]
                self.log(icap_details)
                self.log(item)
                icap_obj_params = self.icap_obj_params("assurance_icap_settings")

                if not self.requires_update(icap_details, item, icap_obj_params):
                    self.msg = "ICAP Config is not applied to the Cisco Catalyst Center"
                    self.status = "failed"
                    return self

                icap_index += 1

            self.log("Successfully validated ICAP configuration(s).", "INFO")
            self.result.get("response")[0].get(
                "assurance_icap_settings").update({"Validation": "Success"})

        self.msg = "Successfully validated the ICAP configuration."
        self.status = "success"
        return self


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
    ccc_assurance = Icap(module)
    state = ccc_assurance.params.get("state")
    # ccc_sda_devices = FabricDevices(module)
    if ccc_assurance.compare_dnac_versions(ccc_assurance.get_ccc_version(), "2.3.7.9") < 0:
        ccc_assurance.msg = (
            "The specified version '{0}' does not support the Assurance ICAP settings feature. Supported versions start from '2.3.7.9' onwards."
            .format(ccc_assurance.get_ccc_version())
        )
        ccc_assurance.status = "failed"
        ccc_assurance.check_return_status()

    if state not in ccc_assurance.supported_states:
        ccc_assurance.status = "invalid"
        ccc_assurance.msg = "State {0} is invalid".format(state)
        ccc_assurance.check_return_status()

    ccc_assurance.validate_input().check_return_status()
    config_verify = ccc_assurance.params.get("config_verify")

    for config in ccc_assurance.validated_config:
        ccc_assurance.reset_values()
        ccc_assurance.get_want(config).check_return_status()
        # ccc_assurance.get_have(config).check_return_status()
        ccc_assurance.get_diff_state_apply[state](config).check_return_status()
        # if config_verify:
        #     ccc_assurance.verify_diff_state_apply[state](config).check_return_status()

        module.exit_json(**ccc_assurance.result)


if __name__ == "__main__":
    main()
