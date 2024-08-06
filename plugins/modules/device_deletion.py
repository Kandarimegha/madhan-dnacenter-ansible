#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
import time
import re
import json
__metaclass__ = type
__author__ = ("A Mohamed Rafeek, Megha Kandari, Sonali Deepthi Kesali, Natarajan, Madhan Sankaranarayanan, Abhishek Maheshwari")


import json
import re, time
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
    validate_str,
    get_dict_result,
   
)
from ansible.module_utils.basic import AnsibleModule

import sys
sys.path.append('/Users/mekandar/dnacenter-ansible/plugins/modules/')  
from accesspoint_workflow_manager import Accesspoint

class delete_device(Accesspoint):
    """Class containing member attributes for DNAC Access Point Automation module"""
    
    def __init__(self, module):
        super().__init__(module)
        self.result["response"] = []
        self.supported_states = ["merged", "deleted"]
        self.payload = module.params
        # self.keymap = {}    

    import time

def delete_device(self):
    """
    Deletes a device (AP) from a specific site.

    Parameters:
        self (object): An instance of a class used for interacting with Cisco Catalyst Center.

    Returns:
        tuple: A tuple containing the deletion status ("SUCCESS" or "failed") and
        the deletion details or error message.

    Description:
        Deletes an Access Point (AP) from a specified site using the provided
        site name hierarchy and hostname. Logs details and handles errors.
    """

    deletion_status = "failed"
    deletion_details = None

    try:
      
        host_name = self.have.get("hostname")
        device_id = self.have.get("device_id")
        # host_name = Accesspoint.have.get("hostname")
        # device_id = Accesspoint.have.get("device_id")

        if not host_name:
            error_msg = ("Cannot delete device: Missing parameters - "
                          "device_id: {}"
                         .format( device_id))
            self.log(error_msg, "ERROR")
            self.module.fail_json(msg=error_msg)

        # deletion_params = [{
        #     "deviceId": "37b05b0f-1b1e-496a-b101-8f277f0af8ff"
        # }]
        self.log('Current deletion details: {0}'.format(self.pprint(device_id)), "INFO")

        response = self.dnac._exec(
            family="devices",
            function='delete_device_by_id',
            op_modifies=True,
            # params={"payload": device_id},
            params={"id": device_id},
        )

        self.log('Response from ap_delete: {0}'.format(str(response)), "INFO")
        
        if response and isinstance(response, dict):
            executionid = response.get("executionId")
            resync_retry_count = self.want.get("resync_retry_count", 100)
            resync_retry_interval = self.want.get("resync_retry_interval", 5)

            while resync_retry_count:
                execution_details = self.get_execution_details(executionid)
                if execution_details.get("status") == "SUCCESS":
                    self.result['changed'] = True
                    self.result['response'] = execution_details
                    deletion_status = "SUCCESS"
                    deletion_details = execution_details
                    break

                elif execution_details.get("bapiError"):
                    self.module.fail_json(msg=execution_details.get("bapiError"),
                                          response=execution_details)
                    break
                time.sleep(resync_retry_interval)
                resync_retry_count -= 1

        self.log("Deleted device with host '{0}' successfully.".format(
            host_name), "INFO")
        
    except Exception as e:
        error_msg = 'An error occurred during device deletion: {0}'.format(str(e))
        self.log(error_msg, "ERROR")
        self.status = "failed"

    return deletion_status, deletion_details




def main():

    """ 
    main entry point for module execution
    """

    accepoint_spec = {'dnac_host': {'required': True, 'type': 'str'},
                    'dnac_port': {'type': 'str', 'default': '443'},
                    'dnac_username': {'type': 'str', 'default': 'admin', 'aliases': ['user']},
                    'dnac_password': {'type': 'str', 'no_log': True},
                    'dnac_verify': {'type': 'bool', 'default': 'True'},
                    'dnac_version': {'type': 'str', 'default': '2.2.3.3'},
                    'dnac_debug': {'type': 'bool', 'default': False},
                    'dnac_log_level': {'type': 'str', 'default': 'WARNING'},
                    "dnac_log_file_path": {"type": 'str', "default": 'dnac.log'},
                    "dnac_log_append": {"type": 'bool', "default": True},
                    'dnac_log': {'type': 'bool', 'default': False},
                    'validate_response_schema': {'type': 'bool', 'default': True},
                    'config_verify': {'type': 'bool', "default": False},
                    'dnac_api_task_timeout': {'type': 'int', "default": 1200},
                    'dnac_task_poll_interval': {'type': 'int', "default": 2},
                    'config': {'required': True, 'type': 'list', 'elements': 'dict'},
                    'state': {'default': 'merged', 'choices': ['merged', 'deleted']}
                    }

    module = AnsibleModule(
        argument_spec=accepoint_spec,
        supports_check_mode=True
    )
   
    ccc_network = Accesspoint(module)
    state = ccc_network.params.get("state")

    if state not in ccc_network.supported_states:
        ccc_network.status = "invalid"
        ccc_network.msg = "State {0} is invalid".format(state)
        ccc_network.check_return_status() 

    ccc_network.validate_input_yml().check_return_status()
    config_verify = ccc_network.params.get("config_verify")

    for config in ccc_network.validated_config:
        # ccc_network.validate_input(config).check_return_status()
        # ccc_network.reset_values()
        # ccc_network.get_want(config).check_return_status()
        ccc_network.get_have(config).check_return_status()
        # ccc_network.get_diff_state_apply[state](config).check_return_status()
        ccc_network.delete_device(config).check_return_status()
        
        
    if config_verify:
        time.sleep(5)
        # ccc_network.verify_diff_state_apply[state](config).check_return_status()

    module.exit_json(**ccc_network.result)

if __name__ == '__main__':
    main()


