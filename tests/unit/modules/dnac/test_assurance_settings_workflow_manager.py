# Copyright (c) 2024 Cisco and/or its affiliates.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Make coding more python3-ish
from __future__ import absolute_import, division, print_function

__metaclass__ = type
from unittest.mock import patch
from ansible_collections.cisco.dnac.plugins.modules import assurance_settings_workflow_manager
from .dnac_module import TestDnacModule, set_module_args, loadPlaybookData

class TestDnacAssuranceSettings(TestDnacModule):
    module = assurance_settings_workflow_manager
    test_data = loadPlaybookData("assurance_settings_workflow_manager")
    playbook_config_updation= test_data.get("playbook_config_updation")
    playbook_config_creation = test_data.get("playbook_config_creation")

    def setUp(self):
        super(TestDnacAssuranceSettings, self).setUp()

        self.mock_dnac_init = patch(
            "ansible_collections.cisco.dnac.plugins.module_utils.dnac.DNACSDK.__init__")
        self.run_dnac_init = self.mock_dnac_init.start()
        self.run_dnac_init.side_effect = [None]
        self.mock_dnac_exec = patch(
            "ansible_collections.cisco.dnac.plugins.module_utils.dnac.DNACSDK._exec"
        )
        self.run_dnac_exec = self.mock_dnac_exec.start()

        self.load_fixtures()

    def tearDown(self):
        super(TestDnacAssuranceSettings, self).tearDown()
        self.mock_dnac_exec.stop()
        self.mock_dnac_init.stop()

    def load_fixtures(self, response=None, device=""):
        """
        Load fixtures for user.
        """
        if "updation" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("issue_exist"),
                self.test_data.get("prev_issue_exist"),
                self.test_data.get("issue_updation"),
                self.test_data.get("issue_exist_after_updation")
            ]

        if "creation" in self._testMethodName:
            self.run_dnac_exec.side_effect = [
                self.test_data.get("Testing_creation_exit"),
                self.test_data.get("issue_creation"),
                self.test_data.get("exist_after_creation"),
                # self.test_data.get("issue_exist_after_updation")
            ]

    def test_assurance_settings_workflow_manager_with_issue_resolve_updation(self):
        """
        Test case for healthscore settings workflow manager when creating a device credential.

        This test case checks the behavior of the healthscore settings workflow manager when creating a new device credentials in the specified DNAC.
        """
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_version="2.3.7.6",
                dnac_log=True,
                state="merged",
                config_verify=True,
                config=self.playbook_config_updation
            )
        )
        result = self.execute_module(changed= True, failed=False)
        print(result['response'][0]['assurance_user_defined_issue_settings']['response'])
        self.assertEqual(
            result['response'][0]['assurance_user_defined_issue_settings']['response'],
            {'updated user defined issue Details': {'name': 'test_user_defined', 'description': 'testing settings 1', 'rules': 
              [{'severity': '2', 'facility': 'redundancy', 'mnemonic': 'peer monitor event', 'pattern': 'issue test', 'occurrences': 1, 
              'duration_in_minutes': 2}], 'is_enabled': True, 'priority': 'P2', 'is_notification_enabled': True, 'prev_name': 'test_seema_1'}}
        )

    def test_assurance_settings_workflow_manager_with_issue_resolve_creation(self):
        """
        Test case for healthscore settings workflow manager when creating a device credential.

        This test case checks the behavior of the healthscore settings workflow manager when creating a new device credentials in the specified DNAC.
        """
        set_module_args(
            dict(
                dnac_host="1.1.1.1",
                dnac_username="dummy",
                dnac_password="dummy",
                dnac_version="2.3.7.6",
                dnac_log=True,
                state="merged",
                config_verify=True,
                config=self.playbook_config_creation
            )
        )
        result = self.execute_module(changed= True, failed=False)
        print(result['response'][0]['assurance_user_defined_issue_settings']['response'])
        self.assertEqual(
            result['response'][0]['assurance_user_defined_issue_settings']['response'],
            {'created user-defined issue': {'name': 'Testing_creation', 'description': 'testing settings 1',
            'rules': [{'severity': '2', 'facility': 'Alert', 'mnemonic': 'peer monitor event', 'pattern': 'issue test',
            'occurrences': 1, 'duration_in_minutes': 2}], 'is_enabled': True, 'priority': 'P2', 'is_notification_enabled': True}}
        )

    # def test_healthscore_settings_workflow_manager_update_not_required(self):
    #     """
    #     Test case for healthscore settings workflow manager when creating a device credential.

    #     This test case checks the behavior of the healthscore settings workflow manager when creating a new device credentials in the specified DNAC.
    #     """
    #     set_module_args(
    #         dict(
    #             dnac_host="1.1.1.1",
    #             dnac_username="dummy",
    #             dnac_password="dummy",
    #             dnac_log=True,
    #             state="merged",
    #             config=self.playbook_config_updation
    #         )
    #     )
    #     result = self.execute_module(changed= True, failed=False)
    #     print(result['response'][0]['device_healthscore_settings']['msg'])
    #     self.assertEqual(
    #         result['response'][0]['device_healthscore_settings']['msg'],
    #         {'linkDiscardThreshold': "Healthscore setting doesn't require an update"}
    #     )

    # def test_healthscore_settings_workflow_manager_error_while_update(self):
    #     """
    #     Test case for healthscore settings workflow manager when creating a device credential.

    #     This test case checks the behavior of the healthscore settings workflow manager when creating a new device credentials in the specified DNAC.
    #     """
    #     set_module_args(
    #         dict(
    #             dnac_host="1.1.1.1",
    #             dnac_username="dummy",
    #             dnac_password="dummy",
    #             dnac_log=True,
    #             state="merged",
    #             config_verify=True,
    #             config=self.playbook_config_updation
    #         )
    #     )
    #     result = self.execute_module(changed= False, failed=True)
    #     print(result['response'][0]['device_healthscore_settings']['msg'])
    #     self.assertEqual(
    #         result['response'][0]['device_healthscore_settings']['msg'],
    #         {}
    #     )

    # def test_healthscore_settings_workflow_manager_updation(self):
    #     """
    #     Test case for healthscore settings workflow manager when creating a device credential.

    #     This test case checks the behavior of the healthscore settings workflow manager when creating a new device credentials in the specified DNAC.
    #     """
    #     set_module_args(
    #         dict(
    #             dnac_host="1.1.1.1",
    #             dnac_username="dummy",
    #             dnac_password="dummy",
    #             dnac_log=True,
    #             state="merged",
    #             config_verify=True,
    #             config=self.playbook_config_updation
    #         )
    #     )
    #     result = self.execute_module(changed= True, failed=False)
    #     print(result['response'][0]['device_healthscore_settings']['msg'])
    #     self.assertEqual(
    #         result['response'][0]['device_healthscore_settings']['msg'],
    #         {'linkDiscardThreshold': 'Healthscore settings Updated Successfully'}
    #     )

    # def test_healthscore_settings_workflow_manager_verification_failure(self):
    #     """
    #     Test case for healthscore settings workflow manager when creating a device credential.

    #     This test case checks the behavior of the healthscore settings workflow manager when creating a new device credentials in the specified DNAC.
    #     """
    #     set_module_args(
    #         dict(
    #             dnac_host="1.1.1.1",
    #             dnac_username="dummy",
    #             dnac_password="dummy",
    #             dnac_log=True,
    #             state="merged",
    #             config_verify=True,
    #             config=self.playbook_config_updation
    #         )
    #     )
    #     result = self.execute_module(changed= True, failed=True)
    #     print(result['response'][0]['device_healthscore_settings']['msg'])
    #     self.assertEqual(
    #         result['response'][0]['device_healthscore_settings']['msg'],
    #         {}
    #     )

