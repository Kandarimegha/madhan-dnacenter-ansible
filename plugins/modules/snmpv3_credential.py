#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: snmpv3_credential
short_description: Resource module for Snmpv3 Credential
description:
- Manage operations create and update of the resource Snmpv3 Credential.
version_added: '1.0.0'
author: Rafael Campos (@racampos)
options:
  payload:
    description: Snmpv3 Credential's payload.
    suboptions:
      authPassword:
        description: Snmpv3 Credential's authPassword.
        type: str
      authType:
        description: Snmpv3 Credential's authType.
        type: str
      comments:
        description: Snmpv3 Credential's comments.
        type: str
      credentialType:
        description: Snmpv3 Credential's credentialType.
        type: str
      description:
        description: Snmpv3 Credential's description.
        type: str
      id:
        description: Snmpv3 Credential's id.
        type: str
      instanceTenantId:
        description: Snmpv3 Credential's instanceTenantId.
        type: str
      instanceUuid:
        description: Snmpv3 Credential's instanceUuid.
        type: str
      privacyPassword:
        description: Snmpv3 Credential's privacyPassword.
        type: str
      privacyType:
        description: Snmpv3 Credential's privacyType.
        type: str
      snmpMode:
        description: Snmpv3 Credential's snmpMode.
        type: str
      username:
        description: Snmpv3 Credential's username.
        type: str
    type: list
requirements:
- dnacentersdk
seealso:
# Reference by Internet resource
- name: Snmpv3 Credential reference
  description: Complete reference of the Snmpv3 Credential object model.
  link: https://dnacentersdk.readthedocs.io/en/latest/api/api.html#v3-0-0-summary
"""

EXAMPLES = r"""
- name: Update all
  cisco.dnac.snmpv3_credential:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present

- name: Create
  cisco.dnac.snmpv3_credential:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present

"""

RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": {},
        "url": "string"
      },
      "version": "string"
    }
"""