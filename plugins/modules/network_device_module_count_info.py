#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_module_count_info
short_description: Information module for Network Device Module Count
description:
- Get all Network Device Module Count.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  deviceId:
    description:
    - DeviceId query parameter.
    type: str
  nameList:
    description:
    - NameList query parameter.
    type: list
  vendorEquipmentTypeList:
    description:
    - VendorEquipmentTypeList query parameter.
    type: list
  partNumberList:
    description:
    - PartNumberList query parameter.
    type: list
  operationalStateCodeList:
    description:
    - OperationalStateCodeList query parameter.
    type: list
requirements:
- dnacentersdk >= 2.3.1
- python >= 3.5
seealso:
# Reference by Internet resource
- name: Network Device Module Count reference
  description: Complete reference of the Network Device Module Count object model.
  link: https://dnacentersdk.readthedocs.io/en/latest/api/api.html#v3-0-0-summary
"""

EXAMPLES = r"""
- name: Get all Network Device Module Count
  cisco.dnac.network_device_module_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers:
      custom: value
    deviceId: string
    nameList: []
    vendorEquipmentTypeList: []
    partNumberList: []
    operationalStateCodeList: []
  register: result

"""

RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": 0,
      "version": "string"
    }
"""
