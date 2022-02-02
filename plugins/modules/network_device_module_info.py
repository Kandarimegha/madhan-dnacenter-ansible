#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_module_info
short_description: Information module for Network Device Module
description:
- Get all Network Device Module.
- Get Network Device Module by id.
- Returns Module info by id.
- Returns modules by specified device id.
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
  limit:
    description:
    - Limit query parameter.
    type: str
  offset:
    description:
    - Offset query parameter.
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
  id:
    description:
    - Id path parameter.
    type: str
requirements:
- dnacentersdk == 2.4.5
- python >= 3.5
notes:
  - SDK Method used are
    devices.Devices.get_module_info_by_id,
    devices.Devices.get_modules,

  - Paths used are
    get /dna/intent/api/v1/network-device/module,
    get /dna/intent/api/v1/network-device/module/{id},

"""

EXAMPLES = r"""
- name: Get all Network Device Module
  cisco.dnac.network_device_module_info:
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
    limit: string
    offset: string
    nameList: []
    vendorEquipmentTypeList: []
    partNumberList: []
    operationalStateCodeList: []
  register: result

- name: Get Network Device Module by id
  cisco.dnac.network_device_module_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers:
      custom: value
    id: string
  register: result

"""

RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "assemblyNumber": "string",
        "assemblyRevision": "string",
        "attributeInfo": {},
        "containmentEntity": "string",
        "description": "string",
        "entityPhysicalIndex": "string",
        "id": "string",
        "isFieldReplaceable": "string",
        "isReportingAlarmsAllowed": "string",
        "manufacturer": "string",
        "moduleIndex": 0,
        "name": "string",
        "operationalStateCode": "string",
        "partNumber": "string",
        "serialNumber": "string",
        "vendorEquipmentType": "string"
      },
      "version": "string"
    }
"""
