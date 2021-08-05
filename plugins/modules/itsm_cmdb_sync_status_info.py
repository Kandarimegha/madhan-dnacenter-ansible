#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: itsm_cmdb_sync_status_info
short_description: Information module for Itsm Cmdb Sync Status
description:
- Get all Itsm Cmdb Sync Status.
version_added: '1.0.0'
author: Rafael Campos (@racampos)
options:
  status:
    description:
    - >
      Status query parameter. Supported values are "Success","Failed" and "Unknown". Providing other values will
      result in all the available sync job status.
    type: str
  date:
    description:
    - Date query parameter. Provide date in "YYYY-MM-DD" format.
    type: str
requirements:
- dnacentersdk
seealso:
# Reference by Internet resource
- name: Itsm Cmdb Sync Status reference
  description: Complete reference of the Itsm Cmdb Sync Status object model.
  link: https://dnacentersdk.readthedocs.io/en/latest/api/api.html#v3-0-0-summary
"""

EXAMPLES = r"""
- name: Get all Itsm Cmdb Sync Status
  cisco.dnac.itsm_cmdb_sync_status_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    status: string
    date: string
  register: result

"""

RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: list
  elements: dict
  sample: >
    [
      {
        "successCount": "string",
        "failureCount": "string",
        "devices": [
          {
            "deviceId": "string",
            "status": "string"
          }
        ],
        "unknownErrorCount": "string",
        "message": "string",
        "syncTime": "string"
      }
    ]
"""