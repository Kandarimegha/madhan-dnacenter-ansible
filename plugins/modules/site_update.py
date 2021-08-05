#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: site_update
short_description: Resource module for Site Update
description:
- Manage operation update of the resource Site Update.
version_added: '1.0.0'
author: Rafael Campos (@racampos)
options:
  site:
    description: Site Update's site.
    suboptions:
      area:
        description: Site Update's area.
        suboptions:
          name:
            description: Site Update's name.
            type: str
          parentName:
            description: Site Update's parentName.
            type: str
        type: dict
      building:
        description: Site Update's building.
        suboptions:
          address:
            description: Site Update's address.
            type: str
          latitude:
            description: Site Update's latitude.
            type: int
          longitude:
            description: Site Update's longitude.
            type: int
          name:
            description: Site Update's name.
            type: str
          parentName:
            description: Site Update's parentName.
            type: str
        type: dict
      floor:
        description: Site Update's floor.
        suboptions:
          height:
            description: Site Update's height.
            type: int
          length:
            description: Site Update's length.
            type: int
          name:
            description: Site Update's name.
            type: str
          rfModel:
            description: Site Update's rfModel.
            type: str
          width:
            description: Site Update's width.
            type: int
        type: dict
    type: dict
  siteId:
    description: SiteId path parameter. Site id to which site details to be updated.
    type: str
  type:
    description: Site Update's type.
    type: str
requirements:
- dnacentersdk
seealso:
# Reference by Internet resource
- name: Site Update reference
  description: Complete reference of the Site Update object model.
  link: https://dnacentersdk.readthedocs.io/en/latest/api/api.html#v3-0-0-summary
"""

EXAMPLES = r"""
- name: Update by id
  cisco.dnac.site_update:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    site:
      area:
        name: string
        parentName: string
      building:
        address: string
        latitude: 0
        longitude: 0
        name: string
        parentName: string
      floor:
        height: 0
        length: 0
        name: string
        rfModel: string
        width: 0
    siteId: string
    type: string

- name: Delete by id
  cisco.dnac.site_update:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    siteId: string

"""

RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "result": "string",
      "response": {
        "endTime": "string",
        "version": "string",
        "startTime": "string",
        "progress": "string",
        "data": "string",
        "serviceType": "string",
        "operationIdList": [
          "string"
        ],
        "isError": "string",
        "rootId": "string",
        "instanceTenantId": "string",
        "id": "string"
      },
      "status": "string"
    }
"""