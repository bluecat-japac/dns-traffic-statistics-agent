#!/usr/bin/python

# Copyright 2019 BlueCat Networks (USA) Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""[Announcement_bam_deploy]
Send HTTS's request to reload Named after BDDS receive deploy from BAM
Informations(IP, port) need match with:
    - Agent: config.py in dns-snmp-agent
    - Packetbeat: statistics_config.json
"""
import httplib

# Request to Agent HTTP
try:
    conn = httplib.HTTPConnection("127.0.0.1", 51415)
    conn.request("GET", "/announcement-deploy-from-bam")
except Exception as ex:
    pass

# Request to Packetbeat HTTP server
try:
    conn = httplib.HTTPConnection("127.0.0.1", 51416)
    conn.request("GET", "/announcement-deploy-from-bam")
except Exception as ex:
    pass
