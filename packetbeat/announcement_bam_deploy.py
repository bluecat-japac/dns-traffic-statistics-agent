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
import os
import re

NAMED_PATH = '/replicated/jail/named/etc/named.conf'


class StatisticPerType():
    """[Statistic type]
    """
    CLIENT = "perClient"
    SERVER = "perServer"


def get_regex_by_type(per_type):
    regex = ".*"
    if per_type == StatisticPerType.CLIENT:
        regex = "acl _TrafficStatisticsAgent_Clients.*{\s(.+).*}"
    elif per_type == StatisticPerType.SERVER:
        regex = "acl _TrafficStatisticsAgent_Servers.*{\s(.+).*}"
    return regex


# Request to Agent HTTP
try:
    conn = httplib.HTTPConnection("127.0.0.1", 51415)
    conn.request("GET", "/announcement-deploy-from-bam")
except Exception as ex:
    pass

# Request to Packetbeat HTTP server
try:
    if os.path.exists(NAMED_PATH):
        named_f = open(NAMED_PATH, "r")
        contents = named_f.read()
        named_f.close()
        check_acl_client = True if re.findall(get_regex_by_type(StatisticPerType.CLIENT), contents) else False
        check_acl_server = True if re.findall(get_regex_by_type(StatisticPerType.SERVER), contents) else False
        if check_acl_client and check_acl_server:
            conn = httplib.HTTPConnection("127.0.0.1", 51416)
            conn.request("GET", "/announcement-deploy-from-bam")
except Exception as ex:
    pass
