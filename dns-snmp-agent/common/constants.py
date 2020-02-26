"""[SNMP AGENT CONSTANTS]
"""

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

class TableOidStr():
    """[OID STR OF BCN DNS AGENT TABLE]
    """
    STAT_PER_CLIENT = "BCN-DNS-AGENT-MIB::statPerClientTable"
    STAT_PER_SERVER = "BCN-DNS-AGENT-MIB::statPerServerTable"
    AVG_TIME_PER_CLIENT = "BCN-DNS-AGENT-MIB::avgTimePerClientTable"
    AVG_TIME_PER_SERVER = "BCN-DNS-AGENT-MIB::avgTimePerServerTable"
    STAT_PER_VIEW = "BCN-DNS-AGENT-MIB::statPerViewTable"
    AVG_TIME_PER_VIEW = "BCN-DNS-AGENT-MIB::avgTimePerViewTable"
    BIND_STAT_PER_VIEW = "BCN-DNS-AGENT-MIB::bindStatPerViewTable"


class StatisticPerType():
    """[Statistic type]
    """
    CLIENT = "perClient"
    SERVER = "perServer"
    VIEW = "perView"
    BIND_VIEW = "perBindView"


class QryType():
    """[Query type to define in mib]
    """
    METRIC_FOR_AGENT = {
        "total_queries": 1,
        "total_responses": 2,
        "referral": 3,
        "nx_rrset": 4,
        "nx_domain": 5,
        "recursive": 6,
        "successful": 7,
        "format_error": 8,
        "server_fail": 9,
        "duplicated": 10,
        "refused": 11,
        "other_rcode": 12,
        "successful_recursive": 13,
        "successful_noauthans": 14,
        "truncated": 15
    }
    METRIC_FOR_BIND_VIEW = {
        "totalQueries": 1,
        "totalResponses": 2,
        "NXDOMAIN": 3,
        "SERVFAIL": 4,
        "FORMERR": 5,
        "Retry": 6,
        "QueryTimeout": 7,
        "QryRTT10": 8,
        "QryRTT100": 9,
        "QryRTT500": 10,
        "QryRTT800": 11,
        "QryRTT1600": 12,
        "QryRTT1600+": 13,
        "REFUSED": 14,
        "OtherError": 15
    }
    METRIC_AVG_TIME = "average_time"

class ErrorMessage():
    """[Error message]
    """
    NOT_FOUND_URL = "No such URL."

BLACK_LIST_VIEW = ["_bind"]
IPV4_PARTERN  = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2}|)'
IPV6SEG  = r'(?:(?:[0-9a-fA-F]){1,4})'
IPV6GROUPS = (
    r'(?:' + IPV6SEG + r':){7,7}' + IPV6SEG,                  # 1:2:3:4:5:6:7:8
    r'(?:' + IPV6SEG + r':){1,7}:',                           # 1::                                 1:2:3:4:5:6:7::
    r'(?:' + IPV6SEG + r':){1,6}:' + IPV6SEG,                 # 1::8               1:2:3:4:5:6::8   1:2:3:4:5:6::8
    r'(?:' + IPV6SEG + r':){1,5}(?::' + IPV6SEG + r'){1,2}',  # 1::7:8             1:2:3:4:5::7:8   1:2:3:4:5::8
    r'(?:' + IPV6SEG + r':){1,4}(?::' + IPV6SEG + r'){1,3}',  # 1::6:7:8           1:2:3:4::6:7:8   1:2:3:4::8
    r'(?:' + IPV6SEG + r':){1,3}(?::' + IPV6SEG + r'){1,4}',  # 1::5:6:7:8         1:2:3::5:6:7:8   1:2:3::8
    r'(?:' + IPV6SEG + r':){1,2}(?::' + IPV6SEG + r'){1,5}',  # 1::4:5:6:7:8       1:2::4:5:6:7:8   1:2::8
    IPV6SEG + r':(?:(?::' + IPV6SEG + r'){1,6})',             # 1::3:4:5:6:7:8     1::3:4:5:6:7:8   1::8
    r':(?:(?::' + IPV6SEG + r'){1,7}|:)'                     # ::2:3:4:5:6:7:8    ::2:3:4:5:6:7:8  ::8       ::
)
IPV6_PARTERN = '|'.join(['(?:{})'.format(g) for g in IPV6GROUPS[::-1]])  # Reverse rows for greedy match
