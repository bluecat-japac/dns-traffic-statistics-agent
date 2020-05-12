"""[Named module]
"""

# Copyright 2020 BlueCat Networks (USA) Inc. and its affiliates
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

import re
from config import NAMED_PATH_FILE
from common.constants import StatisticPerType, IPV4_PARTERN, IPV6_PARTERN
from common.common import FileExcution, is_ip_in_list_cidr

def get_regex_by_type(per_type):
    regex = ".*"
    if per_type == StatisticPerType.CLIENT:
        regex = "acl _TrafficStatisticsAgent_Clients.+"
    elif per_type == StatisticPerType.SERVER:
        regex = 'acl _TrafficStatisticsAgent_Servers.+'
    elif per_type == StatisticPerType.VIEW:
        regex = 'view \".+\"'
    return regex


class AclTrafficStatisticsAgent():
    def __init__(self, per_type, file_excution):
        self.type = per_type
        self.file_excution = file_excution
        # If named is None(not exist) OR named is empty,
        # will set list_ip and list_ip_cdir is empty list.
        self.list_ip, self.list_ip_cdir = self.__get_addr_acl() if self.file_excution.contents \
             else ([], [])

    def __get_addr_acl(self):
        regex = get_regex_by_type(self.type)
        findall_acl_addr = self.file_excution.findall_data(regex)

        list_ip = []
        list_ip_range = []
        for acl in findall_acl_addr:
            addrs_acl = re.findall("{}|{}".format(IPV4_PARTERN, IPV6_PARTERN), acl)
            for addr_acl in addrs_acl:
                if addr_acl in list_ip or addr_acl in list_ip_range or addr_acl[-1] == ':':
                    continue
                elif "/" in addr_acl:
                    list_ip_range.append(addr_acl)
                else:
                    list_ip.append(addr_acl.lower())
        return list_ip, list_ip_range

    def is_ip_available_acl(self, ip):
        if ip in self.list_ip or is_ip_in_list_cidr(ip, self.list_ip_cdir):
            return True
        else:
            return False


class ViewDNS():
    def __init__(self, file_excution):
        self.file_excution = file_excution
        # If named is None(not exist) OR named is empty,
        # will set list_views_name is empty list.
        self.list_views_name = self.__get_view_acl() if self.file_excution.contents \
             else []

    def __get_view_acl(self):
        regex = get_regex_by_type(StatisticPerType.VIEW)
        findall_views = self.file_excution.findall_data(regex)
        views = [view[6:-1] for view in findall_views]
        return views
    
    def is_available(self, view):
        return view in self.list_views_name


class NamedConfiguration():
    def __init__(self):
        self.file_excution = None
        self.acl_traffic_client = None
        self.acl_traffic_server = None
        self.dns_view = None

    def __load_file(self):
        self.file_excution = FileExcution(NAMED_PATH_FILE)

    def load_configuration(self):
        self.__load_file()
        self.acl_traffic_client = AclTrafficStatisticsAgent(StatisticPerType.CLIENT, self.file_excution)
        self.acl_traffic_server = AclTrafficStatisticsAgent(StatisticPerType.SERVER, self.file_excution)
        self.dns_view = ViewDNS(self.file_excution)
