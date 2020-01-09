"""[Common module]
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

from __future__ import division
import os
import re


def mili_to_micro(input_time):
    """[Averagetime, multiply 1000 so convert to microsecond]
    Arguments:
        input_time {[float]} -- [milisecond]
    Returns:
        [int] -- [microsecond]
    """
    return int(input_time*1000)


def micro_to_mili(input_time):
    """[Averagetime, divide 1000 so convert to milisecend]
    Arguments:
        input_time {[float]} -- [microsecond]
    Returns:
        [int] -- [milisecond]
    """
    return input_time/1000


def convert_ipv4(ip):
    return tuple(int(n) for n in ip.split('.'))


def convert_ipv6(ip):
    return tuple(int(n) for n in ip.split(':'))


def check_ipv4_in(addr, start, end):
    return convert_ipv4(start) < convert_ipv4(addr) < convert_ipv4(end)


def check_ipv6_in(addr, start, end):
    return convert_ipv6(start) < convert_ipv6(addr) < convert_ipv6(end)


def is_ip_in_cidr(ip, cidr):
    import ipaddress
    net = ipaddress.ip_network(u'{}'.format(cidr))
    ip_range = (str(net[0]), str(net[-1]))
    ip = ipaddress.ip_address(u'{}'.format(ip))
    if isinstance(ip, ipaddress.IPv4Address) and isinstance(net, ipaddress.IPv4Network):
        return check_ipv4_in(str(ip), *ip_range)
    elif isinstance(ip, ipaddress.IPv6Address) and isinstance(net, ipaddress.IPv6Network):
        return check_ipv6_in(str(ip), *ip_range)
    return False


def is_ip_in_list_cidr(ip, list_cidr):
    for cidr in list_cidr:
        if is_ip_in_cidr(ip, cidr):
            return True
    return False


class FileExcution():
    def __init__(self, file_path):
        self.contents = self.__read_file(file_path)

    def __read_file(self, file_path):
        if not os.path.exists(file_path):
            return None
        f = open(file_path ,"r")
        contents = f.read()
        f.close()
        return contents

    def findall_data(self, regex_content):
        findall = re.findall(regex_content, self.contents)
        return findall
