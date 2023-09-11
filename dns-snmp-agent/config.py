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

import os
import logging
from logging.handlers import TimedRotatingFileHandler

###
#   HTTPServer's configuration
###
HTTP_CONFIGURATION = {
    "host": "127.0.0.1",
    "port": 51415
}

###
#   Subagent's configuration
###
AGENT_CONFIGURATION = {
    "agent_name": "DnsStatisticAgent",
    "master_socket": "/var/agentx/master",
    "persistence_dir": "/etc/snmp/"
}

###
#   BIND's configuration
###
BIND_CONFIGURATION = {
    "host": "127.0.0.1",
    "port": 8053,
    "stats_path": "/json/v1/server"
}


###
# Named
###
NAMED_PATH_FILE = "/replicated/jail/named/etc/named.conf"

###
#   Config logger
###
DEBUG = False
LOG_PATH = "/var/log/dns_stat_agent"
LOG_NAME = "dns_stat_agent.log"
if not os.path.exists(LOG_PATH):
    os.mkdir(LOG_PATH)
if DEBUG:
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
else:
    logger = logging.getLogger("stat_counter_agent")
    logger.setLevel(logging.INFO)

handler = TimedRotatingFileHandler(LOG_PATH + "/" + LOG_NAME, when="midnight", interval=1, backupCount=30)
handler.suffix = "%Y%m%d"
handler.extMatch = re.compile(r"^\d{4}\d{2}\d{2}$")

log_formater = logging.Formatter("%(asctime)s:%(levelname)s:%(message)s")
handler.setFormatter(log_formater)
logger.addHandler(handler)
