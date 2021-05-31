"""[SNMP SUBAGENT OF DNS TRAFFIC STATISTIC]
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

import sys
import threading
import netsnmpagent

from config import logger, AGENT_CONFIGURATION
from http_server.http_agent_server import start_http_server
from common.constants import TableOidStr


def initialize(prg_name):
    ###
    #	Init agent
    ###
    try:
        agent = netsnmpagent.netsnmpAgent(
            AgentName=AGENT_CONFIGURATION["agent_name"],
            MasterSocket=AGENT_CONFIGURATION["master_socket"],
            PersistenceDir=AGENT_CONFIGURATION["persistence_dir"]
        )
    except netsnmpagent.netsnmpAgentException as ex:
        logger.error("{0}: {1}".format(prg_name, ex))

    ###
    #	Init table
    ###
    # Init dns statistic per client
    stat_per_client_table = agent.Table(
        oidstr=TableOidStr.STAT_PER_CLIENT,
        indexes=[
            agent.OctetString(),					# client ip
            agent.Integer32()					    # bcnDnsStatAgentQryTypes
        ],
        columns=[
            # Columns begin with an index of 2 here because 1 is actually
            # used for the single index column above.
            # We must explicitly specify that the columns should be SNMPSETable.
            (1, agent.OctetString(), True),		    # client ip
            (2, agent.Integer32(), True),		    # bcnDnsStatAgentQryTypes
            (3, agent.Counter64(), True)		    # statistic dns value
        ],
        # Allow adding new records
        extendable=True
    )

    # Init table of average response time in the last interval (e.g. 1 minute) and are classified by DNS client.
    avg_time_per_client_table = agent.Table(
        oidstr=TableOidStr.AVG_TIME_PER_CLIENT,
        indexes=[
            agent.OctetString() 					# client ip
        ],
        columns=[
            (1, agent.OctetString(), True),		    # client ip
            (2, agent.Integer32(), True)            # Average time in micro seconds
        ],
        # Allow adding new records
        extendable=True
    )

    # Init dns statistic per auth dns server
    stat_per_server_table = agent.Table(
        oidstr=TableOidStr.STAT_PER_SERVER,
        indexes=[
            agent.OctetString(),					# Server ip
            agent.Integer32()					    # bcnDnsStatAgentQryTypes
        ],
        columns=[
            # Columns begin with an index of 2 here because 1 is actually
            # used for the single index column above.
            (1, agent.OctetString(), True),		    # Server ip
            (2, agent.Integer32(), True),		    # bcnDnsStatAgentQryTypes
            (3, agent.Counter64(), True)		    # statistic dns value
        ],
        # Allow adding new records
        extendable=True
    )

    # Init table of average response time in the last interval (e.g. 1 minute) and are classified by Authoritative DNS Server or Forwarder.
    avg_time_per_server_table = agent.Table(
        oidstr=TableOidStr.AVG_TIME_PER_SERVER,
        indexes=[
            agent.OctetString() 					# server ip
        ],
        columns=[
            (1, agent.OctetString(), True),		    # server ip
            (2, agent.Integer32(), True)            # Average time in micro seconds
        ],
        # Allow adding new records
        extendable=True
    )

    # Init table of statistics per each view from Packetbeat.
    stat_per_view_table = agent.Table(
        oidstr=TableOidStr.STAT_PER_VIEW,
        indexes=[
            agent.DisplayString(),					# view
            agent.Integer32()					    # bcnDnsStatAgentQryTypes
        ],
        columns=[
            # Columns begin with an index of 2 here because 1 is actually
            # used for the single index column above.
            (1, agent.DisplayString(), True),		# view
            (2, agent.Integer32(), True),		    # bcnDnsStatAgentQryTypes
            (3, agent.Counter64(), True)            # The value of the reported statistic
        ],
        # Allow adding new records
        extendable=True
    )

    # Init table of average response time in the last interval (e.g. 1 minute) and are classified by view.
    avg_time_per_view_table = agent.Table(
        oidstr=TableOidStr.AVG_TIME_PER_VIEW,
        indexes=[
            agent.DisplayString() 					# view
        ],
        columns=[
            (1, agent.DisplayString(), True),		# view
            (2, agent.Integer32(), True)            # Average time in micro seconds
        ],
        # Allow adding new records
        extendable=True
    )

    # Init table of statistics per each view from the time the BIND service starts running.
    bind_stat_per_view_table = agent.Table(
        oidstr=TableOidStr.BIND_STAT_PER_VIEW,
        indexes=[
            agent.DisplayString(),					# bindView
            agent.Integer32()					    # bcnDnsBindStatPerViewAgentQryTypes
        ],
        columns=[
            # Columns begin with an index of 2 here because 1 is actually
            # used for the single index column above.
            (1, agent.DisplayString(), True),		# bindView
            (2, agent.Integer32(), True),		    # bcnDnsBindStatPerViewAgentQryTypes
            (3, agent.Counter64(), True)            # The value of the reported statistic from bind
        ],
        # Allow adding new records
        extendable=True
    )

    table = {
        TableOidStr.STAT_PER_CLIENT: {
            "table": stat_per_client_table,
            "table_value": {}
        },
        TableOidStr.AVG_TIME_PER_CLIENT: {
            "table": avg_time_per_client_table
        },
        TableOidStr.STAT_PER_SERVER: {
            "table": stat_per_server_table,
            "table_value": {}
        },
        TableOidStr.AVG_TIME_PER_SERVER: {
            "table": avg_time_per_server_table
        },
        TableOidStr.STAT_PER_VIEW: {
            "table": stat_per_view_table,
            "table_value": {}
        },
        TableOidStr.AVG_TIME_PER_VIEW: {
            "table": avg_time_per_view_table
        },
        TableOidStr.BIND_STAT_PER_VIEW: {
            "table": bind_stat_per_view_table
        }
    }

    return agent, table


def main():
    """[Main function]
    """

    prg_name = sys.argv[0]
    ###
    #	Start agent
    ###
    version = "v2.8.3"
    logger.info("Start DNS Statistic Agent verion {}".format(version))
    http_proccess = None
    try:
        agent, mib_table = initialize(prg_name)
        agent.start()
        logger.info(
            "{0}: AgentX connection to snmpd established.".format(prg_name))
        http_proccess = threading.Thread(target=start_http_server,
                                         args=(agent, mib_table))
        http_proccess.start()
    except netsnmpagent.netsnmpAgentException as netsnmp_agent_exception:
        logger.error("{0}: {1}".format(prg_name, netsnmp_agent_exception))
        agent.shutdown()
        # Restart
        main()

    is_starting = True
    try:
        while is_starting:
            # Block and process SNMP requests, if available
            agent.check_and_process()
    except Exception as ex:
        logger.error(ex)
        is_starting = False
    finally:
        logger.info("Shutdown agent")
        agent.shutdown()
        if http_proccess is not None:
            logger.info("Join http_proccess thread")
            http_proccess.join()


if __name__ == "__main__":
    main()
