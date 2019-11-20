"""[HTTP AGENT SERVER]
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


# Config package for python version
try:
    # Version 2
    from SimpleHTTPServer import SimpleHTTPRequestHandler as BaseHTTPRequestHandler
except ImportError:
    # Version 3
    from http.server import BaseHTTPRequestHandler

try:
    # Version 2
    from SocketServer import TCPServer as HTTPServer
except ImportError:
    # Version 3
    from http.server import HTTPServer

import json
import re
import traceback
from config import logger, HTTP_CONFIGURATION, NAMED_PATH_FILE
from common.constants import QryType, StatisticPerType, TableOidStr, IPV4_PARTERN, IPV6_PARTERN
from common.common import mili_to_micro, FileExcution
from common.bind import get_stats_views
global AGENT, MIB_TABLE, ROW_DICT
AGENT, MIB_TABLE = None, None
ROW_DICT = {}


def get_old_counter_value(ip, dns_query_type_id, table_value):
    """[Get old statistic value of metric]
    Arguments:
        ip {[String]} -- [Ip address]
        dns_query_type_id {[Int]} -- [Id of dns query type]
        table_value {[list]} -- [List of statistic data in mib table]
    Returns:
        [int] -- [Value of metric]
    """
    for value in table_value:
        if value[1] == ip and value[2] == dns_query_type_id:
            return value[3]
    return 0


def get_table_by_type(stat_type, is_time_table=False):
    """[summary]
    Arguments:
        stat_type {[String]} -- [Statistic type]
    Keyword Arguments:
        is_time_table {bool} -- [Enable if want to get
            avg time table of this statistic type] (default: {False})
    Returns:
        [TABLE] -- [Table of statistics]
    """
    try:
        if stat_type == StatisticPerType.CLIENT:
            if is_time_table:
                return MIB_TABLE[TableOidStr.AVG_TIME_PER_CLIENT]
            return MIB_TABLE[TableOidStr.STAT_PER_CLIENT]
        elif stat_type == StatisticPerType.SERVER:
            if is_time_table:
                return MIB_TABLE[TableOidStr.AVG_TIME_PER_SERVER]
            return MIB_TABLE[TableOidStr.STAT_PER_SERVER]
        elif stat_type == StatisticPerType.VIEW:
            if is_time_table:
                return MIB_TABLE[TableOidStr.AVG_TIME_PER_VIEW]
            return MIB_TABLE[TableOidStr.STAT_PER_VIEW]
        elif stat_type == StatisticPerType.BIND_VIEW:
            return MIB_TABLE[TableOidStr.BIND_STAT_PER_VIEW]
        else:
            return None     
    except KeyError as key_exception:
        logger.error("Get table by type has key error {}".format(key_exception))
        return None
        
def set_view_default_named(file_excution):
    findall_views = file_excution.findall_data('view \".+\"')
    views = [view[6:-1] for view in findall_views]
    metrics = QryType.METRIC_FOR_AGENT.keys()
    metrics.append(QryType.METRIC_AVG_TIME)
    views_stats_default = dict()
    for view in views:
        for metric_name in metrics:
            AgentServer.update_to_mib_table(StatisticPerType.VIEW, view, metric_name, 0)
    

def set_clients_default_named(file_excution):
    clients_stats_default = dict()
    findall_acl_clients = file_excution.findall_data('acl _TrafficStatisticsAgent_Clients.+')
    metrics = QryType.METRIC_FOR_AGENT.keys()
    metrics.append(QryType.METRIC_AVG_TIME)
    list_client = []
    for acl in findall_acl_clients:
        clients = re.findall("{}|{}".format(IPV4_PARTERN, IPV6_PARTERN), acl)
        for client in clients:
            if client[-2:] == '.0' or client[-1] == ':' or client in list_client:
                continue
            logger.info("Add client {} to mib".format(client))
            list_client.append(client)
            for metric_name in metrics:
                AgentServer.update_to_mib_table(StatisticPerType.CLIENT, client, metric_name, 0)


def set_servers_default_named(file_excution):
    servers_stats_default = dict()
    findall_acl_servers = file_excution.findall_data('acl _TrafficStatisticsAgent_Servers.+')
    metrics = QryType.METRIC_FOR_AGENT.keys()
    metrics.append(QryType.METRIC_AVG_TIME)
    list_server = []
    for acl in findall_acl_servers:
        servers = re.findall("{}|{}".format(IPV4_PARTERN, IPV6_PARTERN), acl)
        for server in servers:
            if server[-2:] == '.0' or server[-1] == ':' or server in list_server:
                continue
            logger.info("Add server {} to mib".format(server))
            list_server.append(server)
            for metric_name in metrics:
                AgentServer.update_to_mib_table(StatisticPerType.SERVER, server, metric_name, 0)

class AgentServer(BaseHTTPRequestHandler):

    @classmethod
    def set_default_stats(cls):
        try:
            file_excution = FileExcution(NAMED_PATH_FILE)
            if file_excution.contents is None:
                logger.warn("Named.conf is not exist")
                pass

            # logger.debug("{}".format(str(file_excution.content)))
            stats_default = dict({"stats_map": dict()})
            views_default = set_view_default_named(file_excution)
            clients_default = set_clients_default_named(file_excution)
            servers_default = set_servers_default_named(file_excution)
        except Exception as ex:
            logger.error("AgentServer init error: {}".format(ex))
            logger.error(traceback.format_exc())

    @classmethod
    def update_to_mib_table(cls, stat_type, ip_or_view, dns_query_type, value):
        """[Update each metric data to mib table]

        Arguments:
            stat_type {[String]} -- [Statistic type per client or AS]
            ip_or_view {[String]} -- [Ip address of client or AS or name of view]
            dns_query_type {[String]} -- [The statistic type supported by
                the DNS Traffic Statistic Agent]
            value {[float]} -- [The value of the reported statistic]
        """
        try:
            logger.debug(
                "Update {}-{}-{}-{} to mib table".format(stat_type, ip_or_view, dns_query_type, value))

            is_time_query_type = True if dns_query_type == QryType.METRIC_AVG_TIME else False
            table = get_table_by_type(stat_type, is_time_query_type)

            if not table:
                logger.error("Stat_type is not correct.")
                return

            if stat_type == StatisticPerType.BIND_VIEW:
                bind_view = ip_or_view
                dns_query_type_id = QryType.METRIC_FOR_BIND_VIEW[dns_query_type]
                metric_row = table["table"].addRow(
                    [AGENT.DisplayString(bind_view), AGENT.Integer32(dns_query_type_id)])
                metric_row.setRowCell(1, AGENT.DisplayString(bind_view))
                metric_row.setRowCell(
                    2, AGENT.Integer32(dns_query_type_id))
                metric_row.setRowCell(3, AGENT.Counter64(value))
            elif is_time_query_type: #if dns_query_type == QryType.METRIC_AVG_TIME
                avg_time_row = table["table"].addRow(
                    [AGENT.OctetString(ip_or_view)])
                avg_time_row.setRowCell(1, AGENT.OctetString(ip_or_view))
                avg_time_row.setRowCell(
                    2, AGENT.Integer32(mili_to_micro(value)))
            else:
                dns_query_type_id = QryType.METRIC_FOR_AGENT[dns_query_type]
                row_index = "{}|{}|{}".format(stat_type, ip_or_view, dns_query_type_id)
                if row_index in ROW_DICT:
                    table_value = table["table_value"]
                    metric_row = ROW_DICT[row_index]
                    old_value = get_old_counter_value(
                        ip_or_view, dns_query_type_id, table_value.values()[1:])
                    metric_row.setRowCell(
                        3, AGENT.Counter64(old_value + value))
                else:
                    metric_row = table["table"].addRow(
                        [AGENT.OctetString(ip_or_view), AGENT.Integer32(dns_query_type_id)])
                    metric_row.setRowCell(1, AGENT.OctetString(ip_or_view))
                    metric_row.setRowCell(
                        2, AGENT.Integer32(dns_query_type_id))
                    metric_row.setRowCell(3, AGENT.Counter64(value))
                    ROW_DICT.update({row_index: metric_row})
        except KeyError as key_exception:
            logger.error(
                "Update_to_mib_table key error {}".format(key_exception))
        except TypeError as type_exception:
            logger.error("Input {} wrong format".format(type_exception))

    @classmethod
    def update_mib_stat_counter(cls, pb_request_content):
        """[Update all statistic dns receiver from PacketBeat and Bind]

        Arguments:
            pb_request_content {[dict]} -- [statistic content get json request's json data
                Example: {
                "start": "2019-6-6,18:23:23.1",
                "end": "2019-6-6,18:23:24.9",
                "stats_map": {
                    "192.168.88.23": {"type": "perClient", "dnsmetrics": {"total_queries":0,"total_queries_new":0,
                    "total_responses":2,"total_responses_new":2,"recursive":0,"duplicated":0,"average_time":0,"successful":0,
                    "server_fail":0,"nx_domain":0,"format_error":2,"nx_rrset":0,"referral":0,"refused":0,"other_rcode":0}}}}]
        """
        global MIB_TABLE
        # Clear up 3 tables of avgTime and table of statistic views from bind
        MIB_TABLE[TableOidStr.AVG_TIME_PER_CLIENT]["table"].clear()
        MIB_TABLE[TableOidStr.AVG_TIME_PER_SERVER]["table"].clear()
        MIB_TABLE[TableOidStr.AVG_TIME_PER_VIEW]["table"].clear()
        MIB_TABLE[TableOidStr.BIND_STAT_PER_VIEW]["table"].clear()

        # Sync-up with data in mib
        MIB_TABLE[TableOidStr.STAT_PER_CLIENT]["table_value"] = MIB_TABLE[TableOidStr.STAT_PER_CLIENT]["table"].value()
        MIB_TABLE[TableOidStr.STAT_PER_SERVER]["table_value"] = MIB_TABLE[TableOidStr.STAT_PER_SERVER]["table"].value()
        MIB_TABLE[TableOidStr.STAT_PER_VIEW]["table_value"] = MIB_TABLE[TableOidStr.STAT_PER_VIEW]["table"].value()

        list_statistic_data = pb_request_content.get('stats_map', [])
        logger.info("Update {} client/server/view from PB to mib table".format(
            len(list_statistic_data)))
        for statistic_key in list_statistic_data:
            ip = statistic_key
            stat_type = list_statistic_data[statistic_key]['type']
            metrics = list_statistic_data[statistic_key]['dnsmetrics']
            for metric_name in metrics:
                value = metrics[metric_name]
                cls.update_to_mib_table(stat_type, ip, metric_name, value)

        # Update statistic of view to mib
        stats_views = get_stats_views()
        logger.info("Update {} view from bind channel to mib table".format(
            len(stats_views)))
        for view in stats_views:
            metrics = stats_views[view]
            for metric_name in metrics:
                value = metrics[metric_name]
                cls.update_to_mib_table(
                    StatisticPerType.BIND_VIEW, view, metric_name, value)

    def _repsonse_template(self, code, status):
        """[Prepare content for response]

        Arguments:
            code {[Int]} -- [HTTP code status]
            status {[String]} -- [Status message]

        Returns:
            [dict] -- [Template response content]
        """
        return {
            'status': status,
            'code': code
        }

    def do_GET(self):
        logger.info("Have request GET API")
        if self.path == '/counter':
            logger.info("Receive GET Counter api")
            content_len = int(self.headers.get('content-length'))
            content = json.loads(self.rfile.read(content_len))
            logger.debug("Content receive from PB")
            logger.debug(content)
            self.update_mib_stat_counter(content)

            # Response
            logger.info("Reponse to client")
            self.send_response(200)
            self.end_headers()
            response_content = self._repsonse_template(200, 'SUCCESSFUL')
            self.wfile.write(json.dumps(response_content).encode())
        elif self.path == '/announcement-deploy-from-bam':
            logger.info("Announcement deploy from bam")
            self.set_default_stats()
            # self.send_response(200, "SUCCESSFUL")
        else:
            logger.info("Wrong request url")
            self.send_response(404, "NOT FOUND")

class HTTPAgnetServer(HTTPServer):
    def server_bind(self):
        import socket
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(self.server_address)

def start_http_server(agent_input, table_input):
    """[Start http agent server]

    Arguments:
        agent_input {[Agent]} -- [netsnmpagent.netsnmpAgent]
        table_input {[dict]} -- [netsnmpagent.netsnmpAgent.table]
    """
    global AGENT, MIB_TABLE
    AGENT = agent_input
    MIB_TABLE = table_input

    logger.info("Start http agent server")
    httpd = None
    try:
        AgentServer.set_default_stats()
        httpd = HTTPAgnetServer(
            (HTTP_CONFIGURATION['host'], HTTP_CONFIGURATION['port']), AgentServer)
        httpd.allow_reuse_address = True
        httpd.serve_forever()
    except Exception as ex:
        logger.error("start_http_server error: {}".format(ex))
        logger.info("Shutdown http agent server")
        if httpd:
            httpd.close_request() 
