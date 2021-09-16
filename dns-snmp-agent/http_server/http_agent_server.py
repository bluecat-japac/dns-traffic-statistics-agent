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
import traceback
from config import logger, HTTP_CONFIGURATION
from common import exception as c_except
from common.constants import QryType, StatisticPerType, TableOidStr
from common.common import mili_to_micro, micro_to_mili
from common.bind import get_stats_views
from http_server import named

global AGENT, MIB_TABLE, ROW_DICT, NAMED_CONFIGURATION
AGENT, MIB_TABLE, NAMED_CONFIGURATION = None, None, None
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


def get_average_time(ip, table_value):
    for value in table_value:
        if value[1] == ip:
            return value[2]
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
        

def set_view_default_named(views):
    pb_view_metrics = QryType.METRIC_FOR_AGENT.keys()
    pb_view_metrics.append(QryType.METRIC_AVG_TIME)
    bind_view_metrics = QryType.METRIC_FOR_BIND_VIEW.keys()
    for view in views:
        # Set default value zero for view from Packetbeat
        for metric_name in pb_view_metrics:
            AgentServer.update_to_mib_table(StatisticPerType.VIEW, view, metric_name, 0)
        # Set default value zero for view from BIND
        for metric_name in bind_view_metrics:
            AgentServer.update_to_mib_table(StatisticPerType.BIND_VIEW, view, metric_name, 0)


def set_clients_default_named(clients):
    metrics = QryType.METRIC_FOR_AGENT.keys()
    metrics.append(QryType.METRIC_AVG_TIME)
    for client in clients:
        logger.info("Add client {} to mib".format(client))
        for metric_name in metrics:
            AgentServer.update_to_mib_table(StatisticPerType.CLIENT, client, metric_name, 0)


def set_servers_default_named(servers):
    metrics = QryType.METRIC_FOR_AGENT.keys()
    metrics.append(QryType.METRIC_AVG_TIME)
    for server in servers:
        logger.info("Add server {} to mib".format(server))
        for metric_name in metrics:
            AgentServer.update_to_mib_table(StatisticPerType.SERVER, server, metric_name, 0)


def parse_to_ls_stats(type, group_datas):
    list_statistic_data = []

    average_time_table = get_table_by_type(type, True)
    average_time_table_value = average_time_table['table'].value().values()[1:]
    
    metrics = {id: metrics_name for metrics_name, id in QryType.METRIC_FOR_AGENT.items()}
    for ip_or_view, values in group_datas.items():
        dnsmetrics = {}
        for value in values:
            dnsmetrics.update({metrics[value[2]]: int(value[3])})
        average_time = get_average_time(ip_or_view, average_time_table_value)
        # Need to change average_time from micro to milisecend 
        dnsmetrics.update({"average_time": micro_to_mili(average_time)})
        stat = {
            "ip_or_view": ip_or_view, 
            "type": type, 
            "dnsmetrics": dnsmetrics}
        list_statistic_data.append(stat)
    return list_statistic_data


def get_stats_acl_after_deploy(acl_traffic):
    import collections

    group_addrs = collections.defaultdict(list)

    logger.debug("List IP in ACL: {}".format(acl_traffic.list_ip))
    logger.debug("List IP CIDR in ACL: {}".format(acl_traffic.list_ip_cdir))

    qry_table = get_table_by_type(acl_traffic.type)
    qry_table_value = qry_table["table_value"].values()[1:]
    for value in qry_table_value:
        if not acl_traffic.is_ip_available_acl(value[1]):
            continue
        group_addrs[value[1]].append(value)

    list_statistic_data = parse_to_ls_stats(acl_traffic.type, group_addrs)
    return list_statistic_data


def get_stats_view_after_deploy(dns_view):
    type = StatisticPerType.VIEW
    import collections

    list_statistic_data = []
    group_views = collections.defaultdict(list)
    
    views = dns_view.list_views_name
    qry_table = get_table_by_type(type)
    qry_table_value = qry_table["table_value"].values()[1:]
    for value in qry_table_value:
        if value[1] not in views:
            continue
        group_views[value[1]].append(value)
    
    list_statistic_data = parse_to_ls_stats(type, group_views)
    return list_statistic_data


def clean_all_table_agent():
    global ROW_DICT
    ROW_DICT = {}
    MIB_TABLE[TableOidStr.STAT_PER_CLIENT]["table"].clear()
    MIB_TABLE[TableOidStr.STAT_PER_SERVER]["table"].clear()
    MIB_TABLE[TableOidStr.STAT_PER_VIEW]["table"].clear()
    

def reformat_pb_content(pb_request_content):
    """[Restucture content from packetbeat]
    
    Arguments:
        pb_request_content {[dict]} -- [statistic content get json request's json data
            Example: {
            "start": "2019-6-6,18:23:23.1",
            "end": "2019-6-6,18:23:24.9",
            "stats_map": {
                "192.168.88.23": {"type": "perClient", "dnsmetrics": {"total_queries":0,"total_queries_new":0,
                "total_responses":2,"total_responses_new":2,"recursive":0,"duplicated":0,"average_time":0,"successful":0,
                "server_fail":0,"nx_domain":0,"format_error":2,"nx_rrset":0,"referral":0,"refused":0,"other_rcode":0}}}}]
    Returns:
        [list] -- [
            [
                {"ip_or_view": "192.168.88.23", "type": "perClient", "dnsmetrics": {"total_queries":0,"total_queries_new":0,
                "total_responses":2,"total_responses_new":2,"recursive":0,"duplicated":0,"average_time":0,"successful":0,
                "server_fail":0,"nx_domain":0,"format_error":2,"nx_rrset":0,"referral":0,"refused":0,"other_rcode":0}},
                ...
            ]]
    """
    list_statistic_data = pb_request_content.get('stats_map', [])
    new_structure_data = []
    for statistic_key in list_statistic_data:
        data  = list_statistic_data[statistic_key]
        data.update({"ip_or_view": statistic_key})
        new_structure_data.append(data)
    return new_structure_data


class AgentServer(BaseHTTPRequestHandler):
    @classmethod
    def validate_traffic_input(cls, per_type, ip_or_view):
        if per_type == StatisticPerType.VIEW:
            return NAMED_CONFIGURATION.dns_view.is_available(ip_or_view)
        elif per_type == StatisticPerType.SERVER:
            return NAMED_CONFIGURATION.acl_traffic_server.is_ip_available_acl(ip_or_view)
        elif per_type == StatisticPerType.CLIENT:
            return NAMED_CONFIGURATION.acl_traffic_client.is_ip_available_acl(ip_or_view)

    @classmethod
    def set_default_stats(cls):
        try:
            set_view_default_named(NAMED_CONFIGURATION.dns_view.list_views_name)
            set_clients_default_named(NAMED_CONFIGURATION.acl_traffic_client.list_ip)
            set_servers_default_named(NAMED_CONFIGURATION.acl_traffic_server.list_ip)
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
                row_index = "{}|{}|{}".format(stat_type, ip_or_view, dns_query_type_id)
                if row_index in ROW_DICT:
                    metric_row = ROW_DICT[row_index]
                else:
                    metric_row = table["table"].addRow(
                        [AGENT.DisplayString(bind_view), AGENT.Integer32(dns_query_type_id)])
                    metric_row.setRowCell(1, AGENT.DisplayString(bind_view))
                    metric_row.setRowCell(
                        2, AGENT.Integer32(dns_query_type_id))
                    ROW_DICT.update({row_index: metric_row})
                metric_row.setRowCell(3, AGENT.Counter64(value))
            elif is_time_query_type: #if dns_query_type == QryType.METRIC_AVG_TIME
                dns_query_type_id = "metric-avg-time"
                row_index = "{}|{}|{}".format(stat_type, ip_or_view, dns_query_type_id)
                if row_index in ROW_DICT:
                    avg_time_row = ROW_DICT[row_index]
                else:
                    avg_time_row = table["table"].addRow(
                        [AGENT.OctetString(ip_or_view)])
                    avg_time_row.setRowCell(1, AGENT.OctetString(ip_or_view))
                    ROW_DICT.update({row_index: avg_time_row})

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
    def update_mib_stat_counter(cls, list_statistic_data):
        """[Update all statistic dns receiver from PacketBeat and Bind]

        Arguments:
            list_statistic_data {[list]} -- [statistic content get from request's data packetbeat
                Example: [
                {"ip_or_view": "192.168.88.23", "type": "perClient", "dnsmetrics": {"total_queries":0,"total_queries_new":0,
                "total_responses":2,"total_responses_new":2,"recursive":0,"duplicated":0,"average_time":0,"successful":0,
                "server_fail":0,"nx_domain":0,"format_error":2,"nx_rrset":0,"referral":0,"refused":0,"other_rcode":0}},
                ...]]
        """
        global MIB_TABLE
        
        # Sync-up with data in mib
        MIB_TABLE[TableOidStr.STAT_PER_CLIENT]["table_value"] = MIB_TABLE[TableOidStr.STAT_PER_CLIENT]["table"].value()
        MIB_TABLE[TableOidStr.STAT_PER_SERVER]["table_value"] = MIB_TABLE[TableOidStr.STAT_PER_SERVER]["table"].value()
        MIB_TABLE[TableOidStr.STAT_PER_VIEW]["table_value"] = MIB_TABLE[TableOidStr.STAT_PER_VIEW]["table"].value()

        logger.info("Update {} client/server/view from PB to mib table".format(
            len(list_statistic_data)))
        for statistic in list_statistic_data:
            ip_or_view = statistic['ip_or_view']
            stat_type = statistic['type']
            if not cls.validate_traffic_input(stat_type, ip_or_view):
                continue
            metrics = statistic['dnsmetrics']
            for metric_name in metrics:
                value = metrics[metric_name]
                cls.update_to_mib_table(stat_type, ip_or_view, metric_name, value)

        # Update statistic of view from bind to mib
        stats_views = get_stats_views()
        logger.info("Update {} view from bind channel to mib table".format(
            len(stats_views)))
        for view in stats_views:
            metrics = stats_views[view]
            for metric_name in metrics:
                value = metrics[metric_name]
                cls.update_to_mib_table(
                    StatisticPerType.BIND_VIEW, view, metric_name, value)

        # Sync-up with data in mib
        # Sync-up again after update data from Packetbeat and then set default for another client/server/view missing
        MIB_TABLE[TableOidStr.STAT_PER_CLIENT]["table_value"] = MIB_TABLE[TableOidStr.STAT_PER_CLIENT]["table"].value()
        MIB_TABLE[TableOidStr.STAT_PER_SERVER]["table_value"] = MIB_TABLE[TableOidStr.STAT_PER_SERVER]["table"].value()
        MIB_TABLE[TableOidStr.STAT_PER_VIEW]["table_value"] = MIB_TABLE[TableOidStr.STAT_PER_VIEW]["table"].value()

        # Run set default for client/server/view in ACL missing in PB output
        # And set default for view in ACL missing in BIND output
        logger.info("Set default zero value for metrics missing")
        cls.set_default_stats()


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
        import traceback
        logger.info("Have request GET API")
        try:
            if self.path == '/counter':
                logger.info("Receive GET Counter api")
                content_len = int(self.headers.get('content-length'))
                content = json.loads(self.rfile.read(content_len))
                logger.debug("Content receive from PB")
                logger.debug(content)
                list_statistic_data = reformat_pb_content(content)
                self.update_mib_stat_counter(list_statistic_data)

                # Response
                logger.info("Reponse to client")
                self.send_response(200)
                self.end_headers()
                response_content = self._repsonse_template(200, 'SUCCESSFUL')
                self.wfile.write(json.dumps(response_content).encode())
            elif self.path == '/announcement-deploy-from-bam':
                logger.info("Announcement deploy from bam")
                NAMED_CONFIGURATION.load_configuration()
                if NAMED_CONFIGURATION.file_excution.contents is None:
                    logger.warning("Announcement deploy from bam: {}".format(str(c_except.NamedNotExist())))
                list_statistic_data = []
                list_statistic_data += get_stats_acl_after_deploy(NAMED_CONFIGURATION.acl_traffic_client)
                list_statistic_data += get_stats_acl_after_deploy(NAMED_CONFIGURATION.acl_traffic_server)
                list_statistic_data += get_stats_view_after_deploy(NAMED_CONFIGURATION.dns_view)
                clean_all_table_agent()
                self.update_mib_stat_counter(list_statistic_data)
                # self.send_response(200, "SUCCESSFUL")
            else:
                logger.info("Wrong request url")
                self.send_response(404, "NOT FOUND")
        except Exception:
                logger.error(traceback.format_exc())


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
    global AGENT, MIB_TABLE, NAMED_CONFIGURATION
    AGENT = agent_input
    MIB_TABLE = table_input

    logger.info("Start http agent server")
    httpd = None
    try:
        NAMED_CONFIGURATION = named.NamedConfiguration()
        NAMED_CONFIGURATION.load_configuration()
        if NAMED_CONFIGURATION.file_excution.contents is None:
            logger.warning("start_http_server: {}".format(str(c_except.NamedNotExist())))
        AgentServer.set_default_stats()
        MIB_TABLE[TableOidStr.STAT_PER_CLIENT]["table_value"] = MIB_TABLE[TableOidStr.STAT_PER_CLIENT]["table"].value()
        MIB_TABLE[TableOidStr.STAT_PER_SERVER]["table_value"] = MIB_TABLE[TableOidStr.STAT_PER_SERVER]["table"].value()
        MIB_TABLE[TableOidStr.STAT_PER_VIEW]["table_value"] = MIB_TABLE[TableOidStr.STAT_PER_VIEW]["table"].value()
        httpd = HTTPAgnetServer(
            (HTTP_CONFIGURATION['host'], HTTP_CONFIGURATION['port']), AgentServer)
        httpd.allow_reuse_address = True
        httpd.serve_forever()
    except Exception as ex:
        logger.error("start_http_server error: {}".format(ex))
        logger.error(traceback.format_exc())
        logger.info("Shutdown http agent server")
        if httpd:
            httpd.close_request() 
