"""[BIND]
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


import json
import requests
from config import BIND_CONFIGURATION, logger
from .constants import BLACK_LIST_VIEW, QryType, ErrorMessage


def get_stats(stats_type):
    """[Get statistic by type from bind]
    Arguments:
        stats_type {[String]} -- [Type of statistic]
    Returns:
        [dict] -- [statistic value get follow input type]
    """
    url = "http://{}:{}{}".format(
        BIND_CONFIGURATION["host"],
        BIND_CONFIGURATION["port"],
        BIND_CONFIGURATION["stats_path"]
    )

    try:
        response = requests.get(url)
        # Check if no such url
        if response.text.strip() == ErrorMessage.NOT_FOUND_URL:
            logger.error("Bind path {} is not found".format(
                BIND_CONFIGURATION["stats_path"]))
            return {}

        stats = json.loads(response.text)
        return stats[stats_type]
    except requests.exceptions.ConnectionError:
        logger.error("Cannot connect to bind {}:{}".format(
            BIND_CONFIGURATION["host"],
            BIND_CONFIGURATION["port"]))
        return {}


def get_stats_views():
    """[Get statistic of views in bind]
    Returns:
        [dict] -- [Statistic value of all views]
    """
    logger.debug("Get statistic from bind")
    stats_views_bind = get_stats('views')
    stats_views = {}
    try:
        for view in stats_views_bind:
            if view in BLACK_LIST_VIEW:
                continue

            stats_dict = stats_views_bind[view]["resolver"]["stats"]

            total_queries = stats_dict.get(
                "Queryv4", 0) + stats_dict.get("Queryv6", 0)
            total_responses = stats_dict.get(
                "Responsev4", 0) + stats_dict.get("Responsev6", 0)
            other_error = stats_dict.get("OtherError", 0) + \
                stats_dict.get("BadEDNSVersion", 0)
            stats_dict.update({
                "totalQueries": total_queries,
                "totalResponses": total_responses,
                "OtherError": other_error
            })

            # Just get statistic in whilte_list
            white_list_stat_view = QryType.METRIC_FOR_BIND_VIEW.keys()
            stats_dict = {stat: stats_dict[stat]
                        for stat in stats_dict if stat in white_list_stat_view}

            stats_views.update({view: stats_dict})
    except Exception as ex:
        logger.error("Get statistic view from bind is {}".format(ex))
    return stats_views
