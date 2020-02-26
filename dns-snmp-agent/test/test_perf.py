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
import requests
import json
import datetime

url = "http://localhost:51415/counter"

payload = {
    "start": "2019-06-07T18:50:31.924578754+07:00",
    "end": "2019-06-07T18:50:32.924464593+07:00",
    "stats_map": {}
}

number_client = sys.argv[1]

for count in range(int(number_client)):
    payload['stats_map'].update({
        "192.168.88.{}".format(str(count+1)): {
            "type": "perClient",
            "dnsmetrics": {
                "total_queries": 900,
                "total_responses": 210,
                "referral": 0,
                "nx_rrset": 44,
                "nx_domain": 700,
                "recursive": 200,
                "successful": 0,
                "format_error": 0,
                "server_fail": 120,
                "duplicated": 0,
                "refused": 0,
                "other_rcode": 10,
                "average_time": 0.115,
                "successful_recursive": 12,
                "successful_noauthans": 0,
                "truncated": 1
            }
        }
    })

headers = {
    'Content-Type': "application/json",
    'cache-control': "no-cache",
    'Postman-Token': "03c8144a-11b1-4688-976a-734aadf218b7"
}


print(datetime.datetime.now())
response = requests.request(
    "GET", url, data=json.dumps(payload), headers=headers)

print(response.text)
print(datetime.datetime.now())
