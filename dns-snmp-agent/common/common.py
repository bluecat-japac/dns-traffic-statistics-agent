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
