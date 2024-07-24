#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#
# This is an example "local" configuration file. In order to set/override config
# options that ONLY apply to your local environment, simply copy/rename this file
# to docker/pythonpath/superset_config_docker.py
# It ends up being imported by docker/superset_config.py which is loaded by
# superset/config.py
#
import os
from superset_security import CustomSecurityManager

CUSTOM_SECURITY_MANAGER = CustomSecurityManager

SECRET_KEY = os.getenv("SUPERSET_SECRET_KEY")
APP_ICON =  os.getenv("SUPERSET_APP_ICON", "/static/assets/images/superset-logo-horiz.png")
LOGO_TARGET_PATH = os.getenv("SUPERSET_LOGO_TARGET_PATH", None)
APP_NAME = os.getenv("SUPERSET_APP_NAME") 
FAVICONS = [{"href": os.getenv("SUPERSET_FAVICONS", "/static/assets/images/favicon.png") }]
ROW_LIMIT = os.getenv("SUPERSET_ROW_LIMIT")
LOGO_RIGHT_TEXT = os.getenv("SUPERSET_LOGO_RIGHT_TEXT", "")

PUBLIC_ROLE_LIKE = os.getenv("SUPERSET_PUBLIC_ROLE_LIKE", "Gamma")
AUTH_ROLE_PUBLIC = os.getenv("SUPERSET_AUTH_ROLE_PUBLIC", "Public")