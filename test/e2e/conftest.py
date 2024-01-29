# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the
# License is located at
#
#	 http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.

import boto3
import pytest
import time
import logging

from acktest.aws.identity import get_region
from acktest.resources import random_suffix_name
from acktest.k8s import resource as k8s
from e2e import CRD_GROUP, CRD_VERSION, load_networkfirewall_resource
from e2e.replacement_values import REPLACEMENT_VALUES

VPC_CREATE_WAIT_AFTER_SECONDS = 10
VPC_RESOURCE_PLURAL = "vpcs"

@pytest.fixture(scope="module")
def networkfirewall_client():
    region = get_region()
    return boto3.client("network-firewall", region)
