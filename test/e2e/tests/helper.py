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

"""Helper functions for networkfirewall tests
"""

import datetime
import time
import pytest
import logging

from acktest.resources import random_suffix_name
from e2e import create_firewall_resource
from e2e.replacement_values import REPLACEMENT_VALUES

WAIT_AFTER_SECONDS = 10

def create_simple_firewall_policy():
    resource_name = random_suffix_name("fw-pol-ack-test", 24)

    replacements = REPLACEMENT_VALUES.copy()
    replacements["FIREWALL_POLICY_NAME"] = resource_name
    replacements["STATEFUL_DEFAULT_ACTION"] = "aws:drop_established"
    replacements["RULE_ORDER"] = "STRICT_ORDER"
    replacements["STREAM_EXCEPTION_POLICY"] = "DROP"
    replacements["STATELESS_DEFAULT_ACTION"] = "aws:drop"
    replacements["STATELESS_FRAG_DEFAULT_ACTION"] = "aws:forward_to_sfe"

    ref, cr = create_firewall_resource(
        "firewallpolicies",
        resource_name,
        "firewall_policy",
        replacements,
    )

    return ref, cr

class NetworkFirewallValidator:
    def __init__(self, networkfirewall_client):
        self.networkfirewall_client = networkfirewall_client

    def get_network_firewall(self, firewall_name: str):
        try:
            aws_res = self.networkfirewall_client.describe_firewall(FirewallName=firewall_name)
            if len(aws_res["Firewall"]) > 0:
                return aws_res["Firewall"][0]
            return None
        except self.networkfirewall_client.exceptions.ResourceNotFoundException:
            return None

    def get_network_firewall_status(self, firewall_name: str):
        try:
            aws_res = self.networkfirewall_client.describe_firewall(FirewallName=firewall_name)
            return aws_res["FirewallStatus"]["Status"]
        except self.networkfirewall_client.exceptions.ResourceNotFoundException:
            return None

    def assert_network_firewall_logs(self, firewall_name: str, want_num_logs: int):
        got_num_logs = 0
        try:
            aws_res = self.networkfirewall_client.describe_logging_configuration(FirewallName=firewall_name)
            got_num_logs = len(aws_res["LoggingConfiguration"]["LogDestinationConfigs"])
        except self.networkfirewall_client.exceptions.ClientError:
            pass
        assert got_num_logs is want_num_logs

    def wait_for_firewall_creation_or_die(self, firewall_name: str, desired_state: str, timeout_sec):
        while True:
            now = datetime.datetime.now()
            timeout = now + datetime.timedelta(seconds=timeout_sec)
            if datetime.datetime.now() >= timeout:
                pytest.fail(f"Timed out waiting for Firewall to enter {desired_state} state")
            time.sleep(WAIT_AFTER_SECONDS)
            instance_state = self.get_network_firewall_status(firewall_name)
            if instance_state == desired_state:
                break

    def wait_for_firewall_deletion_or_die(self, firewall_name: str, timeout_sec):
        while True:
            now = datetime.datetime.now()
            timeout = now + datetime.timedelta(seconds=timeout_sec)
            if datetime.datetime.now() >= timeout:
                pytest.fail(f"Timed out waiting for Firewall to be deleted")
            time.sleep(WAIT_AFTER_SECONDS)
            instance_state = self.get_network_firewall_status(firewall_name)
            if instance_state is None:
                break

            if instance_state != "DELETING":
                pytest.fail(
                    "Status is not 'DELETING' for Firewall that was "
                    "deleted. Status is " + instance_state
                )
