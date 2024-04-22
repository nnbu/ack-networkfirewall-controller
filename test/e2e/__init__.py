# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may
# not use this file except in compliance with the License. A copy of the
# License is located at
#
# 	 http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.

import pytest

from pathlib import Path
from typing import Dict, Any

from acktest.k8s import resource as k8s
from acktest.resources import load_resource_file

SERVICE_NAME = "networkfirewall"
CRD_GROUP = "networkfirewall.services.k8s.aws"
CRD_VERSION = "v1alpha1"

# PyTest marker for the current service
service_marker = pytest.mark.service(arg=SERVICE_NAME)

bootstrap_directory = Path(__file__).parent
resource_directory = Path(__file__).parent / "resources"
def load_networkfirewall_resource(resource_name: str, additional_replacements: Dict[str, Any] = {}):
    """ Overrides the default `load_resource_file` to access the specific resources
    directory for the current service.
    """
    return load_resource_file(resource_directory, resource_name, additional_replacements=additional_replacements)

def create_firewall_resource(
    resource_plural,
    resource_name,
    spec_file,
    replacements,
    crd_group=CRD_GROUP,
    namespace="default",
):
    resource_data = load_networkfirewall_resource(
        spec_file,
        additional_replacements=replacements,
    )

    ref = k8s.CustomResourceReference(
        crd_group, CRD_VERSION, resource_plural,
        resource_name, namespace,
    )
    k8s.create_custom_resource(ref, resource_data)

    cr = k8s.wait_resource_consumed_by_controller(ref)

    assert cr is not None
    assert k8s.get_resource_exists(ref)

    return ref, cr

def delete_firewall_resource(ref):
    try:
        _, deleted = k8s.delete_custom_resource(ref, 3, 10)
        assert deleted
    except:
        pass
