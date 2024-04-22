// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

package firewall

import (
	"context"
	"errors"
	"reflect"
	"sort"

	"github.com/aws-controllers-k8s/networkfirewall-controller/apis/v1alpha1"
	ackcompare "github.com/aws-controllers-k8s/runtime/pkg/compare"
	ackrequeue "github.com/aws-controllers-k8s/runtime/pkg/requeue"
	ackrtlog "github.com/aws-controllers-k8s/runtime/pkg/runtime/log"
	svcsdk "github.com/aws/aws-sdk-go/service/networkfirewall"
)

var (
	requeueWaitWhileDeleting = ackrequeue.NeededAfter(
		errors.New(GroupKind.Kind+" is deleting."),
		ackrequeue.DefaultRequeueAfterDuration,
	)
)

func (rm *resourceManager) customUpdateFirewall(
	ctx context.Context,
	desired *resource,
	latest *resource,
	delta *ackcompare.Delta,
) (updated *resource, err error) {
	rlog := ackrtlog.FromContext(ctx)
	exit := rlog.Trace("rm.customUpdateFirewall")
	defer exit(err)

	ko := desired.ko.DeepCopy()

	rm.setStatusDefaults(ko)

	if delta.DifferentAt("Spec.FirewallPolicyARN") {
		if err = rm.syncFirewallPolicyARN(ctx, desired, latest); err != nil {
			return nil, err
		}
	}

	ko.Status.Firewall.FirewallPolicyARN = desired.ko.Spec.FirewallPolicyARN

	return &resource{ko}, nil
}

func (rm *resourceManager) syncFirewallPolicyARN(
	ctx context.Context,
	desired *resource,
	latest *resource,
) (err error) {
	rlog := ackrtlog.FromContext(ctx)
	exit := rlog.Trace("rm.syncFirewallPolicyARN")
	defer exit(err)

	input := &svcsdk.AssociateFirewallPolicyInput{}

	// Fetch latest firewall information from AWS.
	if latest.ko.Status.Firewall != nil && latest.ko.Status.Firewall.FirewallARN != nil {
		input.FirewallArn = latest.ko.Status.Firewall.FirewallARN
	}

	// Update firewall policy ARN with desired value.
	if desired.ko.Spec.FirewallPolicyARN != nil {
		input.FirewallPolicyArn = desired.ko.Spec.FirewallPolicyARN
	}

	_, err = rm.sdkapi.AssociateFirewallPolicyWithContext(ctx, input)
	rm.metrics.RecordAPICall("UPDATE", "AssociateFirewallPolicy", err)
	if err != nil {
		return err
	}

	return nil
}

func customPreCompare(
	delta *ackcompare.Delta,
	a *resource,
	b *resource,
) {
	// Custom comparison of subnet mappings such that they can be compared in a deterministic way.
	customCompareSubnetMappings(delta, a, b)
}

func customCompareSubnetMappings(
	delta *ackcompare.Delta,
	a *resource,
	b *resource,
) {
	if len(a.ko.Spec.SubnetMappings) != len(b.ko.Spec.SubnetMappings) {
		delta.Add("Spec.SubnetMappings", a.ko.Spec.SubnetMappings, b.ko.Spec.SubnetMappings)
		return
	}

	// Sort a copy of the inputs to avoid modifying the original spec. A full deep copy is not necessary here.
	desiredCopy := copySortedSubnetMappings(a.ko.Spec.SubnetMappings)
	latestCopy := copySortedSubnetMappings(b.ko.Spec.SubnetMappings)

	if !reflect.DeepEqual(desiredCopy, latestCopy) {
		delta.Add("Spec.SubnetMappings", a.ko.Spec.SubnetMappings, b.ko.Spec.SubnetMappings)
	}
}

func copySortedSubnetMappings(
	subnetMappings []*v1alpha1.SubnetMapping,
) []*v1alpha1.SubnetMapping {
	if subnetMappings == nil {
		return nil
	}

	newSubnetMappings := make([]*v1alpha1.SubnetMapping, len(subnetMappings))
	for i, mapping := range subnetMappings {
		newSubnetMappings[i] = &v1alpha1.SubnetMapping{
			SubnetID:      mapping.SubnetID,
			IPAddressType: mapping.IPAddressType,
		}
	}

	sort.Slice(newSubnetMappings[:], func(i, j int) bool {
		return *newSubnetMappings[i].SubnetID < *newSubnetMappings[j].SubnetID
	})
	return newSubnetMappings
}
