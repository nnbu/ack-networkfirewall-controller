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
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"

	"github.com/aws-controllers-k8s/networkfirewall-controller/apis/v1alpha1"
	svcapitypes "github.com/aws-controllers-k8s/networkfirewall-controller/apis/v1alpha1"
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

	ErrSyncingPutProperty = errors.New("error syncing property LoggingConfiguration")
)

// createLoggingConfig creates logging config for a firewall.
func (rm *resourceManager) createLoggingConfig(
	ctx context.Context,
	r *resource,
) (err error) {
	rlog := ackrtlog.FromContext(ctx)
	exit := rlog.Trace("rm.createLoggingConfig")
	defer exit(err)

	if r.ko.Spec.LoggingConfiguration != nil {
		if err = rm.syncLoggingConfiguration(ctx, r, nil); err != nil {
			return fmt.Errorf("%v: %v", err, ErrSyncingPutProperty)
		}
	}
	return nil
}

// deleteLoggingConfig deletes logging config from a firewall. It is necessary
// to delete logging config prior to the deletion of firewall.
func (rm *resourceManager) deleteLoggingConfig(
	ctx context.Context,
	r *resource,
) (err error) {
	rlog := ackrtlog.FromContext(ctx)
	exit := rlog.Trace("rm.deleteLoggingConfig")
	defer exit(err)

	if r.ko.Spec.LoggingConfiguration != nil {
		if err = rm.syncLoggingConfiguration(ctx, nil, r); err != nil {
			return fmt.Errorf("%v: %v", err, ErrSyncingPutProperty)
		}
	}
	return nil
}

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

	if delta.DifferentAt("Spec.LoggingConfiguration") {
		if err := rm.syncLoggingConfiguration(ctx, desired, latest); err != nil {
			return nil, fmt.Errorf("%v: %v", err, ErrSyncingPutProperty)
		}
	}

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

// addPutFieldsToSpec will describe logging config and add its
// returned values to the Firewall spec.
func (rm *resourceManager) addLoggingConfigToSpec(
	ctx context.Context,
	r *resource,
	ko *svcapitypes.Firewall,
) (err error) {
	getLoggingConfigurationResponse, err := rm.sdkapi.DescribeLoggingConfigurationWithContext(ctx, rm.getLoggingConfigurationPayload(r))
	if err != nil {
		return err
	}
	ko.Spec.LoggingConfiguration = rm.setResourceLoggingConfiguration(r, getLoggingConfigurationResponse)
	return nil
}

func customPreCompare(
	delta *ackcompare.Delta,
	a *resource,
	b *resource,
) {
	// Custom comparison of subnet mappings such that they can be compared in a deterministic way.
	customCompareSubnetMappings(delta, a, b)

	// Custom comparison of logging configurations such that they can be
	// compared in a deterministic way.
	customCompareLoggingConfigurations(delta, a, b)
}

func customCompareLoggingConfigurations(
	delta *ackcompare.Delta,
	a *resource,
	b *resource,
) {
	if a.ko.Spec.LoggingConfiguration == nil && b.ko.Spec.LoggingConfiguration == nil {
		return
	}

	if a.ko.Spec.LoggingConfiguration == nil {
		a.ko.Spec.LoggingConfiguration = &svcapitypes.LoggingConfiguration{}
	}

	if b.ko.Spec.LoggingConfiguration == nil {
		b.ko.Spec.LoggingConfiguration = &svcapitypes.LoggingConfiguration{}
	}

	sort.Slice(a.ko.Spec.LoggingConfiguration.LogDestinationConfigs[:], func(i, j int) bool {
		return *a.ko.Spec.LoggingConfiguration.LogDestinationConfigs[i].LogType < *a.ko.Spec.LoggingConfiguration.LogDestinationConfigs[j].LogType
	})
	sort.Slice(b.ko.Spec.LoggingConfiguration.LogDestinationConfigs[:], func(i, j int) bool {
		return *b.ko.Spec.LoggingConfiguration.LogDestinationConfigs[i].LogType < *b.ko.Spec.LoggingConfiguration.LogDestinationConfigs[j].LogType
	})
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

func (rm *resourceManager) getLoggingConfigurationPayload(
	r *resource,
) *svcsdk.DescribeLoggingConfigurationInput {
	res := &svcsdk.DescribeLoggingConfigurationInput{}
	res.SetFirewallName(*r.ko.Spec.FirewallName)
	return res
}

func (rm *resourceManager) newLoggingConfigurationPayload(
	r *resource,
) *svcsdk.UpdateLoggingConfigurationInput {
	res := &svcsdk.UpdateLoggingConfigurationInput{}
	res.SetFirewallName(*r.ko.Spec.FirewallName)
	if r.ko.Spec.LoggingConfiguration != nil {
		res.SetLoggingConfiguration(rm.newLoggingConfiguration(r))
	} else {
		res.SetLoggingConfiguration(&svcsdk.LoggingConfiguration{})
	}
	return res
}

func makeLogDestinationConfigMap(logDestinationConfig []*svcapitypes.LogDestinationConfig) (map[string]*svcapitypes.LogDestinationConfig, error) {
	logDestinationConfigMap := make(map[string]*svcapitypes.LogDestinationConfig)

	for _, cfg := range logDestinationConfig {
		// LogDestinationConfig contains a field LogDestination which is of
		// type map. json.Marshal sorts the map keys which allows to have
		// consistent retun value irrespective of the objects' order in the map.
		key, err := json.Marshal(cfg)
		if err != nil {
			return nil, err
		}
		logDestinationConfigMap[string(key)] = cfg
	}
	return logDestinationConfigMap, nil
}

// compareLoggingDestinationConfigs generates LogDestinationConfigs which need to be
// added and deleted to reach desired LogDestinationConfig from latest LogDestinationConfig
func compareLoggingDestinationConfigs(desired []*svcapitypes.LogDestinationConfig, latest []*svcapitypes.LogDestinationConfig) (add []*svcapitypes.LogDestinationConfig, delete []*svcapitypes.LogDestinationConfig, err error) {
	add = make([]*svcapitypes.LogDestinationConfig, 0)
	delete = make([]*svcapitypes.LogDestinationConfig, 0)

	desiredMap, err := makeLogDestinationConfigMap(desired)
	if err != nil {
		return nil, nil, err
	}
	latestMap, err := makeLogDestinationConfigMap(latest)
	if err != nil {
		return nil, nil, err
	}

	for key, val := range desiredMap {
		if _, ok := latestMap[key]; !ok {
			add = append(add, val)
		}
	}

	for key, val := range latestMap {
		if _, ok := desiredMap[key]; !ok {
			delete = append(delete, val)
		}
	}

	return add, delete, nil
}

// syncLoggingConfiguration gets desired logging config and latest (existing)
// logging config as input. It compares both and applies the delta to ensure
// desired logging config is configured for the firewall.
func (rm *resourceManager) syncLoggingConfiguration(
	ctx context.Context,
	desired *resource,
	latest *resource,
) (err error) {
	rlog := ackrtlog.FromContext(ctx)
	exit := rlog.Trace("rm.syncLoggingConfiguration")
	defer exit(err)

	var input *svcsdk.UpdateLoggingConfigurationInput
	var add, delete []*svcapitypes.LogDestinationConfig
	if latest != nil && desired != nil {
		add, delete, err = compareLoggingDestinationConfigs(desired.ko.Spec.LoggingConfiguration.LogDestinationConfigs, latest.ko.Spec.LoggingConfiguration.LogDestinationConfigs)
		if err != nil {
			return err
		}
		input = rm.newLoggingConfigurationPayload(latest)
	} else if latest == nil {
		add = desired.ko.Spec.LoggingConfiguration.LogDestinationConfigs
		input = rm.newLoggingConfigurationPayload(desired)
		input.LoggingConfiguration = &svcsdk.LoggingConfiguration{}
	} else {
		delete = latest.ko.Spec.LoggingConfiguration.LogDestinationConfigs
		input = rm.newLoggingConfigurationPayload(latest)
	}

	// UpdateLoggingConfiguration allows only single LogDestinationConfig
	// update at a time. So the updates (delete/add) need to be done in a loop.
	for _, c := range delete {
		resf0elem := &svcsdk.LogDestinationConfig{}

		resf0elem.SetLogDestination(c.LogDestination)
		resf0elem.SetLogDestinationType(*c.LogDestinationType)
		resf0elem.SetLogType(*c.LogType)

		for i, config := range input.LoggingConfiguration.LogDestinationConfigs {
			if reflect.DeepEqual(config, resf0elem) {
				// Swap with the last element
				input.LoggingConfiguration.LogDestinationConfigs[i] = input.LoggingConfiguration.LogDestinationConfigs[len(input.LoggingConfiguration.LogDestinationConfigs)-1]
				// Reduce the slice's length by 1
				input.LoggingConfiguration.LogDestinationConfigs = input.LoggingConfiguration.LogDestinationConfigs[:len(input.LoggingConfiguration.LogDestinationConfigs)-1]

				output, err := rm.sdkapi.UpdateLoggingConfigurationWithContext(ctx, input)
				rm.metrics.RecordAPICall("UPDATE", "UpdateLoggingConfiguration", err)
				if err != nil {
					return err
				}
				input.FirewallName = output.FirewallName
				input.LoggingConfiguration = output.LoggingConfiguration
			}
		}
	}

	for _, c := range add {
		resf0elem := &svcsdk.LogDestinationConfig{}

		resf0elem.SetLogDestination(c.LogDestination)
		resf0elem.SetLogDestinationType(*c.LogDestinationType)
		resf0elem.SetLogType(*c.LogType)

		input.LoggingConfiguration.LogDestinationConfigs = append(input.LoggingConfiguration.LogDestinationConfigs, resf0elem)

		output, err := rm.sdkapi.UpdateLoggingConfigurationWithContext(ctx, input)
		rm.metrics.RecordAPICall("UPDATE", "UpdateLoggingConfiguration", err)
		if err != nil {
			return err
		}
		input.FirewallName = output.FirewallName
		input.LoggingConfiguration = output.LoggingConfiguration
	}

	return nil
}
