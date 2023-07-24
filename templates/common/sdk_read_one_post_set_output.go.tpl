
	if resp.Firewall != nil {
		if resp.Firewall.VpcId != nil {
			ko.Spec.VPCID = resp.Firewall.VpcId
		}

		if resp.Firewall.FirewallPolicyArn != nil {
			ko.Spec.FirewallPolicyARN = resp.Firewall.FirewallPolicyArn
		}

		if resp.Firewall.SubnetMappings != nil {
			subnetMappings := []*svcapitypes.SubnetMapping{}
			for _, subnetMapping := range resp.Firewall.SubnetMappings {
				subnetMap := &svcapitypes.SubnetMapping{}
				if subnetMapping.SubnetId != nil {
					subnetMap.SubnetID = subnetMapping.SubnetId
				}
				subnetMappings = append(subnetMappings, subnetMap)
			}
			ko.Spec.SubnetMappings = subnetMappings
		}
	}

	if err := rm.addLoggingConfigToSpec(ctx, r, ko); err != nil {
		return nil, err
	}
