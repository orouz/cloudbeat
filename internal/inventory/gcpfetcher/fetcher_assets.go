// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package gcpfetcher

import (
	"context"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/samber/lo"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/elastic/cloudbeat/internal/infra/clog"
	"github.com/elastic/cloudbeat/internal/inventory"
	gcpinventory "github.com/elastic/cloudbeat/internal/resources/providers/gcplib/inventory"
)

type (
	assetsInventory struct {
		logger   *clog.Logger
		provider inventoryProvider
	}
	inventoryProvider interface {
		ListAllAssetTypesByName(ctx context.Context, assets []string) ([]*gcpinventory.ExtendedGcpAsset, error)
	}
	ResourcesClassification struct {
		assetType      string
		classification inventory.AssetClassification
	}
)

var ResourcesToFetch = []ResourcesClassification{
	{gcpinventory.CrmOrgAssetType, inventory.AssetClassificationGcpOrganization},
	{gcpinventory.CrmFolderAssetType, inventory.AssetClassificationGcpFolder},
	{gcpinventory.CrmProjectAssetType, inventory.AssetClassificationGcpProject},
	{gcpinventory.ComputeInstanceAssetType, inventory.AssetClassificationGcpInstance},
	{gcpinventory.ComputeFirewallAssetType, inventory.AssetClassificationGcpFirewall},
	{gcpinventory.StorageBucketAssetType, inventory.AssetClassificationGcpBucket},
	{gcpinventory.ComputeSubnetworkAssetType, inventory.AssetClassificationGcpSubnet},
	{gcpinventory.IamServiceAccountAssetType, inventory.AssetClassificationGcpServiceAccount},
	{gcpinventory.IamServiceAccountKeyAssetType, inventory.AssetClassificationGcpServiceAccountKey},
	{gcpinventory.GkeClusterAssetType, inventory.AssetClassificationGcpGkeCluster},
	{gcpinventory.ComputeForwardingRuleAssetType, inventory.AssetClassificationGcpForwardingRule},
	{gcpinventory.CloudFunctionAssetType, inventory.AssetClassificationGcpCloudFunction},
	{gcpinventory.CloudRunService, inventory.AssetClassificationGcpCloudRunService},
	{gcpinventory.IamRoleAssetType, inventory.AssetClassificationGcpIamRole},
}

func newAssetsInventoryFetcher(logger *clog.Logger, provider inventoryProvider) inventory.AssetFetcher {
	return &assetsInventory{
		logger:   logger,
		provider: provider,
	}
}

func (f *assetsInventory) Fetch(ctx context.Context, assetChan chan<- inventory.AssetEvent) {
	for _, r := range ResourcesToFetch {
		f.fetch(ctx, assetChan, r.assetType, r.classification)
	}
}

func (f *assetsInventory) fetch(ctx context.Context, assetChan chan<- inventory.AssetEvent, assetType string, classification inventory.AssetClassification) {
	f.logger.Infof("Fetching %s", assetType)
	defer f.logger.Infof("Fetching %s - Finished", assetType)

	gcpAssets, err := f.provider.ListAllAssetTypesByName(ctx, []string{assetType})
	if err != nil {
		f.logger.Errorf("Could not fetch %s: %v", assetType, err)
		return
	}

	for _, item := range gcpAssets {
		assetChan <- getAssetEvent(classification, item)
	}
}

func getAssetEvent(classification inventory.AssetClassification, item *gcpinventory.ExtendedGcpAsset) inventory.AssetEvent {
	// Common enrichers
	enrichers := []inventory.AssetEnricher{
		inventory.WithRawAsset(item),
		inventory.WithLabels(getAssetLabels(item)),
		inventory.WithTags(getAssetTags(item)),
		inventory.WithRelatedAssetIds(
			findRelatedAssetIds(classification.Type, item),
		),
		// Any asset type enrichers also setting Cloud fields will need to re-add these fields below
		inventory.WithCloud(inventory.Cloud{
			Provider:    inventory.GcpCloudProvider,
			AccountID:   item.CloudAccount.AccountId,
			AccountName: item.CloudAccount.AccountName,
			ProjectID:   item.CloudAccount.OrganisationId,
			ProjectName: item.CloudAccount.OrganizationName,
			ServiceName: item.AssetType,
		}),
	}

	// Asset type specific enrichers
	if hasResourceData(item) {
		if enricher, ok := assetEnrichers[item.AssetType]; ok {
			enrichers = append(enrichers, enricher(item, item.GetResource().GetData())...)
		}
	}

	return inventory.NewAssetEvent(
		classification,
		item.Name,
		item.Name,
		enrichers...,
	)
}

func findRelatedAssetIds(t inventory.AssetType, item *gcpinventory.ExtendedGcpAsset) []string {
	ids := []string{}
	ids = append(ids, item.Ancestors...)
	if item.Resource != nil {
		ids = append(ids, item.Resource.Parent)
	}

	ids = append(ids, findRelatedAssetIdsForType(t, item)...)

	ids = lo.Compact(ids)
	ids = lo.Uniq(ids)
	return ids
}

func findRelatedAssetIdsForType(t inventory.AssetType, item *gcpinventory.ExtendedGcpAsset) []string {
	ids := []string{}

	var fields map[string]*structpb.Value
	if item.Resource != nil && item.Resource.Data != nil {
		fields = item.GetResource().GetData().GetFields()
	}

	switch t {
	case inventory.AssetClassificationGcpInstance.Type:
		if v, ok := fields["networkInterfaces"]; ok {
			for _, networkInterface := range v.GetListValue().GetValues() {
				networkInterfaceFields := networkInterface.GetStructValue().GetFields()
				ids = appendIfExists(ids, networkInterfaceFields, "network")
				ids = appendIfExists(ids, networkInterfaceFields, "subnetwork")
			}
		}
		if v, ok := fields["serviceAccounts"]; ok {
			for _, serviceAccount := range v.GetListValue().GetValues() {
				serviceAccountFields := serviceAccount.GetStructValue().GetFields()
				ids = appendIfExists(ids, serviceAccountFields, "email")
			}
		}
		if v, ok := fields["disks"]; ok {
			for _, disk := range v.GetListValue().GetValues() {
				diskFields := disk.GetStructValue().GetFields()
				ids = appendIfExists(ids, diskFields, "source")
			}
		}
		ids = appendIfExists(ids, fields, "machineType")
		ids = appendIfExists(ids, fields, "zone")
	case inventory.AssetClassificationGcpFirewall.Type, inventory.AssetClassificationGcpSubnet.Type:
		ids = appendIfExists(ids, fields, "network")
	case inventory.AssetClassificationGcpProject.Type, inventory.AssetClassificationGcpBucket.Type:
		if item.IamPolicy == nil {
			break
		}
		for _, binding := range item.IamPolicy.Bindings {
			ids = append(ids, binding.Role)
			ids = append(ids, binding.Members...)
		}
	default:
		return ids
	}

	return ids
}

func appendIfExists(slice []string, fields map[string]*structpb.Value, key string) []string {
	value, ok := fields[key]
	if !ok {
		return slice
	}
	return append(slice, value.GetStringValue())
}

func hasResourceData(item *gcpinventory.ExtendedGcpAsset) bool {
	return item.Resource != nil && item.Resource.Data != nil
}

func getAssetTags(item *gcpinventory.ExtendedGcpAsset) []string {
	if !hasResourceData(item) {
		return nil
	}

	tagsObj, ok := item.GetResource().GetData().GetFields()["tags"]
	if !ok {
		return nil
	}

	structValue := tagsObj.GetStructValue()
	if structValue == nil {
		return nil
	}

	items, ok := structValue.GetFields()["items"]
	if !ok {
		return nil
	}

	tagValues := items.GetListValue().GetValues()
	tags := make([]string, len(tagValues))
	for i, tag := range tagValues {
		tags[i] = tag.GetStringValue()
	}

	return tags
}

func getAssetLabels(item *gcpinventory.ExtendedGcpAsset) map[string]string {
	if !hasResourceData(item) {
		return nil
	}

	labels, ok := item.GetResource().GetData().GetFields()["labels"]
	if !ok {
		return nil
	}

	labelsMap := make(map[string]string)
	if err := mapstructure.Decode(labels.GetStructValue().AsMap(), &labelsMap); err != nil {
		return nil
	}

	return labelsMap
}

var assetEnrichers = map[string]func(item *gcpinventory.ExtendedGcpAsset, pb *structpb.Struct) []inventory.AssetEnricher{
	gcpinventory.IamRoleAssetType:               noopEnricher,
	gcpinventory.CrmFolderAssetType:             noopEnricher,
	gcpinventory.CrmProjectAssetType:            noopEnricher,
	gcpinventory.StorageBucketAssetType:         noopEnricher,
	gcpinventory.IamServiceAccountKeyAssetType:  noopEnricher,
	gcpinventory.CloudRunService:                enrichCloudRunService,
	gcpinventory.CrmOrgAssetType:                enrichOrganization,
	gcpinventory.ComputeInstanceAssetType:       enrichComputeInstance,
	gcpinventory.ComputeFirewallAssetType:       enrichFirewall,
	gcpinventory.ComputeSubnetworkAssetType:     enrichSubnetwork,
	gcpinventory.IamServiceAccountAssetType:     enrichServiceAccount,
	gcpinventory.GkeClusterAssetType:            enrichGkeCluster,
	gcpinventory.ComputeForwardingRuleAssetType: enrichForwardingRule,
	gcpinventory.CloudFunctionAssetType:         enrichCloudFunction,
}

func enrichOrganization(_ *gcpinventory.ExtendedGcpAsset, pb *structpb.Struct) []inventory.AssetEnricher {
	return []inventory.AssetEnricher{
		inventory.WithOrganization(inventory.Organization{
			Name: first(getPathValues([]string{"displayName"}, pb)),
		}),
	}
}

func enrichComputeInstance(item *gcpinventory.ExtendedGcpAsset, pb *structpb.Struct) []inventory.AssetEnricher {
	return []inventory.AssetEnricher{
		inventory.WithCloud(inventory.Cloud{
			// This will override the default Cloud pb, so we re-add the common ones
			Provider:         inventory.GcpCloudProvider,
			AccountID:        item.CloudAccount.AccountId,
			AccountName:      item.CloudAccount.AccountName,
			ProjectID:        item.CloudAccount.OrganisationId,
			ProjectName:      item.CloudAccount.OrganizationName,
			ServiceName:      item.AssetType,
			InstanceID:       first(getPathValues([]string{"id"}, pb)),
			InstanceName:     first(getPathValues([]string{"name"}, pb)),
			MachineType:      first(getPathValues([]string{"machineType"}, pb)),
			AvailabilityZone: first(getPathValues([]string{"zone"}, pb)),
		}),
		inventory.WithHost(inventory.Host{
			ID: first(getPathValues([]string{"id"}, pb)),
		}),
		inventory.WithNetwork(inventory.Network{
			Name: getPathValues([]string{"networkInterfaces", "name"}, pb),
		}),
	}
}

func enrichFirewall(_ *gcpinventory.ExtendedGcpAsset, pb *structpb.Struct) []inventory.AssetEnricher {
	return []inventory.AssetEnricher{
		inventory.WithNetwork(inventory.Network{
			Name:      getPathValues([]string{"name"}, pb),
			Direction: first(getPathValues([]string{"direction"}, pb)),
		}),
	}
}

func enrichSubnetwork(_ *gcpinventory.ExtendedGcpAsset, pb *structpb.Struct) []inventory.AssetEnricher {
	return []inventory.AssetEnricher{
		inventory.WithNetwork(inventory.Network{
			Name: getPathValues([]string{"name"}, pb),
			Type: strings.ToLower(first(getPathValues([]string{"stackType"}, pb))),
		}),
	}
}

func enrichServiceAccount(_ *gcpinventory.ExtendedGcpAsset, pb *structpb.Struct) []inventory.AssetEnricher {
	return []inventory.AssetEnricher{
		inventory.WithUser(inventory.User{
			Email: first(getPathValues([]string{"email"}, pb)),
			Name:  first(getPathValues([]string{"displayName"}, pb)),
		}),
	}
}

func enrichGkeCluster(_ *gcpinventory.ExtendedGcpAsset, pb *structpb.Struct) []inventory.AssetEnricher {
	return []inventory.AssetEnricher{
		inventory.WithOrchestrator(inventory.Orchestrator{
			Type:        "kubernetes",
			ClusterName: first(getPathValues([]string{"name"}, pb)),
			ClusterID:   first(getPathValues([]string{"id"}, pb)),
		}),
	}
}

func enrichForwardingRule(_ *gcpinventory.ExtendedGcpAsset, pb *structpb.Struct) []inventory.AssetEnricher {
	return []inventory.AssetEnricher{
		inventory.WithCloud(inventory.Cloud{
			Region: first(getPathValues([]string{"region"}, pb)),
		}),
	}
}

func enrichCloudFunction(_ *gcpinventory.ExtendedGcpAsset, pb *structpb.Struct) []inventory.AssetEnricher {
	return []inventory.AssetEnricher{
		inventory.WithURL(inventory.URL{
			Full: first(getPathValues([]string{"url"}, pb)),
		}),
		inventory.WithFass(inventory.Fass{
			Name:    first(getPathValues([]string{"name"}, pb)),
			Version: first(getPathValues([]string{"serviceConfig", "revision"}, pb)),
		}),
	}
}

func enrichCloudRunService(_ *gcpinventory.ExtendedGcpAsset, pb *structpb.Struct) []inventory.AssetEnricher {
	return []inventory.AssetEnricher{
		inventory.WithContainer(inventory.Container{
			Name:      getPathValues([]string{"spec", "template", "spec", "containers", "name"}, pb),
			ImageName: getPathValues([]string{"spec", "template", "spec", "containers", "image"}, pb),
		}),
	}
}

func noopEnricher(_ *gcpinventory.ExtendedGcpAsset, _ *structpb.Struct) []inventory.AssetEnricher {
	return []inventory.AssetEnricher{}
}

func getPathValues(keys []string, pb *structpb.Struct) []string {
	m := pb.AsMap()

	var values []string
	var current interface{} = m

	for _, key := range keys {
		if subMap, ok := current.(map[string]interface{}); ok {
			current = subMap[key]
		} else {
			return nil
		}
	}

	switch v := current.(type) {
	case []interface{}:
		for _, item := range v {
			if str, ok := item.(string); ok {
				values = append(values, str)
			}
		}
	case string:
		values = append(values, v)
	}
	return values
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
