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
		asset := inventory.NewAssetEvent(
			classification,
			item.Name,
			item.Name,
			inventory.WithRawAsset(item),
			inventory.WithRelatedAssetIds(
				f.findRelatedAssetIds(classification.Type, item),
			),
			inventory.WithCloud(inventory.Cloud{
				Provider:    inventory.GcpCloudProvider,
				AccountID:   item.CloudAccount.AccountId,
				AccountName: item.CloudAccount.AccountName,
				ProjectID:   item.CloudAccount.OrganisationId,
				ProjectName: item.CloudAccount.OrganizationName,
				ServiceName: assetType,
			}),
			inventory.WithLabels(getAssetLabels(item)),
			inventory.WithTags(getAssetTags(item)),
		)
		enrichAsset(&asset, item)
		assetChan <- asset
	}
}

func getAssetTags(item *gcpinventory.ExtendedGcpAsset) []string {
	if item.Resource == nil && item.Resource.Data == nil {
		return nil
	}
	fields := item.GetResource().GetData().GetFields()
	if tagsObj, ok := fields["tags"]; ok {
		if items, ok := tagsObj.GetStructValue().GetFields()["items"]; ok {
			tags := items.GetListValue().GetValues()
			var t []string
			for _, tag := range tags {
				t = append(t, tag.GetStringValue())
			}
			return t
		}
	}
	return nil
}

func getAssetLabels(item *gcpinventory.ExtendedGcpAsset) map[string]string {
	if item.Resource == nil && item.Resource.Data == nil {
		return nil
	}
	fields := item.GetResource().GetData().GetFields()
	if value, ok := fields["labels"]; ok {
		convertedMap := make(map[string]string)
		if err := mapstructure.Decode(value.GetStructValue().AsMap(), &convertedMap); err != nil {
			return nil
		}
		return convertedMap
	}
	return nil
}

func enrichAsset(asset *inventory.AssetEvent, item *gcpinventory.ExtendedGcpAsset) {
	if item.Resource == nil && item.Resource.Data == nil {
		return
	}
	fields := item.GetResource().GetData().GetFields()
	getStringValue := func(key string, f map[string]*structpb.Value) string {
		if value, ok := f[key]; ok {
			return value.GetStringValue()
		}
		return ""
	}

	switch item.AssetType {
	case gcpinventory.IamRoleAssetType:
		// TODO: Cloud, Entity, User, Labels (if tags/labels are available)
		// TODO: what user values? https://cloud.google.com/iam/docs/reference/rest/v1/roles

	case gcpinventory.IamServiceAccountKeyAssetType:
		// TODO: Cloud, Entity, User (the SA key is for), Labels (if tags/labels are available)
		// TODO: what user values? https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts.keys

	case gcpinventory.IamServiceAccountAssetType:
		// TODO: Cloud, Entity, User, Labels (if tags/labels are available)
		asset.User = &inventory.User{
			Email: getStringValue("email", fields),
			Name:  getStringValue("displayName", fields),
		}

	case gcpinventory.ComputeInstanceAssetType:
		// TODO: Cloud, Entity, Host, Labels (if tags/labels are available)
		// https://cloud.google.com/compute/docs/reference/rest/v1/instances#resource:-instance
		asset.Cloud.InstanceID = getStringValue("id", fields)
		asset.Cloud.InstanceName = getStringValue("name", fields)
		asset.Cloud.MachineType = getStringValue("machineType", fields)
		asset.Cloud.AvailabilityZone = getStringValue("zone", fields)

	case gcpinventory.GkeClusterAssetType:
		// TODO: Cloud, Entity, Orchastrator, Labels (if tags/labels are available)
		asset.Orchestrator = &inventory.Orchestrator{
			Type:        "kubernetes",
			ClusterName: getStringValue("name", fields),
			ClusterID:   getStringValue("id", fields),
		}
	case gcpinventory.CloudRunService:
		// TODO: Cloud, Entity, Container, Labels (if tags/labels are available)
		container := &inventory.Container{}
		// if metadata, ok := fields["metadata"]; ok {
		// 	metadataFields := metadata.GetStructValue().GetFields()
		// 	container.Name = getStringValue("name", metadataFields)
		// 	container.ID=  getStringValue("uid", metadataFields)
		// }

		if spec, ok := fields["spec"]; ok {
			specFields := spec.GetStructValue().GetFields()
			if containers, ok := specFields["containers"]; ok {
				for _, containerValue := range containers.GetListValue().GetValues() {
					containerFields := containerValue.GetStructValue().GetFields()
					container.ImageName = getStringValue("image", containerFields)
				}
			}
		}

		asset.Container = container

	case gcpinventory.CrmOrgAssetType:
		// TODO: Cloud, Entity, Organization, Labels (if tags/labels are available)
	case gcpinventory.CrmProjectAssetType:
		// TODO: Cloud, Entity, Labels (if tags/labels are available)
	case gcpinventory.CrmFolderAssetType:
		// TODO: Cloud, Entity, Organization, Labels (if tags/labels are available)
	case gcpinventory.ComputeFirewallAssetType:
		// TODO: Cloud, Entity, Labels (if tags/labels are available)
		// https://cloud.google.com/compute/docs/reference/rest/v1/firewalls#resource:-firewall
		asset.Network = &inventory.Network{
			Name:      getStringValue("name", fields), // use "network" field?
			Direction: getStringValue("direction", fields),
		}
		// TODO:
		// https://www.elastic.co/guide/en/ecs/current/ecs-network.html#field-network-transport
		// asset.Network.Transport = allowed[].IPProtocol (example: icmp)
		// https://www.elastic.co/guide/en/ecs/current/ecs-network.html#field-network-iana-number
		// asset.Network.IanaNumber = allowed[].IPProtocol -> https://pkg.go.dev/golang.org/x/net/internal/iana
	case gcpinventory.ComputeForwardingRuleAssetType:
		// TODO: Cloud, Entity, Labels (if tags/labels are available)
	case
		// TODO: Cloud, Entity, Labels (if tags/labels are available)
		// https://cloud.google.com/compute/docs/reference/rest/v1/subnetworks#resource:-subnetwork
		gcpinventory.ComputeSubnetworkAssetType:
		asset.Network = &inventory.Network{
			Name: getStringValue("name", fields),
			Type: strings.ToLower(getStringValue("stackType", fields)),
		}
	case gcpinventory.CloudFunctionAssetType:
		// TODO: Cloud, Entity, FaaS, Labels (if tags/labels are available)
	case
		// TODO: Cloud, Entity, Labels (if tags/labels are available)
		// https://cloud.google.com/storage/docs/json_api/v1/buckets#resource-representations
		gcpinventory.StorageBucketAssetType:
	}

}

func (f *assetsInventory) findRelatedAssetIds(t inventory.AssetType, item *gcpinventory.ExtendedGcpAsset) []string {
	ids := []string{}
	ids = append(ids, item.Ancestors...)
	if item.Resource != nil {
		ids = append(ids, item.Resource.Parent)
	}

	ids = append(ids, f.findRelatedAssetIdsForType(t, item)...)

	ids = lo.Compact(ids)
	ids = lo.Uniq(ids)
	return ids
}

func (f *assetsInventory) findRelatedAssetIdsForType(t inventory.AssetType, item *gcpinventory.ExtendedGcpAsset) []string {
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
