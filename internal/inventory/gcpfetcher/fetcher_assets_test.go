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
	"testing"

	"cloud.google.com/go/asset/apiv1/assetpb"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/elastic/cloudbeat/internal/infra/clog"
	"github.com/elastic/cloudbeat/internal/inventory"
	"github.com/elastic/cloudbeat/internal/inventory/testutil"
	"github.com/elastic/cloudbeat/internal/resources/fetching"
	gcpinventory "github.com/elastic/cloudbeat/internal/resources/providers/gcplib/inventory"
)

func TestAccountFetcher_Fetch_Assets(t *testing.T) {
	logger := clog.NewLogger("gcpfetcher_test")
	assets := []*gcpinventory.ExtendedGcpAsset{
		{
			Asset: &assetpb.Asset{
				Name: "/projects/<project UUID>/some_resource", // name is the ID
			},
			CloudAccount: &fetching.CloudAccountMetadata{
				AccountId:        "<project UUID>",
				AccountName:      "<project name>",
				OrganisationId:   "<org UUID>",
				OrganizationName: "<org name>",
			},
		},
	}

	expected := lo.Map(ResourcesToFetch, func(r ResourcesClassification, _ int) inventory.AssetEvent {
		return inventory.NewAssetEvent(
			r.classification,
			"/projects/<project UUID>/some_resource",
			"/projects/<project UUID>/some_resource",
			inventory.WithRawAsset(assets[0]),
			inventory.WithRelatedAssetIds([]string{}),
			inventory.WithCloud(inventory.Cloud{
				Provider:    inventory.GcpCloudProvider,
				AccountID:   "<project UUID>",
				AccountName: "<project name>",
				ProjectID:   "<org UUID>",
				ProjectName: "<org name>",
				ServiceName: r.assetType,
			}),
		)
	})

	provider := newMockInventoryProvider(t)
	provider.EXPECT().ListAllAssetTypesByName(mock.Anything, mock.AnythingOfType("[]string")).Return(assets, nil)
	fetcher := newAssetsInventoryFetcher(logger, provider)
	testutil.CollectResourcesAndMatch(t, fetcher, expected)
}

func TestAccountFetcher_EnrichAsset(t *testing.T) {
	var data = map[string]struct {
		resource    *assetpb.Resource
		enrichments inventory.AssetEvent
	}{
		gcpinventory.IamRoleAssetType:              {},
		gcpinventory.CrmFolderAssetType:            {},
		gcpinventory.CrmProjectAssetType:           {},
		gcpinventory.StorageBucketAssetType:        {},
		gcpinventory.IamServiceAccountKeyAssetType: {},
		gcpinventory.CrmOrgAssetType: {
			resource: &assetpb.Resource{
				Data: NewStructMap(map[string]interface{}{
					"displayName": "org",
				}),
			},
			enrichments: inventory.AssetEvent{
				Organization: &inventory.Organization{
					Name: "org",
				},
			},
		},
		gcpinventory.ComputeInstanceAssetType: {
			resource: &assetpb.Resource{
				Data: NewStructMap(map[string]interface{}{
					"id":          "id",
					"name":        "name",
					"machineType": "machineType",
					"zone":        "zone",
				}),
			},
			enrichments: inventory.AssetEvent{
				Cloud: &inventory.Cloud{
					InstanceID:       "id",
					InstanceName:     "name",
					MachineType:      "machineType",
					AvailabilityZone: "zone",
				},
			},
		},
		gcpinventory.ComputeFirewallAssetType: {
			resource: &assetpb.Resource{
				Data: NewStructMap(map[string]interface{}{
					"direction": "INGRESS",
					"name":      "default-allow-ssh",
				}),
			},
			enrichments: inventory.AssetEvent{
				Network: &inventory.Network{
					Direction: "INGRESS",
					Name:      "default-allow-ssh",
				},
			},
		},
		gcpinventory.ComputeSubnetworkAssetType: {
			resource: &assetpb.Resource{
				Data: NewStructMap(map[string]interface{}{
					"name":      "subnetwork",
					"stackType": "IPV4_ONLY",
				}),
			},
			enrichments: inventory.AssetEvent{
				Network: &inventory.Network{
					Name: "subnetwork",
					Type: "ipv4_only",
				},
			},
		},
		gcpinventory.IamServiceAccountAssetType: {
			resource: &assetpb.Resource{
				Data: NewStructMap(map[string]interface{}{
					"displayName": "service-account",
					"email":       "service-account@<project UUID>.iam.gserviceaccount.com",
				}),
			},
			enrichments: inventory.AssetEvent{
				User: &inventory.User{
					Name:  "service-account",
					Email: "service-account@<project UUID>.iam.gserviceaccount.com",
				},
			},
		},
		gcpinventory.GkeClusterAssetType: {
			resource: &assetpb.Resource{
				Data: NewStructMap(map[string]interface{}{
					"name": "cluster",
					"id":   "cluster-id",
				}),
			},
			enrichments: inventory.AssetEvent{
				Orchestrator: &inventory.Orchestrator{
					Type:        "kubernetes",
					ClusterName: "cluster",
					ClusterID:   "cluster-id",
				},
			},
		},
		gcpinventory.ComputeForwardingRuleAssetType: {
			resource: &assetpb.Resource{
				Data: NewStructMap(map[string]interface{}{
					"region": "region1",
				}),
			},
			enrichments: inventory.AssetEvent{
				Cloud: &inventory.Cloud{
					Region: "region1",
				},
			},
		},
		gcpinventory.CloudFunctionAssetType: {
			resource: &assetpb.Resource{
				Data: NewStructMap(map[string]interface{}{
					"name": "cloud-function",
					"url":  "https://cloud-function.com",
				}),
			},
			enrichments: inventory.AssetEvent{
				Fass: &inventory.Fass{
					Name: "cloud-function",
				},
				URL: &inventory.URL{
					Full: "https://cloud-function.com",
				},
			},
		},
		gcpinventory.CloudRunService: {},
	}

	for _, r := range ResourcesToFetch {
		item, ok := data[r.assetType]
		if !ok {
			t.Errorf("Missing case for %s", r.assetType)
		}

		gcpAsset := &gcpinventory.ExtendedGcpAsset{
			Asset: &assetpb.Asset{
				Name:      "/projects/<project UUID>/some_resource",
				AssetType: r.assetType,
				Resource:  item.resource,
			},
			CloudAccount: &fetching.CloudAccountMetadata{
				AccountId:        "<project UUID>",
				AccountName:      "<project name>",
				OrganisationId:   "<org UUID>",
				OrganizationName: "<org name>",
			},
		}

		actual := inventory.NewAssetEvent(
			r.classification,
			gcpAsset.Name,
			gcpAsset.Name,
			inventory.WithRawAsset(gcpAsset),
			inventory.WithRelatedAssetIds([]string{}),
			inventory.WithCloud(inventory.Cloud{
				Provider:    inventory.GcpCloudProvider,
				AccountID:   gcpAsset.CloudAccount.AccountId,
				AccountName: gcpAsset.CloudAccount.AccountName,
				ProjectID:   gcpAsset.CloudAccount.OrganisationId,
				ProjectName: gcpAsset.CloudAccount.OrganizationName,
				ServiceName: r.assetType,
			}))

		expected := item.enrichments
		expected.Event = actual.Event                 // Event is not set in the enrichments
		expected.Entity = actual.Entity               // Entity is not set in the enrichments
		expected.RawAttributes = actual.RawAttributes // RawAttributes is not set in the enrichments

		// When there are no cloud fields enrichments, use the actual cloud fields
		if expected.Cloud == nil {
			expected.Cloud = actual.Cloud
		}

		enrichAsset(&actual, gcpAsset)

		// Add or safely override common cloud fields not set in the enrichments
		expected.Cloud.Provider = actual.Cloud.Provider
		expected.Cloud.AccountID = actual.Cloud.AccountID
		expected.Cloud.AccountName = actual.Cloud.AccountName
		expected.Cloud.ProjectID = actual.Cloud.ProjectID
		expected.Cloud.ProjectName = actual.Cloud.ProjectName
		expected.Cloud.ServiceName = actual.Cloud.ServiceName

		assert.Equalf(t, expected, actual, "%v failed", "EnrichAsset")
	}
}

func NewStructMap(data map[string]interface{}) *structpb.Struct {
	dataStruct, err := structpb.NewStruct(data)
	if err != nil {
		panic(err)
	}
	return dataStruct
}
