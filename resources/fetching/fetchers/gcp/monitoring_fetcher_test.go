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

package fetchers

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"cloud.google.com/go/asset/apiv1/assetpb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"github.com/elastic/cloudbeat/resources/fetching"
	"github.com/elastic/cloudbeat/resources/providers/gcplib"
	"github.com/elastic/cloudbeat/resources/providers/gcplib/inventory"
	"github.com/elastic/cloudbeat/resources/utils/testhelper"
)

const projectId = "test-project"

type GcpMonitoringFetcherTestSuite struct {
	suite.Suite

	resourceCh chan fetching.ResourceInfo
}

func TestGcpMonitoringFetcherTestSuite(t *testing.T) {
	s := new(GcpMonitoringFetcherTestSuite)

	suite.Run(t, s)
}

func (s *GcpMonitoringFetcherTestSuite) SetupTest() {
	s.resourceCh = make(chan fetching.ResourceInfo, 50)
}

func (s *GcpMonitoringFetcherTestSuite) TearDownTest() {
	close(s.resourceCh)
}

func (s *GcpMonitoringFetcherTestSuite) TestFetcher_Fetch_Success() {
	ctx := context.Background()
	mockInventoryService := &inventory.MockServiceAPI{}
	fetcher := GcpMonitoringFetcher{
		log:        testhelper.NewLogger(s.T()),
		resourceCh: s.resourceCh,
		provider:   mockInventoryService,
	}

	mockInventoryService.On("ListMonitoringAssets", mock.Anything).Return(
		[]*inventory.MonitoringAsset{
			{
				EcsGcpCloud: &fetching.EcsGcpCloud{
					Provider:         "gcp",
					ProjectId:        "a",
					ProjectName:      "a",
					OrganizationId:   "a",
					OrganizationName: "a",
				},
				LogMetrics: []*inventory.ExtendedGcpAsset{
					{Asset: &assetpb.Asset{Name: "a", AssetType: "logging.googleapis.com/LogMetric"}},
				},
				Alerts: []*inventory.ExtendedGcpAsset{
					{Asset: &assetpb.Asset{Name: "b", AssetType: "monitoring.googleapis.com/AlertPolicy"}},
				},
			},
		}, nil,
	)

	err := fetcher.Fetch(ctx, fetching.CycleMetadata{})
	s.NoError(err)
	results := testhelper.CollectResources(s.resourceCh)

	// ListMonitoringAssets mocked to return a single asset
	s.Equal(1, len(results))
}

func (s *GcpMonitoringFetcherTestSuite) TestFetcher_Fetch_Error() {
	ctx := context.Background()
	mockInventoryService := &inventory.MockServiceAPI{}
	fetcher := GcpMonitoringFetcher{
		log:        testhelper.NewLogger(s.T()),
		resourceCh: s.resourceCh,
		provider:   mockInventoryService,
	}

	mockInventoryService.On("ListMonitoringAssets", mock.Anything).Return(nil, errors.New("api call error"))

	err := fetcher.Fetch(ctx, fetching.CycleMetadata{})
	s.Error(err)
}

func TestMonitoringResource_GetMetadata(t *testing.T) {
	tests := []struct {
		name     string
		resource GcpMonitoringAsset
		want     fetching.ResourceMetadata
		wantErr  bool
	}{
		{
			name: "happy path",
			resource: GcpMonitoringAsset{
				Type:    fetching.MonitoringIdentity,
				subType: fetching.GcpMonitoringType,
				Asset: &inventory.MonitoringAsset{
					EcsGcpCloud: &fetching.EcsGcpCloud{
						ProjectId:        projectId,
						ProjectName:      "a",
						OrganizationId:   "a",
						OrganizationName: "a",
					},
					LogMetrics: []*inventory.ExtendedGcpAsset{},
					Alerts:     []*inventory.ExtendedGcpAsset{},
				},
			},
			want: fetching.ResourceMetadata{
				ID:        fmt.Sprintf("%s-%s", fetching.GcpMonitoringType, projectId),
				Name:      fmt.Sprintf("%s-%s", fetching.GcpMonitoringType, projectId),
				Type:      fetching.MonitoringIdentity,
				SubType:   fetching.GcpMonitoringType,
				Region:    gcplib.GlobalRegion,
				ECSFormat: "cloud",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.resource.GetMetadata()

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
