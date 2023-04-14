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

package fetching

import (
	"context"

	awssdk "github.com/elastic/beats/v7/x-pack/libbeat/common/aws"
	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
)

type ResourceSubType string

const (
	AwsEcr           ResourceSubType = "aws-ecr"
	AwsEks           ResourceSubType = "aws-eks"
	AwsElb           ResourceSubType = "aws-elb"
	AwsKms           ResourceSubType = "aws-kms"
	AwsEc2           ResourceSubType = "aws-ec2"
	AwsEbsSnapshot   ResourceSubType = "aws-ebs-snapshot"
	AwsConfigService ResourceSubType = "aws-config"
	AwsVpc           ResourceSubType = "aws-vpc"
	AwsRds           ResourceSubType = "aws-rds"
	AwsEbs           ResourceSubType = "aws-ebs"
	AwsS3            ResourceSubType = "aws-s3"
	AwsSecurityHub   ResourceSubType = "aws-securityhub"
	AwsNetworkNACL   ResourceSubType = "aws-nacl"
	AwsTrail         ResourceSubType = "aws-trail"
	AwsMultiTrails   ResourceSubType = "aws-multi-trails"
	AwsSecurityGroup ResourceSubType = "aws-security-group"
	AwsIAMUser       ResourceSubType = "aws-iam-user"
	AwsPwdPolicy     ResourceSubType = "aws-password-policy"
)

type ResourceType string

const (
	CloudIdentity          ResourceType = "identity-management"
	EC2Identity            ResourceType = "cloud-compute"
	MonitoringIdentity     ResourceType = "monitoring"
	CloudContainerMgmt     ResourceType = "caas" // containers as a service
	CloudLoadBalancer      ResourceType = "load-balancer"
	CloudContainerRegistry ResourceType = "container-registry"
	CloudStorage           ResourceType = "cloud-storage"
	CloudAudit             ResourceType = "cloud-audit"
	CloudDatabase          ResourceType = "cloud-database"
	CloudConfig            ResourceType = "cloud-config"
	KeyManagement          ResourceType = "key-management"
)

type FetcherType string

const (
	IAMFetcher           FetcherType = "aws-iam"
	KubeAPIFetcher       FetcherType = "kube-api"
	EC2NetworkingFetcher FetcherType = "aws-ec2-network"
	MonitoringFetcher    FetcherType = "aws-monitoring"
	ElbFetcher           FetcherType = "aws-elb"
	EcrFetcher           FetcherType = "aws-ecr"
	EksFetcher           FetcherType = "aws-eks"
	S3Fetcher            FetcherType = "aws-s3"
	TrailFetcher         FetcherType = "aws-trail"
	KmsFetcher           FetcherType = "aws-kms"
	RdsFetcher           FetcherType = "aws-rds"
)

// Factory can create fetcher instances based on configuration
type Factory interface {
	Create(*logp.Logger, *config.C, chan ResourceInfo) (Fetcher, error)
}

// Fetcher represents a data fetcher.
type Fetcher interface {
	Fetch(context.Context, CycleMetadata) error
	Stop()
}

type Condition interface {
	Condition() bool
	Name() string
}

type ResourceInfo struct {
	Resource
	CycleMetadata
}

type CycleMetadata struct {
	Sequence int64
}

type Resource interface {
	GetMetadata() (ResourceMetadata, error)
	GetData() any
	GetElasticCommonData() any
}

type ResourceFields struct {
	ResourceMetadata
	Raw interface{} `json:"raw"`
}

type ResourceMetadata struct {
	ID        string          `json:"id"`
	Type      ResourceType    `json:"type"`
	SubType   ResourceSubType `json:"sub_type,omitempty"`
	Name      string          `json:"name,omitempty"`
	ECSFormat string          `json:"ecsFormat,omitempty"`
}

type Result struct {
	Type     ResourceType    `json:"type"`
	SubType  ResourceSubType `json:"subType"`
	Resource interface{}     `json:"resource"`
}

type ResourceMap map[string][]Resource

type BaseFetcherConfig struct {
	Name FetcherType `config:"name"`
}

type AwsBaseFetcherConfig struct {
	BaseFetcherConfig `config:",inline"`
	AwsConfig         awssdk.ConfigAWS `config:",inline"`
}
