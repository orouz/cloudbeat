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

package kms

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/elastic/cloudbeat/resources/providers/awslib"
	"github.com/elastic/elastic-agent-libs/logp"
)

type KMSInfo struct {
	KeyMetadata        types.KeyMetadata
	KeyRotationEnabled *bool
}

type Logging struct {
	Enabled bool `json:"Enabled"`
}

type KMS interface {
	// TODO: rename DescribeSymmetricKeys ?
	DescribeKeys(ctx context.Context) ([]awslib.AwsResource, error)
}

func NewKMSProvider(log *logp.Logger, cfg aws.Config) *Provider {

	// TODO: multi region clients
	return &Provider{
		log:    log,
		client: kms.NewFromConfig(cfg),
		// awsAccountID: awsAccountID,
	}
}
