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

	kmsClient "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/elastic/cloudbeat/resources/fetching"
	"github.com/elastic/cloudbeat/resources/providers/awslib"
	"github.com/elastic/elastic-agent-libs/logp"
)

type Provider struct {
	log     *logp.Logger
	clients map[string]Client
}

type Client interface {
	ListKeys(ctx context.Context, params *kmsClient.ListKeysInput, optFns ...func(*kmsClient.Options)) (*kmsClient.ListKeysOutput, error)
	DescribeKey(ctx context.Context, params *kmsClient.DescribeKeyInput, optFns ...func(*kmsClient.Options)) (*kmsClient.DescribeKeyOutput, error)
	GetKeyRotationStatus(ctx context.Context, params *kmsClient.GetKeyRotationStatusInput, optFns ...func(*kmsClient.Options)) (*kmsClient.GetKeyRotationStatusOutput, error)
}

func (p Provider) DescribeKeys(ctx context.Context) ([]awslib.AwsResource, error) {

	var result []awslib.AwsResource
	for _, client := range p.clients {
		clientKeys, err := client.ListKeys(ctx, &kmsClient.ListKeysInput{})
		if err != nil {
			p.log.Errorf("Could not list KMS keys: %v", err)
			return nil, err
		}

		for _, keyEntry := range clientKeys.Keys {
			keyId := keyEntry.KeyId

			keyInfo, err := client.DescribeKey(ctx, &kmsClient.DescribeKeyInput{
				KeyId: keyId,
			})
			if err != nil {
				p.log.Errorf("Error describing KMS key %s %v", keyId, err.Error())
				continue
			}

			if keyInfo.KeyMetadata.KeySpec != types.KeySpecSymmetricDefault {
				continue
			}

			rotationStatus, err := client.GetKeyRotationStatus(ctx, &kmsClient.GetKeyRotationStatusInput{
				KeyId: keyId,
			})
			if err != nil {
				p.log.Errorf("Error getting KMS key rotation status: %s %v", *keyInfo, err.Error())
				continue
			}

			result = append(result, KMSInfo{
				KeyMetadata:        *keyInfo.KeyMetadata,
				KeyRotationEnabled: &rotationStatus.KeyRotationEnabled,
			})
		}
	}

	return result, nil
}

func (v KMSInfo) GetResourceArn() string {
	if v.KeyMetadata.Arn == nil {
		return ""
	}
	return *v.KeyMetadata.Arn

}

func (v KMSInfo) GetResourceName() string {
	if v.KeyMetadata.KeyId == nil {
		return ""
	}
	return *v.KeyMetadata.KeyId
}

func (v KMSInfo) GetResourceType() string {
	return fetching.KmsType
}
