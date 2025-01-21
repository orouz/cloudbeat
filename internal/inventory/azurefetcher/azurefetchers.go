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

package azurefetcher

import (
	"github.com/elastic/cloudbeat/internal/inventory"
	"github.com/elastic/cloudbeat/internal/resources/providers/azurelib"
	"github.com/elastic/cloudbeat/internal/resources/providers/msgraph"
	"github.com/elastic/cloudbeat/internal/resources/utils/clog"
)

func New(logger *clog.Logger, provider azurelib.ProviderAPI, msgraphProvider msgraph.ProviderAPI) []inventory.AssetFetcher {
	return []inventory.AssetFetcher{
		newAccountFetcher(logger, provider),
		newActiveDirectoryFetcher(logger, msgraphProvider),
		newResourceGraphFetcher(logger, provider),
		newStorageFetcher(logger, provider),
	}
}
