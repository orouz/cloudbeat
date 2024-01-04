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

// Code generated by mockery v2.37.1. DO NOT EDIT.

package inventory

import (
	context "context"

	cycle "github.com/elastic/cloudbeat/resources/fetching/cycle"
	mock "github.com/stretchr/testify/mock"
)

// MockProviderAPI is an autogenerated mock type for the ProviderAPI type
type MockProviderAPI struct {
	mock.Mock
}

type MockProviderAPI_Expecter struct {
	mock *mock.Mock
}

func (_m *MockProviderAPI) EXPECT() *MockProviderAPI_Expecter {
	return &MockProviderAPI_Expecter{mock: &_m.Mock}
}

// ListAllAssetTypesByName provides a mock function with given fields: ctx, assetsGroup, assets
func (_m *MockProviderAPI) ListAllAssetTypesByName(ctx context.Context, assetsGroup string, assets []string) ([]AzureAsset, error) {
	ret := _m.Called(ctx, assetsGroup, assets)

	var r0 []AzureAsset
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, []string) ([]AzureAsset, error)); ok {
		return rf(ctx, assetsGroup, assets)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, []string) []AzureAsset); ok {
		r0 = rf(ctx, assetsGroup, assets)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]AzureAsset)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, []string) error); ok {
		r1 = rf(ctx, assetsGroup, assets)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockProviderAPI_ListAllAssetTypesByName_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListAllAssetTypesByName'
type MockProviderAPI_ListAllAssetTypesByName_Call struct {
	*mock.Call
}

// ListAllAssetTypesByName is a helper method to define mock.On call
//   - ctx context.Context
//   - assetsGroup string
//   - assets []string
func (_e *MockProviderAPI_Expecter) ListAllAssetTypesByName(ctx interface{}, assetsGroup interface{}, assets interface{}) *MockProviderAPI_ListAllAssetTypesByName_Call {
	return &MockProviderAPI_ListAllAssetTypesByName_Call{Call: _e.mock.On("ListAllAssetTypesByName", ctx, assetsGroup, assets)}
}

func (_c *MockProviderAPI_ListAllAssetTypesByName_Call) Run(run func(ctx context.Context, assetsGroup string, assets []string)) *MockProviderAPI_ListAllAssetTypesByName_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].([]string))
	})
	return _c
}

func (_c *MockProviderAPI_ListAllAssetTypesByName_Call) Return(_a0 []AzureAsset, _a1 error) *MockProviderAPI_ListAllAssetTypesByName_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockProviderAPI_ListAllAssetTypesByName_Call) RunAndReturn(run func(context.Context, string, []string) ([]AzureAsset, error)) *MockProviderAPI_ListAllAssetTypesByName_Call {
	_c.Call.Return(run)
	return _c
}

// ListDiagnosticSettingsAssetTypes provides a mock function with given fields: ctx, cycleMetadata, subscriptionIDs
func (_m *MockProviderAPI) ListDiagnosticSettingsAssetTypes(ctx context.Context, cycleMetadata cycle.Metadata, subscriptionIDs []string) ([]AzureAsset, error) {
	ret := _m.Called(ctx, cycleMetadata, subscriptionIDs)

	var r0 []AzureAsset
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, cycle.Metadata, []string) ([]AzureAsset, error)); ok {
		return rf(ctx, cycleMetadata, subscriptionIDs)
	}
	if rf, ok := ret.Get(0).(func(context.Context, cycle.Metadata, []string) []AzureAsset); ok {
		r0 = rf(ctx, cycleMetadata, subscriptionIDs)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]AzureAsset)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, cycle.Metadata, []string) error); ok {
		r1 = rf(ctx, cycleMetadata, subscriptionIDs)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockProviderAPI_ListDiagnosticSettingsAssetTypes_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListDiagnosticSettingsAssetTypes'
type MockProviderAPI_ListDiagnosticSettingsAssetTypes_Call struct {
	*mock.Call
}

// ListDiagnosticSettingsAssetTypes is a helper method to define mock.On call
//   - ctx context.Context
//   - cycleMetadata cycle.Metadata
//   - subscriptionIDs []string
func (_e *MockProviderAPI_Expecter) ListDiagnosticSettingsAssetTypes(ctx interface{}, cycleMetadata interface{}, subscriptionIDs interface{}) *MockProviderAPI_ListDiagnosticSettingsAssetTypes_Call {
	return &MockProviderAPI_ListDiagnosticSettingsAssetTypes_Call{Call: _e.mock.On("ListDiagnosticSettingsAssetTypes", ctx, cycleMetadata, subscriptionIDs)}
}

func (_c *MockProviderAPI_ListDiagnosticSettingsAssetTypes_Call) Run(run func(ctx context.Context, cycleMetadata cycle.Metadata, subscriptionIDs []string)) *MockProviderAPI_ListDiagnosticSettingsAssetTypes_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(cycle.Metadata), args[2].([]string))
	})
	return _c
}

func (_c *MockProviderAPI_ListDiagnosticSettingsAssetTypes_Call) Return(_a0 []AzureAsset, _a1 error) *MockProviderAPI_ListDiagnosticSettingsAssetTypes_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockProviderAPI_ListDiagnosticSettingsAssetTypes_Call) RunAndReturn(run func(context.Context, cycle.Metadata, []string) ([]AzureAsset, error)) *MockProviderAPI_ListDiagnosticSettingsAssetTypes_Call {
	_c.Call.Return(run)
	return _c
}

// ListSQLEncryptionProtector provides a mock function with given fields: ctx, subID, resourceGroup, sqlServerName
func (_m *MockProviderAPI) ListSQLEncryptionProtector(ctx context.Context, subID string, resourceGroup string, sqlServerName string) ([]AzureAsset, error) {
	ret := _m.Called(ctx, subID, resourceGroup, sqlServerName)

	var r0 []AzureAsset
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) ([]AzureAsset, error)); ok {
		return rf(ctx, subID, resourceGroup, sqlServerName)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) []AzureAsset); ok {
		r0 = rf(ctx, subID, resourceGroup, sqlServerName)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]AzureAsset)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, string) error); ok {
		r1 = rf(ctx, subID, resourceGroup, sqlServerName)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockProviderAPI_ListSQLEncryptionProtector_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListSQLEncryptionProtector'
type MockProviderAPI_ListSQLEncryptionProtector_Call struct {
	*mock.Call
}

// ListSQLEncryptionProtector is a helper method to define mock.On call
//   - ctx context.Context
//   - subID string
//   - resourceGroup string
//   - sqlServerName string
func (_e *MockProviderAPI_Expecter) ListSQLEncryptionProtector(ctx interface{}, subID interface{}, resourceGroup interface{}, sqlServerName interface{}) *MockProviderAPI_ListSQLEncryptionProtector_Call {
	return &MockProviderAPI_ListSQLEncryptionProtector_Call{Call: _e.mock.On("ListSQLEncryptionProtector", ctx, subID, resourceGroup, sqlServerName)}
}

func (_c *MockProviderAPI_ListSQLEncryptionProtector_Call) Run(run func(ctx context.Context, subID string, resourceGroup string, sqlServerName string)) *MockProviderAPI_ListSQLEncryptionProtector_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(string), args[2].(string), args[3].(string))
	})
	return _c
}

func (_c *MockProviderAPI_ListSQLEncryptionProtector_Call) Return(_a0 []AzureAsset, _a1 error) *MockProviderAPI_ListSQLEncryptionProtector_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockProviderAPI_ListSQLEncryptionProtector_Call) RunAndReturn(run func(context.Context, string, string, string) ([]AzureAsset, error)) *MockProviderAPI_ListSQLEncryptionProtector_Call {
	_c.Call.Return(run)
	return _c
}

// ListStorageAccountBlobServices provides a mock function with given fields: ctx, storageAccounts
func (_m *MockProviderAPI) ListStorageAccountBlobServices(ctx context.Context, storageAccounts []AzureAsset) ([]AzureAsset, error) {
	ret := _m.Called(ctx, storageAccounts)

	var r0 []AzureAsset
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, []AzureAsset) ([]AzureAsset, error)); ok {
		return rf(ctx, storageAccounts)
	}
	if rf, ok := ret.Get(0).(func(context.Context, []AzureAsset) []AzureAsset); ok {
		r0 = rf(ctx, storageAccounts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]AzureAsset)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, []AzureAsset) error); ok {
		r1 = rf(ctx, storageAccounts)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockProviderAPI_ListStorageAccountBlobServices_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListStorageAccountBlobServices'
type MockProviderAPI_ListStorageAccountBlobServices_Call struct {
	*mock.Call
}

// ListStorageAccountBlobServices is a helper method to define mock.On call
//   - ctx context.Context
//   - storageAccounts []AzureAsset
func (_e *MockProviderAPI_Expecter) ListStorageAccountBlobServices(ctx interface{}, storageAccounts interface{}) *MockProviderAPI_ListStorageAccountBlobServices_Call {
	return &MockProviderAPI_ListStorageAccountBlobServices_Call{Call: _e.mock.On("ListStorageAccountBlobServices", ctx, storageAccounts)}
}

func (_c *MockProviderAPI_ListStorageAccountBlobServices_Call) Run(run func(ctx context.Context, storageAccounts []AzureAsset)) *MockProviderAPI_ListStorageAccountBlobServices_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].([]AzureAsset))
	})
	return _c
}

func (_c *MockProviderAPI_ListStorageAccountBlobServices_Call) Return(_a0 []AzureAsset, _a1 error) *MockProviderAPI_ListStorageAccountBlobServices_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockProviderAPI_ListStorageAccountBlobServices_Call) RunAndReturn(run func(context.Context, []AzureAsset) ([]AzureAsset, error)) *MockProviderAPI_ListStorageAccountBlobServices_Call {
	_c.Call.Return(run)
	return _c
}

// ListStorageAccountsBlobDiagnosticSettings provides a mock function with given fields: ctx, storageAccounts
func (_m *MockProviderAPI) ListStorageAccountsBlobDiagnosticSettings(ctx context.Context, storageAccounts []AzureAsset) ([]AzureAsset, error) {
	ret := _m.Called(ctx, storageAccounts)

	var r0 []AzureAsset
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, []AzureAsset) ([]AzureAsset, error)); ok {
		return rf(ctx, storageAccounts)
	}
	if rf, ok := ret.Get(0).(func(context.Context, []AzureAsset) []AzureAsset); ok {
		r0 = rf(ctx, storageAccounts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]AzureAsset)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, []AzureAsset) error); ok {
		r1 = rf(ctx, storageAccounts)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockProviderAPI_ListStorageAccountsBlobDiagnosticSettings_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListStorageAccountsBlobDiagnosticSettings'
type MockProviderAPI_ListStorageAccountsBlobDiagnosticSettings_Call struct {
	*mock.Call
}

// ListStorageAccountsBlobDiagnosticSettings is a helper method to define mock.On call
//   - ctx context.Context
//   - storageAccounts []AzureAsset
func (_e *MockProviderAPI_Expecter) ListStorageAccountsBlobDiagnosticSettings(ctx interface{}, storageAccounts interface{}) *MockProviderAPI_ListStorageAccountsBlobDiagnosticSettings_Call {
	return &MockProviderAPI_ListStorageAccountsBlobDiagnosticSettings_Call{Call: _e.mock.On("ListStorageAccountsBlobDiagnosticSettings", ctx, storageAccounts)}
}

func (_c *MockProviderAPI_ListStorageAccountsBlobDiagnosticSettings_Call) Run(run func(ctx context.Context, storageAccounts []AzureAsset)) *MockProviderAPI_ListStorageAccountsBlobDiagnosticSettings_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].([]AzureAsset))
	})
	return _c
}

func (_c *MockProviderAPI_ListStorageAccountsBlobDiagnosticSettings_Call) Return(_a0 []AzureAsset, _a1 error) *MockProviderAPI_ListStorageAccountsBlobDiagnosticSettings_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockProviderAPI_ListStorageAccountsBlobDiagnosticSettings_Call) RunAndReturn(run func(context.Context, []AzureAsset) ([]AzureAsset, error)) *MockProviderAPI_ListStorageAccountsBlobDiagnosticSettings_Call {
	_c.Call.Return(run)
	return _c
}

// ListStorageAccountsQueueDiagnosticSettings provides a mock function with given fields: ctx, storageAccounts
func (_m *MockProviderAPI) ListStorageAccountsQueueDiagnosticSettings(ctx context.Context, storageAccounts []AzureAsset) ([]AzureAsset, error) {
	ret := _m.Called(ctx, storageAccounts)

	var r0 []AzureAsset
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, []AzureAsset) ([]AzureAsset, error)); ok {
		return rf(ctx, storageAccounts)
	}
	if rf, ok := ret.Get(0).(func(context.Context, []AzureAsset) []AzureAsset); ok {
		r0 = rf(ctx, storageAccounts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]AzureAsset)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, []AzureAsset) error); ok {
		r1 = rf(ctx, storageAccounts)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockProviderAPI_ListStorageAccountsQueueDiagnosticSettings_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListStorageAccountsQueueDiagnosticSettings'
type MockProviderAPI_ListStorageAccountsQueueDiagnosticSettings_Call struct {
	*mock.Call
}

// ListStorageAccountsQueueDiagnosticSettings is a helper method to define mock.On call
//   - ctx context.Context
//   - storageAccounts []AzureAsset
func (_e *MockProviderAPI_Expecter) ListStorageAccountsQueueDiagnosticSettings(ctx interface{}, storageAccounts interface{}) *MockProviderAPI_ListStorageAccountsQueueDiagnosticSettings_Call {
	return &MockProviderAPI_ListStorageAccountsQueueDiagnosticSettings_Call{Call: _e.mock.On("ListStorageAccountsQueueDiagnosticSettings", ctx, storageAccounts)}
}

func (_c *MockProviderAPI_ListStorageAccountsQueueDiagnosticSettings_Call) Run(run func(ctx context.Context, storageAccounts []AzureAsset)) *MockProviderAPI_ListStorageAccountsQueueDiagnosticSettings_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].([]AzureAsset))
	})
	return _c
}

func (_c *MockProviderAPI_ListStorageAccountsQueueDiagnosticSettings_Call) Return(_a0 []AzureAsset, _a1 error) *MockProviderAPI_ListStorageAccountsQueueDiagnosticSettings_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockProviderAPI_ListStorageAccountsQueueDiagnosticSettings_Call) RunAndReturn(run func(context.Context, []AzureAsset) ([]AzureAsset, error)) *MockProviderAPI_ListStorageAccountsQueueDiagnosticSettings_Call {
	_c.Call.Return(run)
	return _c
}

// ListStorageAccountsTableDiagnosticSettings provides a mock function with given fields: ctx, storageAccounts
func (_m *MockProviderAPI) ListStorageAccountsTableDiagnosticSettings(ctx context.Context, storageAccounts []AzureAsset) ([]AzureAsset, error) {
	ret := _m.Called(ctx, storageAccounts)

	var r0 []AzureAsset
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, []AzureAsset) ([]AzureAsset, error)); ok {
		return rf(ctx, storageAccounts)
	}
	if rf, ok := ret.Get(0).(func(context.Context, []AzureAsset) []AzureAsset); ok {
		r0 = rf(ctx, storageAccounts)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]AzureAsset)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, []AzureAsset) error); ok {
		r1 = rf(ctx, storageAccounts)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockProviderAPI_ListStorageAccountsTableDiagnosticSettings_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListStorageAccountsTableDiagnosticSettings'
type MockProviderAPI_ListStorageAccountsTableDiagnosticSettings_Call struct {
	*mock.Call
}

// ListStorageAccountsTableDiagnosticSettings is a helper method to define mock.On call
//   - ctx context.Context
//   - storageAccounts []AzureAsset
func (_e *MockProviderAPI_Expecter) ListStorageAccountsTableDiagnosticSettings(ctx interface{}, storageAccounts interface{}) *MockProviderAPI_ListStorageAccountsTableDiagnosticSettings_Call {
	return &MockProviderAPI_ListStorageAccountsTableDiagnosticSettings_Call{Call: _e.mock.On("ListStorageAccountsTableDiagnosticSettings", ctx, storageAccounts)}
}

func (_c *MockProviderAPI_ListStorageAccountsTableDiagnosticSettings_Call) Run(run func(ctx context.Context, storageAccounts []AzureAsset)) *MockProviderAPI_ListStorageAccountsTableDiagnosticSettings_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].([]AzureAsset))
	})
	return _c
}

func (_c *MockProviderAPI_ListStorageAccountsTableDiagnosticSettings_Call) Return(_a0 []AzureAsset, _a1 error) *MockProviderAPI_ListStorageAccountsTableDiagnosticSettings_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockProviderAPI_ListStorageAccountsTableDiagnosticSettings_Call) RunAndReturn(run func(context.Context, []AzureAsset) ([]AzureAsset, error)) *MockProviderAPI_ListStorageAccountsTableDiagnosticSettings_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockProviderAPI creates a new instance of MockProviderAPI. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockProviderAPI(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockProviderAPI {
	mock := &MockProviderAPI{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
