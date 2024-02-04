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

package k8s

import (
	context "context"

	config "github.com/elastic/cloudbeat/internal/config"

	mock "github.com/stretchr/testify/mock"
)

// MockClusterNameProviderAPI is an autogenerated mock type for the ClusterNameProviderAPI type
type MockClusterNameProviderAPI struct {
	mock.Mock
}

type MockClusterNameProviderAPI_Expecter struct {
	mock *mock.Mock
}

func (_m *MockClusterNameProviderAPI) EXPECT() *MockClusterNameProviderAPI_Expecter {
	return &MockClusterNameProviderAPI_Expecter{mock: &_m.Mock}
}

// GetClusterName provides a mock function with given fields: ctx, cfg
func (_m *MockClusterNameProviderAPI) GetClusterName(ctx context.Context, cfg *config.Config) (string, error) {
	ret := _m.Called(ctx, cfg)

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *config.Config) (string, error)); ok {
		return rf(ctx, cfg)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *config.Config) string); ok {
		r0 = rf(ctx, cfg)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(context.Context, *config.Config) error); ok {
		r1 = rf(ctx, cfg)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockClusterNameProviderAPI_GetClusterName_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetClusterName'
type MockClusterNameProviderAPI_GetClusterName_Call struct {
	*mock.Call
}

// GetClusterName is a helper method to define mock.On call
//   - ctx context.Context
//   - cfg *config.Config
func (_e *MockClusterNameProviderAPI_Expecter) GetClusterName(ctx interface{}, cfg interface{}) *MockClusterNameProviderAPI_GetClusterName_Call {
	return &MockClusterNameProviderAPI_GetClusterName_Call{Call: _e.mock.On("GetClusterName", ctx, cfg)}
}

func (_c *MockClusterNameProviderAPI_GetClusterName_Call) Run(run func(ctx context.Context, cfg *config.Config)) *MockClusterNameProviderAPI_GetClusterName_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*config.Config))
	})
	return _c
}

func (_c *MockClusterNameProviderAPI_GetClusterName_Call) Return(_a0 string, _a1 error) *MockClusterNameProviderAPI_GetClusterName_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockClusterNameProviderAPI_GetClusterName_Call) RunAndReturn(run func(context.Context, *config.Config) (string, error)) *MockClusterNameProviderAPI_GetClusterName_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockClusterNameProviderAPI creates a new instance of MockClusterNameProviderAPI. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockClusterNameProviderAPI(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockClusterNameProviderAPI {
	mock := &MockClusterNameProviderAPI{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
