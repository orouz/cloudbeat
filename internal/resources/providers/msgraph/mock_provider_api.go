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

package msgraph

import (
	context "context"

	models "github.com/microsoftgraph/msgraph-sdk-go/models"
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

// ListServicePrincipals provides a mock function with given fields: _a0
func (_m *MockProviderAPI) ListServicePrincipals(_a0 context.Context) ([]*models.ServicePrincipal, error) {
	ret := _m.Called(_a0)

	var r0 []*models.ServicePrincipal
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context) ([]*models.ServicePrincipal, error)); ok {
		return rf(_a0)
	}
	if rf, ok := ret.Get(0).(func(context.Context) []*models.ServicePrincipal); ok {
		r0 = rf(_a0)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]*models.ServicePrincipal)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context) error); ok {
		r1 = rf(_a0)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockProviderAPI_ListServicePrincipals_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListServicePrincipals'
type MockProviderAPI_ListServicePrincipals_Call struct {
	*mock.Call
}

// ListServicePrincipals is a helper method to define mock.On call
//   - _a0 context.Context
func (_e *MockProviderAPI_Expecter) ListServicePrincipals(_a0 interface{}) *MockProviderAPI_ListServicePrincipals_Call {
	return &MockProviderAPI_ListServicePrincipals_Call{Call: _e.mock.On("ListServicePrincipals", _a0)}
}

func (_c *MockProviderAPI_ListServicePrincipals_Call) Run(run func(_a0 context.Context)) *MockProviderAPI_ListServicePrincipals_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context))
	})
	return _c
}

func (_c *MockProviderAPI_ListServicePrincipals_Call) Return(_a0 []*models.ServicePrincipal, _a1 error) *MockProviderAPI_ListServicePrincipals_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockProviderAPI_ListServicePrincipals_Call) RunAndReturn(run func(context.Context) ([]*models.ServicePrincipal, error)) *MockProviderAPI_ListServicePrincipals_Call {
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
