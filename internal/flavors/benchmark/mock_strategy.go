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

package benchmark

import (
	config "github.com/elastic/cloudbeat/internal/config"
	builder "github.com/elastic/cloudbeat/internal/flavors/benchmark/builder"

	context "context"

	"github.com/elastic/cloudbeat/internal/resources/utils/clog"

	mock "github.com/stretchr/testify/mock"
)

// MockStrategy is an autogenerated mock type for the Strategy type
type MockStrategy struct {
	mock.Mock
}

type MockStrategy_Expecter struct {
	mock *mock.Mock
}

func (_m *MockStrategy) EXPECT() *MockStrategy_Expecter {
	return &MockStrategy_Expecter{mock: &_m.Mock}
}

// NewBenchmark provides a mock function with given fields: ctx, log, cfg
func (_m *MockStrategy) NewBenchmark(ctx context.Context, log *clog.Logger, cfg *config.Config) (builder.Benchmark, error) {
	ret := _m.Called(ctx, log, cfg)

	var r0 builder.Benchmark
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *clog.Logger, *config.Config) (builder.Benchmark, error)); ok {
		return rf(ctx, log, cfg)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *clog.Logger, *config.Config) builder.Benchmark); ok {
		r0 = rf(ctx, log, cfg)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(builder.Benchmark)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *clog.Logger, *config.Config) error); ok {
		r1 = rf(ctx, log, cfg)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockStrategy_NewBenchmark_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'NewBenchmark'
type MockStrategy_NewBenchmark_Call struct {
	*mock.Call
}

// NewBenchmark is a helper method to define mock.On call
//   - ctx context.Context
//   - log *clog.Logger
//   - cfg *config.Config
func (_e *MockStrategy_Expecter) NewBenchmark(ctx interface{}, log interface{}, cfg interface{}) *MockStrategy_NewBenchmark_Call {
	return &MockStrategy_NewBenchmark_Call{Call: _e.mock.On("NewBenchmark", ctx, log, cfg)}
}

func (_c *MockStrategy_NewBenchmark_Call) Run(run func(ctx context.Context, log *clog.Logger, cfg *config.Config)) *MockStrategy_NewBenchmark_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(context.Context), args[1].(*clog.Logger), args[2].(*config.Config))
	})
	return _c
}

func (_c *MockStrategy_NewBenchmark_Call) Return(_a0 builder.Benchmark, _a1 error) *MockStrategy_NewBenchmark_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockStrategy_NewBenchmark_Call) RunAndReturn(run func(context.Context, *clog.Logger, *config.Config) (builder.Benchmark, error)) *MockStrategy_NewBenchmark_Call {
	_c.Call.Return(run)
	return _c
}

// checkDependencies provides a mock function with given fields:
func (_m *MockStrategy) checkDependencies() error {
	ret := _m.Called()

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockStrategy_checkDependencies_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'checkDependencies'
type MockStrategy_checkDependencies_Call struct {
	*mock.Call
}

// checkDependencies is a helper method to define mock.On call
func (_e *MockStrategy_Expecter) checkDependencies() *MockStrategy_checkDependencies_Call {
	return &MockStrategy_checkDependencies_Call{Call: _e.mock.On("checkDependencies")}
}

func (_c *MockStrategy_checkDependencies_Call) Run(run func()) *MockStrategy_checkDependencies_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockStrategy_checkDependencies_Call) Return(_a0 error) *MockStrategy_checkDependencies_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockStrategy_checkDependencies_Call) RunAndReturn(run func() error) *MockStrategy_checkDependencies_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockStrategy creates a new instance of MockStrategy. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockStrategy(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockStrategy {
	mock := &MockStrategy{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
