// Code generated by mockery v2.15.0. DO NOT EDIT.

package kms

import (
	context "context"

	servicekms "github.com/aws/aws-sdk-go-v2/service/kms"
	mock "github.com/stretchr/testify/mock"
)

// MockClient is an autogenerated mock type for the Client type
type MockClient struct {
	mock.Mock
}

type MockClient_Expecter struct {
	mock *mock.Mock
}

func (_m *MockClient) EXPECT() *MockClient_Expecter {
	return &MockClient_Expecter{mock: &_m.Mock}
}

// DescribeKey provides a mock function with given fields: ctx, params, optFns
func (_m *MockClient) DescribeKey(ctx context.Context, params *servicekms.DescribeKeyInput, optFns ...func(*servicekms.Options)) (*servicekms.DescribeKeyOutput, error) {
	_va := make([]interface{}, len(optFns))
	for _i := range optFns {
		_va[_i] = optFns[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx, params)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	var r0 *servicekms.DescribeKeyOutput
	if rf, ok := ret.Get(0).(func(context.Context, *servicekms.DescribeKeyInput, ...func(*servicekms.Options)) *servicekms.DescribeKeyOutput); ok {
		r0 = rf(ctx, params, optFns...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*servicekms.DescribeKeyOutput)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *servicekms.DescribeKeyInput, ...func(*servicekms.Options)) error); ok {
		r1 = rf(ctx, params, optFns...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockClient_DescribeKey_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'DescribeKey'
type MockClient_DescribeKey_Call struct {
	*mock.Call
}

// DescribeKey is a helper method to define mock.On call
//   - ctx context.Context
//   - params *servicekms.DescribeKeyInput
//   - optFns ...func(*servicekms.Options)
func (_e *MockClient_Expecter) DescribeKey(ctx interface{}, params interface{}, optFns ...interface{}) *MockClient_DescribeKey_Call {
	return &MockClient_DescribeKey_Call{Call: _e.mock.On("DescribeKey",
		append([]interface{}{ctx, params}, optFns...)...)}
}

func (_c *MockClient_DescribeKey_Call) Run(run func(ctx context.Context, params *servicekms.DescribeKeyInput, optFns ...func(*servicekms.Options))) *MockClient_DescribeKey_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]func(*servicekms.Options), len(args)-2)
		for i, a := range args[2:] {
			if a != nil {
				variadicArgs[i] = a.(func(*servicekms.Options))
			}
		}
		run(args[0].(context.Context), args[1].(*servicekms.DescribeKeyInput), variadicArgs...)
	})
	return _c
}

func (_c *MockClient_DescribeKey_Call) Return(_a0 *servicekms.DescribeKeyOutput, _a1 error) *MockClient_DescribeKey_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

// GetKeyRotationStatus provides a mock function with given fields: ctx, params, optFns
func (_m *MockClient) GetKeyRotationStatus(ctx context.Context, params *servicekms.GetKeyRotationStatusInput, optFns ...func(*servicekms.Options)) (*servicekms.GetKeyRotationStatusOutput, error) {
	_va := make([]interface{}, len(optFns))
	for _i := range optFns {
		_va[_i] = optFns[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx, params)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	var r0 *servicekms.GetKeyRotationStatusOutput
	if rf, ok := ret.Get(0).(func(context.Context, *servicekms.GetKeyRotationStatusInput, ...func(*servicekms.Options)) *servicekms.GetKeyRotationStatusOutput); ok {
		r0 = rf(ctx, params, optFns...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*servicekms.GetKeyRotationStatusOutput)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *servicekms.GetKeyRotationStatusInput, ...func(*servicekms.Options)) error); ok {
		r1 = rf(ctx, params, optFns...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockClient_GetKeyRotationStatus_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetKeyRotationStatus'
type MockClient_GetKeyRotationStatus_Call struct {
	*mock.Call
}

// GetKeyRotationStatus is a helper method to define mock.On call
//   - ctx context.Context
//   - params *servicekms.GetKeyRotationStatusInput
//   - optFns ...func(*servicekms.Options)
func (_e *MockClient_Expecter) GetKeyRotationStatus(ctx interface{}, params interface{}, optFns ...interface{}) *MockClient_GetKeyRotationStatus_Call {
	return &MockClient_GetKeyRotationStatus_Call{Call: _e.mock.On("GetKeyRotationStatus",
		append([]interface{}{ctx, params}, optFns...)...)}
}

func (_c *MockClient_GetKeyRotationStatus_Call) Run(run func(ctx context.Context, params *servicekms.GetKeyRotationStatusInput, optFns ...func(*servicekms.Options))) *MockClient_GetKeyRotationStatus_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]func(*servicekms.Options), len(args)-2)
		for i, a := range args[2:] {
			if a != nil {
				variadicArgs[i] = a.(func(*servicekms.Options))
			}
		}
		run(args[0].(context.Context), args[1].(*servicekms.GetKeyRotationStatusInput), variadicArgs...)
	})
	return _c
}

func (_c *MockClient_GetKeyRotationStatus_Call) Return(_a0 *servicekms.GetKeyRotationStatusOutput, _a1 error) *MockClient_GetKeyRotationStatus_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

// ListKeys provides a mock function with given fields: ctx, params, optFns
func (_m *MockClient) ListKeys(ctx context.Context, params *servicekms.ListKeysInput, optFns ...func(*servicekms.Options)) (*servicekms.ListKeysOutput, error) {
	_va := make([]interface{}, len(optFns))
	for _i := range optFns {
		_va[_i] = optFns[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx, params)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	var r0 *servicekms.ListKeysOutput
	if rf, ok := ret.Get(0).(func(context.Context, *servicekms.ListKeysInput, ...func(*servicekms.Options)) *servicekms.ListKeysOutput); ok {
		r0 = rf(ctx, params, optFns...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*servicekms.ListKeysOutput)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, *servicekms.ListKeysInput, ...func(*servicekms.Options)) error); ok {
		r1 = rf(ctx, params, optFns...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockClient_ListKeys_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'ListKeys'
type MockClient_ListKeys_Call struct {
	*mock.Call
}

// ListKeys is a helper method to define mock.On call
//   - ctx context.Context
//   - params *servicekms.ListKeysInput
//   - optFns ...func(*servicekms.Options)
func (_e *MockClient_Expecter) ListKeys(ctx interface{}, params interface{}, optFns ...interface{}) *MockClient_ListKeys_Call {
	return &MockClient_ListKeys_Call{Call: _e.mock.On("ListKeys",
		append([]interface{}{ctx, params}, optFns...)...)}
}

func (_c *MockClient_ListKeys_Call) Run(run func(ctx context.Context, params *servicekms.ListKeysInput, optFns ...func(*servicekms.Options))) *MockClient_ListKeys_Call {
	_c.Call.Run(func(args mock.Arguments) {
		variadicArgs := make([]func(*servicekms.Options), len(args)-2)
		for i, a := range args[2:] {
			if a != nil {
				variadicArgs[i] = a.(func(*servicekms.Options))
			}
		}
		run(args[0].(context.Context), args[1].(*servicekms.ListKeysInput), variadicArgs...)
	})
	return _c
}

func (_c *MockClient_ListKeys_Call) Return(_a0 *servicekms.ListKeysOutput, _a1 error) *MockClient_ListKeys_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

type mockConstructorTestingTNewMockClient interface {
	mock.TestingT
	Cleanup(func())
}

// NewMockClient creates a new instance of MockClient. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewMockClient(t mockConstructorTestingTNewMockClient) *MockClient {
	mock := &MockClient{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
