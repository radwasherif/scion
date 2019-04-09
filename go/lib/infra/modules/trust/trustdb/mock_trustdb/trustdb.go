// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb (interfaces: TrustDB)

// Package mock_trustdb is a generated GoMock package.
package mock_trustdb

import (
	context "context"
	sql "database/sql"
	gomock "github.com/golang/mock/gomock"
	addr "github.com/scionproto/scion/go/lib/addr"
	trustdb "github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
	cert "github.com/scionproto/scion/go/lib/scrypto/cert"
	trc "github.com/scionproto/scion/go/lib/scrypto/trc"
	reflect "reflect"
)

// MockTrustDB is a mock of TrustDB interface
type MockTrustDB struct {
	ctrl     *gomock.Controller
	recorder *MockTrustDBMockRecorder
}

// MockTrustDBMockRecorder is the mock recorder for MockTrustDB
type MockTrustDBMockRecorder struct {
	mock *MockTrustDB
}

// NewMockTrustDB creates a new mock instance
func NewMockTrustDB(ctrl *gomock.Controller) *MockTrustDB {
	mock := &MockTrustDB{ctrl: ctrl}
	mock.recorder = &MockTrustDBMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockTrustDB) EXPECT() *MockTrustDBMockRecorder {
	return m.recorder
}

// BeginTransaction mocks base method
func (m *MockTrustDB) BeginTransaction(arg0 context.Context, arg1 *sql.TxOptions) (trustdb.Transaction, error) {
	ret := m.ctrl.Call(m, "BeginTransaction", arg0, arg1)
	ret0, _ := ret[0].(trustdb.Transaction)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// BeginTransaction indicates an expected call of BeginTransaction
func (mr *MockTrustDBMockRecorder) BeginTransaction(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BeginTransaction", reflect.TypeOf((*MockTrustDB)(nil).BeginTransaction), arg0, arg1)
}

// Close mocks base method
func (m *MockTrustDB) Close() error {
	ret := m.ctrl.Call(m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

// Close indicates an expected call of Close
func (mr *MockTrustDBMockRecorder) Close() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockTrustDB)(nil).Close))
}

// GetAllChains mocks base method
func (m *MockTrustDB) GetAllChains(arg0 context.Context) (<-chan trustdb.ChainOrErr, error) {
	ret := m.ctrl.Call(m, "GetAllChains", arg0)
	ret0, _ := ret[0].(<-chan trustdb.ChainOrErr)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAllChains indicates an expected call of GetAllChains
func (mr *MockTrustDBMockRecorder) GetAllChains(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAllChains", reflect.TypeOf((*MockTrustDB)(nil).GetAllChains), arg0)
}

// GetAllCustKeys mocks base method
func (m *MockTrustDB) GetAllCustKeys(arg0 context.Context) (<-chan trustdb.CustKeyOrErr, error) {
	ret := m.ctrl.Call(m, "GetAllCustKeys", arg0)
	ret0, _ := ret[0].(<-chan trustdb.CustKeyOrErr)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAllCustKeys indicates an expected call of GetAllCustKeys
func (mr *MockTrustDBMockRecorder) GetAllCustKeys(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAllCustKeys", reflect.TypeOf((*MockTrustDB)(nil).GetAllCustKeys), arg0)
}

// GetAllIssCerts mocks base method
func (m *MockTrustDB) GetAllIssCerts(arg0 context.Context) (<-chan trustdb.CertOrErr, error) {
	ret := m.ctrl.Call(m, "GetAllIssCerts", arg0)
	ret0, _ := ret[0].(<-chan trustdb.CertOrErr)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAllIssCerts indicates an expected call of GetAllIssCerts
func (mr *MockTrustDBMockRecorder) GetAllIssCerts(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAllIssCerts", reflect.TypeOf((*MockTrustDB)(nil).GetAllIssCerts), arg0)
}

// GetAllTRCs mocks base method
func (m *MockTrustDB) GetAllTRCs(arg0 context.Context) (<-chan trustdb.TrcOrErr, error) {
	ret := m.ctrl.Call(m, "GetAllTRCs", arg0)
	ret0, _ := ret[0].(<-chan trustdb.TrcOrErr)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetAllTRCs indicates an expected call of GetAllTRCs
func (mr *MockTrustDBMockRecorder) GetAllTRCs(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetAllTRCs", reflect.TypeOf((*MockTrustDB)(nil).GetAllTRCs), arg0)
}

// GetChainMaxVersion mocks base method
func (m *MockTrustDB) GetChainMaxVersion(arg0 context.Context, arg1 addr.IA) (*cert.Chain, error) {
	ret := m.ctrl.Call(m, "GetChainMaxVersion", arg0, arg1)
	ret0, _ := ret[0].(*cert.Chain)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetChainMaxVersion indicates an expected call of GetChainMaxVersion
func (mr *MockTrustDBMockRecorder) GetChainMaxVersion(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetChainMaxVersion", reflect.TypeOf((*MockTrustDB)(nil).GetChainMaxVersion), arg0, arg1)
}

// GetChainVersion mocks base method
func (m *MockTrustDB) GetChainVersion(arg0 context.Context, arg1 addr.IA, arg2 uint64) (*cert.Chain, error) {
	ret := m.ctrl.Call(m, "GetChainVersion", arg0, arg1, arg2)
	ret0, _ := ret[0].(*cert.Chain)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetChainVersion indicates an expected call of GetChainVersion
func (mr *MockTrustDBMockRecorder) GetChainVersion(arg0, arg1, arg2 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetChainVersion", reflect.TypeOf((*MockTrustDB)(nil).GetChainVersion), arg0, arg1, arg2)
}

// GetCustKey mocks base method
func (m *MockTrustDB) GetCustKey(arg0 context.Context, arg1 addr.IA) (*trustdb.CustKey, error) {
	ret := m.ctrl.Call(m, "GetCustKey", arg0, arg1)
	ret0, _ := ret[0].(*trustdb.CustKey)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetCustKey indicates an expected call of GetCustKey
func (mr *MockTrustDBMockRecorder) GetCustKey(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetCustKey", reflect.TypeOf((*MockTrustDB)(nil).GetCustKey), arg0, arg1)
}

// GetIssCertMaxVersion mocks base method
func (m *MockTrustDB) GetIssCertMaxVersion(arg0 context.Context, arg1 addr.IA) (*cert.Certificate, error) {
	ret := m.ctrl.Call(m, "GetIssCertMaxVersion", arg0, arg1)
	ret0, _ := ret[0].(*cert.Certificate)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetIssCertMaxVersion indicates an expected call of GetIssCertMaxVersion
func (mr *MockTrustDBMockRecorder) GetIssCertMaxVersion(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetIssCertMaxVersion", reflect.TypeOf((*MockTrustDB)(nil).GetIssCertMaxVersion), arg0, arg1)
}

// GetIssCertVersion mocks base method
func (m *MockTrustDB) GetIssCertVersion(arg0 context.Context, arg1 addr.IA, arg2 uint64) (*cert.Certificate, error) {
	ret := m.ctrl.Call(m, "GetIssCertVersion", arg0, arg1, arg2)
	ret0, _ := ret[0].(*cert.Certificate)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetIssCertVersion indicates an expected call of GetIssCertVersion
func (mr *MockTrustDBMockRecorder) GetIssCertVersion(arg0, arg1, arg2 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetIssCertVersion", reflect.TypeOf((*MockTrustDB)(nil).GetIssCertVersion), arg0, arg1, arg2)
}

// GetTRCMaxVersion mocks base method
func (m *MockTrustDB) GetTRCMaxVersion(arg0 context.Context, arg1 addr.ISD) (*trc.TRC, error) {
	ret := m.ctrl.Call(m, "GetTRCMaxVersion", arg0, arg1)
	ret0, _ := ret[0].(*trc.TRC)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetTRCMaxVersion indicates an expected call of GetTRCMaxVersion
func (mr *MockTrustDBMockRecorder) GetTRCMaxVersion(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTRCMaxVersion", reflect.TypeOf((*MockTrustDB)(nil).GetTRCMaxVersion), arg0, arg1)
}

// GetTRCVersion mocks base method
func (m *MockTrustDB) GetTRCVersion(arg0 context.Context, arg1 addr.ISD, arg2 uint64) (*trc.TRC, error) {
	ret := m.ctrl.Call(m, "GetTRCVersion", arg0, arg1, arg2)
	ret0, _ := ret[0].(*trc.TRC)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetTRCVersion indicates an expected call of GetTRCVersion
func (mr *MockTrustDBMockRecorder) GetTRCVersion(arg0, arg1, arg2 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetTRCVersion", reflect.TypeOf((*MockTrustDB)(nil).GetTRCVersion), arg0, arg1, arg2)
}

// InsertChain mocks base method
func (m *MockTrustDB) InsertChain(arg0 context.Context, arg1 *cert.Chain) (int64, error) {
	ret := m.ctrl.Call(m, "InsertChain", arg0, arg1)
	ret0, _ := ret[0].(int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// InsertChain indicates an expected call of InsertChain
func (mr *MockTrustDBMockRecorder) InsertChain(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InsertChain", reflect.TypeOf((*MockTrustDB)(nil).InsertChain), arg0, arg1)
}

// InsertCustKey mocks base method
func (m *MockTrustDB) InsertCustKey(arg0 context.Context, arg1 *trustdb.CustKey, arg2 uint64) error {
	ret := m.ctrl.Call(m, "InsertCustKey", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// InsertCustKey indicates an expected call of InsertCustKey
func (mr *MockTrustDBMockRecorder) InsertCustKey(arg0, arg1, arg2 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InsertCustKey", reflect.TypeOf((*MockTrustDB)(nil).InsertCustKey), arg0, arg1, arg2)
}

// InsertIssCert mocks base method
func (m *MockTrustDB) InsertIssCert(arg0 context.Context, arg1 *cert.Certificate) (int64, error) {
	ret := m.ctrl.Call(m, "InsertIssCert", arg0, arg1)
	ret0, _ := ret[0].(int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// InsertIssCert indicates an expected call of InsertIssCert
func (mr *MockTrustDBMockRecorder) InsertIssCert(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InsertIssCert", reflect.TypeOf((*MockTrustDB)(nil).InsertIssCert), arg0, arg1)
}

// InsertTRC mocks base method
func (m *MockTrustDB) InsertTRC(arg0 context.Context, arg1 *trc.TRC) (int64, error) {
	ret := m.ctrl.Call(m, "InsertTRC", arg0, arg1)
	ret0, _ := ret[0].(int64)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// InsertTRC indicates an expected call of InsertTRC
func (mr *MockTrustDBMockRecorder) InsertTRC(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InsertTRC", reflect.TypeOf((*MockTrustDB)(nil).InsertTRC), arg0, arg1)
}

// SetMaxIdleConns mocks base method
func (m *MockTrustDB) SetMaxIdleConns(arg0 int) {
	m.ctrl.Call(m, "SetMaxIdleConns", arg0)
}

// SetMaxIdleConns indicates an expected call of SetMaxIdleConns
func (mr *MockTrustDBMockRecorder) SetMaxIdleConns(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetMaxIdleConns", reflect.TypeOf((*MockTrustDB)(nil).SetMaxIdleConns), arg0)
}

// SetMaxOpenConns mocks base method
func (m *MockTrustDB) SetMaxOpenConns(arg0 int) {
	m.ctrl.Call(m, "SetMaxOpenConns", arg0)
}

// SetMaxOpenConns indicates an expected call of SetMaxOpenConns
func (mr *MockTrustDBMockRecorder) SetMaxOpenConns(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetMaxOpenConns", reflect.TypeOf((*MockTrustDB)(nil).SetMaxOpenConns), arg0)
}
