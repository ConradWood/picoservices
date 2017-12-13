// Code generated by protoc-gen-go.
// source: proto/registrar.proto
// DO NOT EDIT!

/*
Package registrar is a generated protocol buffer package.

It is generated from these files:
	proto/registrar.proto

It has these top-level messages:
	ServiceDescription
	ServiceAddress
	ServiceLocation
	GetRequest
	GetResponse
	ShutdownRequest
	ListResponse
	EmptyResponse
	ListRequest
	DeregisterRequest
	GetTargetRequest
*/
package registrar

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import _ "google.golang.org/genproto/googleapis/api/annotations"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type Apitype int32

const (
	Apitype_status Apitype = 0
	Apitype_grpc   Apitype = 1
	Apitype_json   Apitype = 2
	Apitype_html   Apitype = 3
	Apitype_tcp    Apitype = 4
)

var Apitype_name = map[int32]string{
	0: "status",
	1: "grpc",
	2: "json",
	3: "html",
	4: "tcp",
}
var Apitype_value = map[string]int32{
	"status": 0,
	"grpc":   1,
	"json":   2,
	"html":   3,
	"tcp":    4,
}

func (x Apitype) String() string {
	return proto.EnumName(Apitype_name, int32(x))
}
func (Apitype) EnumDescriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

type ServiceDescription struct {
	Name     string `protobuf:"bytes,1,opt,name=Name,json=name" json:"Name,omitempty"`
	Gurupath string `protobuf:"bytes,2,opt,name=Gurupath,json=gurupath" json:"Gurupath,omitempty"`
}

func (m *ServiceDescription) Reset()                    { *m = ServiceDescription{} }
func (m *ServiceDescription) String() string            { return proto.CompactTextString(m) }
func (*ServiceDescription) ProtoMessage()               {}
func (*ServiceDescription) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *ServiceDescription) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *ServiceDescription) GetGurupath() string {
	if m != nil {
		return m.Gurupath
	}
	return ""
}

// on a given port, we can have multiple apis
type ServiceAddress struct {
	Host    string    `protobuf:"bytes,1,opt,name=Host,json=host" json:"Host,omitempty"`
	Port    int32     `protobuf:"varint,2,opt,name=Port,json=port" json:"Port,omitempty"`
	ApiType []Apitype `protobuf:"varint,3,rep,packed,name=ApiType,json=apiType,enum=registrar.Apitype" json:"ApiType,omitempty"`
}

func (m *ServiceAddress) Reset()                    { *m = ServiceAddress{} }
func (m *ServiceAddress) String() string            { return proto.CompactTextString(m) }
func (*ServiceAddress) ProtoMessage()               {}
func (*ServiceAddress) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *ServiceAddress) GetHost() string {
	if m != nil {
		return m.Host
	}
	return ""
}

func (m *ServiceAddress) GetPort() int32 {
	if m != nil {
		return m.Port
	}
	return 0
}

func (m *ServiceAddress) GetApiType() []Apitype {
	if m != nil {
		return m.ApiType
	}
	return nil
}

type ServiceLocation struct {
	Service *ServiceDescription `protobuf:"bytes,1,opt,name=Service,json=service" json:"Service,omitempty"`
	Address []*ServiceAddress   `protobuf:"bytes,2,rep,name=Address,json=address" json:"Address,omitempty"`
}

func (m *ServiceLocation) Reset()                    { *m = ServiceLocation{} }
func (m *ServiceLocation) String() string            { return proto.CompactTextString(m) }
func (*ServiceLocation) ProtoMessage()               {}
func (*ServiceLocation) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *ServiceLocation) GetService() *ServiceDescription {
	if m != nil {
		return m.Service
	}
	return nil
}

func (m *ServiceLocation) GetAddress() []*ServiceAddress {
	if m != nil {
		return m.Address
	}
	return nil
}

type GetRequest struct {
	Service *ServiceDescription `protobuf:"bytes,1,opt,name=Service,json=service" json:"Service,omitempty"`
}

func (m *GetRequest) Reset()                    { *m = GetRequest{} }
func (m *GetRequest) String() string            { return proto.CompactTextString(m) }
func (*GetRequest) ProtoMessage()               {}
func (*GetRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *GetRequest) GetService() *ServiceDescription {
	if m != nil {
		return m.Service
	}
	return nil
}

type GetResponse struct {
	Service   *ServiceDescription `protobuf:"bytes,1,opt,name=Service,json=service" json:"Service,omitempty"`
	Location  *ServiceLocation    `protobuf:"bytes,2,opt,name=Location,json=location" json:"Location,omitempty"`
	ServiceID string              `protobuf:"bytes,3,opt,name=ServiceID,json=serviceID" json:"ServiceID,omitempty"`
}

func (m *GetResponse) Reset()                    { *m = GetResponse{} }
func (m *GetResponse) String() string            { return proto.CompactTextString(m) }
func (*GetResponse) ProtoMessage()               {}
func (*GetResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

func (m *GetResponse) GetService() *ServiceDescription {
	if m != nil {
		return m.Service
	}
	return nil
}

func (m *GetResponse) GetLocation() *ServiceLocation {
	if m != nil {
		return m.Location
	}
	return nil
}

func (m *GetResponse) GetServiceID() string {
	if m != nil {
		return m.ServiceID
	}
	return ""
}

type ShutdownRequest struct {
	ServiceName string `protobuf:"bytes,1,opt,name=ServiceName,json=serviceName" json:"ServiceName,omitempty"`
}

func (m *ShutdownRequest) Reset()                    { *m = ShutdownRequest{} }
func (m *ShutdownRequest) String() string            { return proto.CompactTextString(m) }
func (*ShutdownRequest) ProtoMessage()               {}
func (*ShutdownRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{5} }

func (m *ShutdownRequest) GetServiceName() string {
	if m != nil {
		return m.ServiceName
	}
	return ""
}

type ListResponse struct {
	Service []*GetResponse `protobuf:"bytes,3,rep,name=Service,json=service" json:"Service,omitempty"`
}

func (m *ListResponse) Reset()                    { *m = ListResponse{} }
func (m *ListResponse) String() string            { return proto.CompactTextString(m) }
func (*ListResponse) ProtoMessage()               {}
func (*ListResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{6} }

func (m *ListResponse) GetService() []*GetResponse {
	if m != nil {
		return m.Service
	}
	return nil
}

type EmptyResponse struct {
}

func (m *EmptyResponse) Reset()                    { *m = EmptyResponse{} }
func (m *EmptyResponse) String() string            { return proto.CompactTextString(m) }
func (*EmptyResponse) ProtoMessage()               {}
func (*EmptyResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{7} }

type ListRequest struct {
	// optional - if set filter by Name
	Name string `protobuf:"bytes,1,opt,name=Name,json=name" json:"Name,omitempty"`
}

func (m *ListRequest) Reset()                    { *m = ListRequest{} }
func (m *ListRequest) String() string            { return proto.CompactTextString(m) }
func (*ListRequest) ProtoMessage()               {}
func (*ListRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{8} }

func (m *ListRequest) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

type DeregisterRequest struct {
	ServiceID string `protobuf:"bytes,1,opt,name=ServiceID,json=serviceID" json:"ServiceID,omitempty"`
}

func (m *DeregisterRequest) Reset()                    { *m = DeregisterRequest{} }
func (m *DeregisterRequest) String() string            { return proto.CompactTextString(m) }
func (*DeregisterRequest) ProtoMessage()               {}
func (*DeregisterRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{9} }

func (m *DeregisterRequest) GetServiceID() string {
	if m != nil {
		return m.ServiceID
	}
	return ""
}

type GetTargetRequest struct {
	Gurupath string  `protobuf:"bytes,1,opt,name=Gurupath,json=gurupath" json:"Gurupath,omitempty"`
	ApiType  Apitype `protobuf:"varint,3,opt,name=ApiType,json=apiType,enum=registrar.Apitype" json:"ApiType,omitempty"`
}

func (m *GetTargetRequest) Reset()                    { *m = GetTargetRequest{} }
func (m *GetTargetRequest) String() string            { return proto.CompactTextString(m) }
func (*GetTargetRequest) ProtoMessage()               {}
func (*GetTargetRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{10} }

func (m *GetTargetRequest) GetGurupath() string {
	if m != nil {
		return m.Gurupath
	}
	return ""
}

func (m *GetTargetRequest) GetApiType() Apitype {
	if m != nil {
		return m.ApiType
	}
	return Apitype_status
}

func init() {
	proto.RegisterType((*ServiceDescription)(nil), "registrar.ServiceDescription")
	proto.RegisterType((*ServiceAddress)(nil), "registrar.ServiceAddress")
	proto.RegisterType((*ServiceLocation)(nil), "registrar.ServiceLocation")
	proto.RegisterType((*GetRequest)(nil), "registrar.GetRequest")
	proto.RegisterType((*GetResponse)(nil), "registrar.GetResponse")
	proto.RegisterType((*ShutdownRequest)(nil), "registrar.ShutdownRequest")
	proto.RegisterType((*ListResponse)(nil), "registrar.ListResponse")
	proto.RegisterType((*EmptyResponse)(nil), "registrar.EmptyResponse")
	proto.RegisterType((*ListRequest)(nil), "registrar.ListRequest")
	proto.RegisterType((*DeregisterRequest)(nil), "registrar.DeregisterRequest")
	proto.RegisterType((*GetTargetRequest)(nil), "registrar.GetTargetRequest")
	proto.RegisterEnum("registrar.Apitype", Apitype_name, Apitype_value)
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for Registry service

type RegistryClient interface {
	DeregisterService(ctx context.Context, in *DeregisterRequest, opts ...grpc.CallOption) (*EmptyResponse, error)
	RegisterService(ctx context.Context, in *ServiceLocation, opts ...grpc.CallOption) (*GetResponse, error)
	GetServiceAddress(ctx context.Context, in *GetRequest, opts ...grpc.CallOption) (*GetResponse, error)
	ListServices(ctx context.Context, in *ListRequest, opts ...grpc.CallOption) (*ListResponse, error)
	ShutdownService(ctx context.Context, in *ShutdownRequest, opts ...grpc.CallOption) (*EmptyResponse, error)
	GetTarget(ctx context.Context, in *GetTargetRequest, opts ...grpc.CallOption) (*ListResponse, error)
}

type registryClient struct {
	cc *grpc.ClientConn
}

func NewRegistryClient(cc *grpc.ClientConn) RegistryClient {
	return &registryClient{cc}
}

func (c *registryClient) DeregisterService(ctx context.Context, in *DeregisterRequest, opts ...grpc.CallOption) (*EmptyResponse, error) {
	out := new(EmptyResponse)
	err := grpc.Invoke(ctx, "/registrar.Registry/DeregisterService", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registryClient) RegisterService(ctx context.Context, in *ServiceLocation, opts ...grpc.CallOption) (*GetResponse, error) {
	out := new(GetResponse)
	err := grpc.Invoke(ctx, "/registrar.Registry/RegisterService", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registryClient) GetServiceAddress(ctx context.Context, in *GetRequest, opts ...grpc.CallOption) (*GetResponse, error) {
	out := new(GetResponse)
	err := grpc.Invoke(ctx, "/registrar.Registry/GetServiceAddress", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registryClient) ListServices(ctx context.Context, in *ListRequest, opts ...grpc.CallOption) (*ListResponse, error) {
	out := new(ListResponse)
	err := grpc.Invoke(ctx, "/registrar.Registry/ListServices", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registryClient) ShutdownService(ctx context.Context, in *ShutdownRequest, opts ...grpc.CallOption) (*EmptyResponse, error) {
	out := new(EmptyResponse)
	err := grpc.Invoke(ctx, "/registrar.Registry/ShutdownService", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registryClient) GetTarget(ctx context.Context, in *GetTargetRequest, opts ...grpc.CallOption) (*ListResponse, error) {
	out := new(ListResponse)
	err := grpc.Invoke(ctx, "/registrar.Registry/GetTarget", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for Registry service

type RegistryServer interface {
	DeregisterService(context.Context, *DeregisterRequest) (*EmptyResponse, error)
	RegisterService(context.Context, *ServiceLocation) (*GetResponse, error)
	GetServiceAddress(context.Context, *GetRequest) (*GetResponse, error)
	ListServices(context.Context, *ListRequest) (*ListResponse, error)
	ShutdownService(context.Context, *ShutdownRequest) (*EmptyResponse, error)
	GetTarget(context.Context, *GetTargetRequest) (*ListResponse, error)
}

func RegisterRegistryServer(s *grpc.Server, srv RegistryServer) {
	s.RegisterService(&_Registry_serviceDesc, srv)
}

func _Registry_DeregisterService_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeregisterRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistryServer).DeregisterService(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/registrar.Registry/DeregisterService",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistryServer).DeregisterService(ctx, req.(*DeregisterRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Registry_RegisterService_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ServiceLocation)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistryServer).RegisterService(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/registrar.Registry/RegisterService",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistryServer).RegisterService(ctx, req.(*ServiceLocation))
	}
	return interceptor(ctx, in, info, handler)
}

func _Registry_GetServiceAddress_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistryServer).GetServiceAddress(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/registrar.Registry/GetServiceAddress",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistryServer).GetServiceAddress(ctx, req.(*GetRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Registry_ListServices_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistryServer).ListServices(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/registrar.Registry/ListServices",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistryServer).ListServices(ctx, req.(*ListRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Registry_ShutdownService_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ShutdownRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistryServer).ShutdownService(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/registrar.Registry/ShutdownService",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistryServer).ShutdownService(ctx, req.(*ShutdownRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Registry_GetTarget_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetTargetRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistryServer).GetTarget(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/registrar.Registry/GetTarget",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistryServer).GetTarget(ctx, req.(*GetTargetRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Registry_serviceDesc = grpc.ServiceDesc{
	ServiceName: "registrar.Registry",
	HandlerType: (*RegistryServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "DeregisterService",
			Handler:    _Registry_DeregisterService_Handler,
		},
		{
			MethodName: "RegisterService",
			Handler:    _Registry_RegisterService_Handler,
		},
		{
			MethodName: "GetServiceAddress",
			Handler:    _Registry_GetServiceAddress_Handler,
		},
		{
			MethodName: "ListServices",
			Handler:    _Registry_ListServices_Handler,
		},
		{
			MethodName: "ShutdownService",
			Handler:    _Registry_ShutdownService_Handler,
		},
		{
			MethodName: "GetTarget",
			Handler:    _Registry_GetTarget_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "proto/registrar.proto",
}

func init() { proto.RegisterFile("proto/registrar.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 558 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0x9c, 0x54, 0x51, 0x6f, 0xd3, 0x3c,
	0x14, 0xfd, 0xd2, 0xf4, 0x5b, 0xd2, 0x1b, 0x58, 0x33, 0x4b, 0x83, 0x10, 0x8a, 0x54, 0xf2, 0x54,
	0x21, 0xb4, 0x42, 0x2b, 0xc1, 0x0b, 0x12, 0x14, 0xb5, 0x2a, 0x88, 0x09, 0xa1, 0x6c, 0x8f, 0xbc,
	0x98, 0xd6, 0xa4, 0x41, 0x6d, 0x6c, 0x6c, 0x17, 0xd4, 0x27, 0xfe, 0x08, 0xff, 0x81, 0xbf, 0x88,
	0xe2, 0x38, 0x8b, 0xd3, 0xac, 0x43, 0xda, 0x9b, 0x73, 0x7c, 0x7c, 0xee, 0x3d, 0xf7, 0x9e, 0x16,
	0x4e, 0x19, 0xa7, 0x92, 0x0e, 0x39, 0x49, 0x52, 0x21, 0x39, 0xe6, 0x67, 0xea, 0x1b, 0x75, 0xae,
	0x80, 0xb0, 0x97, 0x50, 0x9a, 0xac, 0xc9, 0x10, 0xb3, 0x74, 0x88, 0xb3, 0x8c, 0x4a, 0x2c, 0x53,
	0x9a, 0x89, 0x82, 0x18, 0x4d, 0x01, 0x5d, 0x10, 0xfe, 0x23, 0x5d, 0x90, 0x29, 0x11, 0x0b, 0x9e,
	0xb2, 0xfc, 0x12, 0x21, 0x68, 0x7f, 0xc4, 0x1b, 0x12, 0x58, 0x7d, 0x6b, 0xd0, 0x89, 0xdb, 0x19,
	0xde, 0x10, 0x14, 0x82, 0x3b, 0xdf, 0xf2, 0x2d, 0xc3, 0x72, 0x15, 0xb4, 0x14, 0xee, 0x26, 0xfa,
	0x3b, 0xfa, 0x0a, 0xc7, 0x5a, 0x65, 0xb2, 0x5c, 0x72, 0x22, 0x44, 0xae, 0xf0, 0x8e, 0x0a, 0x59,
	0x2a, 0xac, 0xa8, 0x90, 0x39, 0xf6, 0x89, 0x72, 0xa9, 0x5e, 0xff, 0x1f, 0xb7, 0x19, 0xe5, 0x12,
	0x3d, 0x05, 0x67, 0xc2, 0xd2, 0xcb, 0x1d, 0x23, 0x81, 0xdd, 0xb7, 0x07, 0xc7, 0x23, 0x74, 0x56,
	0x79, 0x99, 0xb0, 0x54, 0xee, 0x18, 0x89, 0x1d, 0x5c, 0x50, 0xa2, 0x5f, 0xd0, 0xd5, 0x75, 0xce,
	0xe9, 0x42, 0xf9, 0x40, 0x2f, 0xc1, 0xd1, 0x90, 0xaa, 0xe5, 0x8d, 0x1e, 0x19, 0x02, 0x4d, 0x6b,
	0xb1, 0x23, 0x0a, 0x0c, 0x8d, 0xc1, 0xd1, 0xcd, 0x06, 0xad, 0xbe, 0x3d, 0xf0, 0x46, 0x0f, 0x9a,
	0x0f, 0x35, 0x21, 0x76, 0x70, 0x71, 0x88, 0x66, 0x00, 0x73, 0x22, 0x63, 0xf2, 0x7d, 0x4b, 0x84,
	0xbc, 0x75, 0xed, 0xe8, 0xb7, 0x05, 0x9e, 0xd2, 0x11, 0x8c, 0x66, 0x82, 0xdc, 0xde, 0xc4, 0x0b,
	0x70, 0xcb, 0x49, 0xa8, 0xb1, 0x7a, 0xa3, 0xb0, 0xf9, 0xb2, 0x64, 0xc4, 0xee, 0xba, 0x9c, 0x5a,
	0x0f, 0x3a, 0xfa, 0xf2, 0xfd, 0x34, 0xb0, 0xd5, 0x8e, 0x3a, 0xa2, 0x04, 0xa2, 0x31, 0x74, 0x2f,
	0x56, 0x5b, 0xb9, 0xa4, 0x3f, 0xb3, 0xd2, 0x6a, 0x1f, 0x3c, 0xfd, 0xc0, 0x08, 0x86, 0x27, 0x2a,
	0x28, 0x7a, 0x03, 0x77, 0xce, 0x53, 0x51, 0x79, 0x7a, 0x56, 0x79, 0xb2, 0xd5, 0x7c, 0xef, 0x19,
	0x9d, 0x19, 0xe6, 0xab, 0xa9, 0x74, 0xe1, 0xee, 0x6c, 0xc3, 0xe4, 0xae, 0xbc, 0x89, 0x1e, 0x83,
	0x57, 0x48, 0x16, 0x3d, 0x5c, 0x93, 0xca, 0xe8, 0x39, 0x9c, 0x4c, 0x49, 0xa1, 0x4b, 0x78, 0x49,
	0xac, 0xb9, 0xb3, 0xf6, 0xdd, 0x7d, 0x06, 0x7f, 0x4e, 0xe4, 0x25, 0xe6, 0x49, 0xb5, 0x49, 0x33,
	0xdc, 0x56, 0x3d, 0xdc, 0xf5, 0x88, 0x5a, 0xff, 0x88, 0xe8, 0x93, 0x57, 0x8a, 0x9d, 0x63, 0x08,
	0xe0, 0x48, 0x48, 0x2c, 0xb7, 0xc2, 0xff, 0x0f, 0xb9, 0xd0, 0x4e, 0x38, 0x5b, 0xf8, 0x56, 0x7e,
	0xfa, 0x26, 0x68, 0xe6, 0xb7, 0xf2, 0xd3, 0x4a, 0x6e, 0xd6, 0xbe, 0x8d, 0x1c, 0xb0, 0xe5, 0x82,
	0xf9, 0xed, 0xd1, 0x1f, 0x1b, 0xdc, 0xb8, 0x10, 0xdf, 0xa1, 0x0f, 0xa6, 0x37, 0x6d, 0x08, 0xf5,
	0x8c, 0xe2, 0x0d, 0xe7, 0x61, 0x60, 0xdc, 0xd6, 0x66, 0x89, 0x66, 0xd0, 0x8d, 0xf7, 0xa4, 0x6e,
	0x88, 0x4a, 0x78, 0x60, 0x59, 0xe8, 0x2d, 0x9c, 0xcc, 0x89, 0xdc, 0xfb, 0xb1, 0x9f, 0xee, 0x93,
	0x8b, 0x66, 0x0e, 0x69, 0xbc, 0x2e, 0x92, 0xa2, 0x45, 0x04, 0x32, 0x79, 0xc6, 0xbe, 0xc3, 0xfb,
	0x0d, 0x5c, 0x0b, 0xcc, 0xab, 0x7c, 0x5e, 0xeb, 0xa5, 0x9e, 0xdd, 0x1b, 0x86, 0x32, 0x81, 0xce,
	0x55, 0x14, 0xd0, 0xc3, 0x7a, 0xbb, 0xb5, 0x80, 0x1c, 0xec, 0xe5, 0xcb, 0x91, 0xfa, 0x1f, 0x1d,
	0xff, 0x0d, 0x00, 0x00, 0xff, 0xff, 0x34, 0xc7, 0xb6, 0xa1, 0x89, 0x05, 0x00, 0x00,
}
