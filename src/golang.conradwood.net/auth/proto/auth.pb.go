// Code generated by protoc-gen-go.
// source: proto/auth.proto
// DO NOT EDIT!

/*
Package auth is a generated protocol buffer package.

It is generated from these files:
	proto/auth.proto

It has these top-level messages:
	Group
	VerifyRequest
	VerifyResponse
	GetDetailRequest
	GetDetailResponse
	AuthenticatePasswordRequest
	VerifyPasswordResponse
	CreateUserRequest
	UserByEmailRequest
	AddToGroupRequest
	RemoveFromGroupRequest
	ListGroupRequest
	UserListResponse
	ListAllGroupsRequest
	GroupList
*/
package auth

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

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

type Group struct {
	GroupID string `protobuf:"bytes,1,opt,name=GroupID,json=groupID" json:"GroupID,omitempty"`
	Name    string `protobuf:"bytes,2,opt,name=Name,json=name" json:"Name,omitempty"`
}

func (m *Group) Reset()                    { *m = Group{} }
func (m *Group) String() string            { return proto.CompactTextString(m) }
func (*Group) ProtoMessage()               {}
func (*Group) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *Group) GetGroupID() string {
	if m != nil {
		return m.GroupID
	}
	return ""
}

func (m *Group) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

type VerifyRequest struct {
	Token string `protobuf:"bytes,1,opt,name=Token,json=token" json:"Token,omitempty"`
}

func (m *VerifyRequest) Reset()                    { *m = VerifyRequest{} }
func (m *VerifyRequest) String() string            { return proto.CompactTextString(m) }
func (*VerifyRequest) ProtoMessage()               {}
func (*VerifyRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *VerifyRequest) GetToken() string {
	if m != nil {
		return m.Token
	}
	return ""
}

type VerifyResponse struct {
	UserID string `protobuf:"bytes,1,opt,name=UserID,json=userID" json:"UserID,omitempty"`
}

func (m *VerifyResponse) Reset()                    { *m = VerifyResponse{} }
func (m *VerifyResponse) String() string            { return proto.CompactTextString(m) }
func (*VerifyResponse) ProtoMessage()               {}
func (*VerifyResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *VerifyResponse) GetUserID() string {
	if m != nil {
		return m.UserID
	}
	return ""
}

type GetDetailRequest struct {
	UserID string `protobuf:"bytes,1,opt,name=UserID,json=userID" json:"UserID,omitempty"`
}

func (m *GetDetailRequest) Reset()                    { *m = GetDetailRequest{} }
func (m *GetDetailRequest) String() string            { return proto.CompactTextString(m) }
func (*GetDetailRequest) ProtoMessage()               {}
func (*GetDetailRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{3} }

func (m *GetDetailRequest) GetUserID() string {
	if m != nil {
		return m.UserID
	}
	return ""
}

type GetDetailResponse struct {
	UserID    string `protobuf:"bytes,1,opt,name=UserID,json=userID" json:"UserID,omitempty"`
	Email     string `protobuf:"bytes,2,opt,name=Email,json=email" json:"Email,omitempty"`
	FirstName string `protobuf:"bytes,3,opt,name=FirstName,json=firstName" json:"FirstName,omitempty"`
	LastName  string `protobuf:"bytes,4,opt,name=LastName,json=lastName" json:"LastName,omitempty"`
	// only set when creating users
	Password string   `protobuf:"bytes,5,opt,name=Password,json=password" json:"Password,omitempty"`
	Groups   []*Group `protobuf:"bytes,6,rep,name=Groups,json=groups" json:"Groups,omitempty"`
}

func (m *GetDetailResponse) Reset()                    { *m = GetDetailResponse{} }
func (m *GetDetailResponse) String() string            { return proto.CompactTextString(m) }
func (*GetDetailResponse) ProtoMessage()               {}
func (*GetDetailResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{4} }

func (m *GetDetailResponse) GetUserID() string {
	if m != nil {
		return m.UserID
	}
	return ""
}

func (m *GetDetailResponse) GetEmail() string {
	if m != nil {
		return m.Email
	}
	return ""
}

func (m *GetDetailResponse) GetFirstName() string {
	if m != nil {
		return m.FirstName
	}
	return ""
}

func (m *GetDetailResponse) GetLastName() string {
	if m != nil {
		return m.LastName
	}
	return ""
}

func (m *GetDetailResponse) GetPassword() string {
	if m != nil {
		return m.Password
	}
	return ""
}

func (m *GetDetailResponse) GetGroups() []*Group {
	if m != nil {
		return m.Groups
	}
	return nil
}

type AuthenticatePasswordRequest struct {
	Email    string `protobuf:"bytes,1,opt,name=Email,json=email" json:"Email,omitempty"`
	Password string `protobuf:"bytes,2,opt,name=Password,json=password" json:"Password,omitempty"`
}

func (m *AuthenticatePasswordRequest) Reset()                    { *m = AuthenticatePasswordRequest{} }
func (m *AuthenticatePasswordRequest) String() string            { return proto.CompactTextString(m) }
func (*AuthenticatePasswordRequest) ProtoMessage()               {}
func (*AuthenticatePasswordRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{5} }

func (m *AuthenticatePasswordRequest) GetEmail() string {
	if m != nil {
		return m.Email
	}
	return ""
}

func (m *AuthenticatePasswordRequest) GetPassword() string {
	if m != nil {
		return m.Password
	}
	return ""
}

type VerifyPasswordResponse struct {
	User  *GetDetailResponse `protobuf:"bytes,1,opt,name=User,json=user" json:"User,omitempty"`
	Token string             `protobuf:"bytes,2,opt,name=Token,json=token" json:"Token,omitempty"`
}

func (m *VerifyPasswordResponse) Reset()                    { *m = VerifyPasswordResponse{} }
func (m *VerifyPasswordResponse) String() string            { return proto.CompactTextString(m) }
func (*VerifyPasswordResponse) ProtoMessage()               {}
func (*VerifyPasswordResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{6} }

func (m *VerifyPasswordResponse) GetUser() *GetDetailResponse {
	if m != nil {
		return m.User
	}
	return nil
}

func (m *VerifyPasswordResponse) GetToken() string {
	if m != nil {
		return m.Token
	}
	return ""
}

type CreateUserRequest struct {
	// e.g. cnw
	UserName string `protobuf:"bytes,1,opt,name=UserName,json=userName" json:"UserName,omitempty"`
	// e.g. junkmail@conradwood.net
	Email     string `protobuf:"bytes,2,opt,name=Email,json=email" json:"Email,omitempty"`
	FirstName string `protobuf:"bytes,3,opt,name=FirstName,json=firstName" json:"FirstName,omitempty"`
	LastName  string `protobuf:"bytes,4,opt,name=LastName,json=lastName" json:"LastName,omitempty"`
	Password  string `protobuf:"bytes,5,opt,name=Password,json=password" json:"Password,omitempty"`
}

func (m *CreateUserRequest) Reset()                    { *m = CreateUserRequest{} }
func (m *CreateUserRequest) String() string            { return proto.CompactTextString(m) }
func (*CreateUserRequest) ProtoMessage()               {}
func (*CreateUserRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{7} }

func (m *CreateUserRequest) GetUserName() string {
	if m != nil {
		return m.UserName
	}
	return ""
}

func (m *CreateUserRequest) GetEmail() string {
	if m != nil {
		return m.Email
	}
	return ""
}

func (m *CreateUserRequest) GetFirstName() string {
	if m != nil {
		return m.FirstName
	}
	return ""
}

func (m *CreateUserRequest) GetLastName() string {
	if m != nil {
		return m.LastName
	}
	return ""
}

func (m *CreateUserRequest) GetPassword() string {
	if m != nil {
		return m.Password
	}
	return ""
}

type UserByEmailRequest struct {
	Email string `protobuf:"bytes,1,opt,name=Email,json=email" json:"Email,omitempty"`
}

func (m *UserByEmailRequest) Reset()                    { *m = UserByEmailRequest{} }
func (m *UserByEmailRequest) String() string            { return proto.CompactTextString(m) }
func (*UserByEmailRequest) ProtoMessage()               {}
func (*UserByEmailRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{8} }

func (m *UserByEmailRequest) GetEmail() string {
	if m != nil {
		return m.Email
	}
	return ""
}

type AddToGroupRequest struct {
	UserID  string `protobuf:"bytes,1,opt,name=UserID,json=userID" json:"UserID,omitempty"`
	GroupID string `protobuf:"bytes,2,opt,name=GroupID,json=groupID" json:"GroupID,omitempty"`
}

func (m *AddToGroupRequest) Reset()                    { *m = AddToGroupRequest{} }
func (m *AddToGroupRequest) String() string            { return proto.CompactTextString(m) }
func (*AddToGroupRequest) ProtoMessage()               {}
func (*AddToGroupRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{9} }

func (m *AddToGroupRequest) GetUserID() string {
	if m != nil {
		return m.UserID
	}
	return ""
}

func (m *AddToGroupRequest) GetGroupID() string {
	if m != nil {
		return m.GroupID
	}
	return ""
}

type RemoveFromGroupRequest struct {
	UserID  string `protobuf:"bytes,1,opt,name=UserID,json=userID" json:"UserID,omitempty"`
	GroupID string `protobuf:"bytes,2,opt,name=GroupID,json=groupID" json:"GroupID,omitempty"`
}

func (m *RemoveFromGroupRequest) Reset()                    { *m = RemoveFromGroupRequest{} }
func (m *RemoveFromGroupRequest) String() string            { return proto.CompactTextString(m) }
func (*RemoveFromGroupRequest) ProtoMessage()               {}
func (*RemoveFromGroupRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{10} }

func (m *RemoveFromGroupRequest) GetUserID() string {
	if m != nil {
		return m.UserID
	}
	return ""
}

func (m *RemoveFromGroupRequest) GetGroupID() string {
	if m != nil {
		return m.GroupID
	}
	return ""
}

type ListGroupRequest struct {
	GroupID string `protobuf:"bytes,1,opt,name=GroupID,json=groupID" json:"GroupID,omitempty"`
}

func (m *ListGroupRequest) Reset()                    { *m = ListGroupRequest{} }
func (m *ListGroupRequest) String() string            { return proto.CompactTextString(m) }
func (*ListGroupRequest) ProtoMessage()               {}
func (*ListGroupRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{11} }

func (m *ListGroupRequest) GetGroupID() string {
	if m != nil {
		return m.GroupID
	}
	return ""
}

type UserListResponse struct {
	Users []*GetDetailResponse `protobuf:"bytes,1,rep,name=Users,json=users" json:"Users,omitempty"`
}

func (m *UserListResponse) Reset()                    { *m = UserListResponse{} }
func (m *UserListResponse) String() string            { return proto.CompactTextString(m) }
func (*UserListResponse) ProtoMessage()               {}
func (*UserListResponse) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{12} }

func (m *UserListResponse) GetUsers() []*GetDetailResponse {
	if m != nil {
		return m.Users
	}
	return nil
}

type ListAllGroupsRequest struct {
}

func (m *ListAllGroupsRequest) Reset()                    { *m = ListAllGroupsRequest{} }
func (m *ListAllGroupsRequest) String() string            { return proto.CompactTextString(m) }
func (*ListAllGroupsRequest) ProtoMessage()               {}
func (*ListAllGroupsRequest) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{13} }

type GroupList struct {
	Groups []*Group `protobuf:"bytes,1,rep,name=Groups,json=groups" json:"Groups,omitempty"`
}

func (m *GroupList) Reset()                    { *m = GroupList{} }
func (m *GroupList) String() string            { return proto.CompactTextString(m) }
func (*GroupList) ProtoMessage()               {}
func (*GroupList) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{14} }

func (m *GroupList) GetGroups() []*Group {
	if m != nil {
		return m.Groups
	}
	return nil
}

func init() {
	proto.RegisterType((*Group)(nil), "auth.Group")
	proto.RegisterType((*VerifyRequest)(nil), "auth.VerifyRequest")
	proto.RegisterType((*VerifyResponse)(nil), "auth.VerifyResponse")
	proto.RegisterType((*GetDetailRequest)(nil), "auth.GetDetailRequest")
	proto.RegisterType((*GetDetailResponse)(nil), "auth.GetDetailResponse")
	proto.RegisterType((*AuthenticatePasswordRequest)(nil), "auth.AuthenticatePasswordRequest")
	proto.RegisterType((*VerifyPasswordResponse)(nil), "auth.VerifyPasswordResponse")
	proto.RegisterType((*CreateUserRequest)(nil), "auth.CreateUserRequest")
	proto.RegisterType((*UserByEmailRequest)(nil), "auth.UserByEmailRequest")
	proto.RegisterType((*AddToGroupRequest)(nil), "auth.AddToGroupRequest")
	proto.RegisterType((*RemoveFromGroupRequest)(nil), "auth.RemoveFromGroupRequest")
	proto.RegisterType((*ListGroupRequest)(nil), "auth.ListGroupRequest")
	proto.RegisterType((*UserListResponse)(nil), "auth.UserListResponse")
	proto.RegisterType((*ListAllGroupsRequest)(nil), "auth.ListAllGroupsRequest")
	proto.RegisterType((*GroupList)(nil), "auth.GroupList")
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for AuthenticationService service

type AuthenticationServiceClient interface {
	// authenticate a user by username/password, return token
	AuthenticatePassword(ctx context.Context, in *AuthenticatePasswordRequest, opts ...grpc.CallOption) (*VerifyPasswordResponse, error)
	// verify a user by token
	VerifyUserToken(ctx context.Context, in *VerifyRequest, opts ...grpc.CallOption) (*VerifyResponse, error)
	GetUserByToken(ctx context.Context, in *VerifyRequest, opts ...grpc.CallOption) (*GetDetailResponse, error)
	GetUserDetail(ctx context.Context, in *GetDetailRequest, opts ...grpc.CallOption) (*GetDetailResponse, error)
	CreateUser(ctx context.Context, in *CreateUserRequest, opts ...grpc.CallOption) (*GetDetailResponse, error)
	// will look up a user by email. Email may be any golang parseable format,
	// e.g. "Conrad Wood" <cnw@gurusystems.com> is ok
	// if a given email returns more than one user, this will throw an error!
	GetUserByEmail(ctx context.Context, in *UserByEmailRequest, opts ...grpc.CallOption) (*GetDetailResponse, error)
	AddUserToGroup(ctx context.Context, in *AddToGroupRequest, opts ...grpc.CallOption) (*GetDetailResponse, error)
	RemoveUserFromGroup(ctx context.Context, in *RemoveFromGroupRequest, opts ...grpc.CallOption) (*GetDetailResponse, error)
	ListUsersInGroup(ctx context.Context, in *ListGroupRequest, opts ...grpc.CallOption) (*UserListResponse, error)
	ListGroups(ctx context.Context, in *ListAllGroupsRequest, opts ...grpc.CallOption) (*GroupList, error)
}

type authenticationServiceClient struct {
	cc *grpc.ClientConn
}

func NewAuthenticationServiceClient(cc *grpc.ClientConn) AuthenticationServiceClient {
	return &authenticationServiceClient{cc}
}

func (c *authenticationServiceClient) AuthenticatePassword(ctx context.Context, in *AuthenticatePasswordRequest, opts ...grpc.CallOption) (*VerifyPasswordResponse, error) {
	out := new(VerifyPasswordResponse)
	err := grpc.Invoke(ctx, "/auth.AuthenticationService/AuthenticatePassword", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authenticationServiceClient) VerifyUserToken(ctx context.Context, in *VerifyRequest, opts ...grpc.CallOption) (*VerifyResponse, error) {
	out := new(VerifyResponse)
	err := grpc.Invoke(ctx, "/auth.AuthenticationService/VerifyUserToken", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authenticationServiceClient) GetUserByToken(ctx context.Context, in *VerifyRequest, opts ...grpc.CallOption) (*GetDetailResponse, error) {
	out := new(GetDetailResponse)
	err := grpc.Invoke(ctx, "/auth.AuthenticationService/GetUserByToken", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authenticationServiceClient) GetUserDetail(ctx context.Context, in *GetDetailRequest, opts ...grpc.CallOption) (*GetDetailResponse, error) {
	out := new(GetDetailResponse)
	err := grpc.Invoke(ctx, "/auth.AuthenticationService/GetUserDetail", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authenticationServiceClient) CreateUser(ctx context.Context, in *CreateUserRequest, opts ...grpc.CallOption) (*GetDetailResponse, error) {
	out := new(GetDetailResponse)
	err := grpc.Invoke(ctx, "/auth.AuthenticationService/CreateUser", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authenticationServiceClient) GetUserByEmail(ctx context.Context, in *UserByEmailRequest, opts ...grpc.CallOption) (*GetDetailResponse, error) {
	out := new(GetDetailResponse)
	err := grpc.Invoke(ctx, "/auth.AuthenticationService/GetUserByEmail", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authenticationServiceClient) AddUserToGroup(ctx context.Context, in *AddToGroupRequest, opts ...grpc.CallOption) (*GetDetailResponse, error) {
	out := new(GetDetailResponse)
	err := grpc.Invoke(ctx, "/auth.AuthenticationService/AddUserToGroup", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authenticationServiceClient) RemoveUserFromGroup(ctx context.Context, in *RemoveFromGroupRequest, opts ...grpc.CallOption) (*GetDetailResponse, error) {
	out := new(GetDetailResponse)
	err := grpc.Invoke(ctx, "/auth.AuthenticationService/RemoveUserFromGroup", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authenticationServiceClient) ListUsersInGroup(ctx context.Context, in *ListGroupRequest, opts ...grpc.CallOption) (*UserListResponse, error) {
	out := new(UserListResponse)
	err := grpc.Invoke(ctx, "/auth.AuthenticationService/ListUsersInGroup", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authenticationServiceClient) ListGroups(ctx context.Context, in *ListAllGroupsRequest, opts ...grpc.CallOption) (*GroupList, error) {
	out := new(GroupList)
	err := grpc.Invoke(ctx, "/auth.AuthenticationService/ListGroups", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for AuthenticationService service

type AuthenticationServiceServer interface {
	// authenticate a user by username/password, return token
	AuthenticatePassword(context.Context, *AuthenticatePasswordRequest) (*VerifyPasswordResponse, error)
	// verify a user by token
	VerifyUserToken(context.Context, *VerifyRequest) (*VerifyResponse, error)
	GetUserByToken(context.Context, *VerifyRequest) (*GetDetailResponse, error)
	GetUserDetail(context.Context, *GetDetailRequest) (*GetDetailResponse, error)
	CreateUser(context.Context, *CreateUserRequest) (*GetDetailResponse, error)
	// will look up a user by email. Email may be any golang parseable format,
	// e.g. "Conrad Wood" <cnw@gurusystems.com> is ok
	// if a given email returns more than one user, this will throw an error!
	GetUserByEmail(context.Context, *UserByEmailRequest) (*GetDetailResponse, error)
	AddUserToGroup(context.Context, *AddToGroupRequest) (*GetDetailResponse, error)
	RemoveUserFromGroup(context.Context, *RemoveFromGroupRequest) (*GetDetailResponse, error)
	ListUsersInGroup(context.Context, *ListGroupRequest) (*UserListResponse, error)
	ListGroups(context.Context, *ListAllGroupsRequest) (*GroupList, error)
}

func RegisterAuthenticationServiceServer(s *grpc.Server, srv AuthenticationServiceServer) {
	s.RegisterService(&_AuthenticationService_serviceDesc, srv)
}

func _AuthenticationService_AuthenticatePassword_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AuthenticatePasswordRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticationServiceServer).AuthenticatePassword(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth.AuthenticationService/AuthenticatePassword",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticationServiceServer).AuthenticatePassword(ctx, req.(*AuthenticatePasswordRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthenticationService_VerifyUserToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(VerifyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticationServiceServer).VerifyUserToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth.AuthenticationService/VerifyUserToken",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticationServiceServer).VerifyUserToken(ctx, req.(*VerifyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthenticationService_GetUserByToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(VerifyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticationServiceServer).GetUserByToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth.AuthenticationService/GetUserByToken",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticationServiceServer).GetUserByToken(ctx, req.(*VerifyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthenticationService_GetUserDetail_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetDetailRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticationServiceServer).GetUserDetail(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth.AuthenticationService/GetUserDetail",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticationServiceServer).GetUserDetail(ctx, req.(*GetDetailRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthenticationService_CreateUser_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateUserRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticationServiceServer).CreateUser(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth.AuthenticationService/CreateUser",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticationServiceServer).CreateUser(ctx, req.(*CreateUserRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthenticationService_GetUserByEmail_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UserByEmailRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticationServiceServer).GetUserByEmail(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth.AuthenticationService/GetUserByEmail",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticationServiceServer).GetUserByEmail(ctx, req.(*UserByEmailRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthenticationService_AddUserToGroup_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(AddToGroupRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticationServiceServer).AddUserToGroup(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth.AuthenticationService/AddUserToGroup",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticationServiceServer).AddUserToGroup(ctx, req.(*AddToGroupRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthenticationService_RemoveUserFromGroup_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RemoveFromGroupRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticationServiceServer).RemoveUserFromGroup(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth.AuthenticationService/RemoveUserFromGroup",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticationServiceServer).RemoveUserFromGroup(ctx, req.(*RemoveFromGroupRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthenticationService_ListUsersInGroup_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListGroupRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticationServiceServer).ListUsersInGroup(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth.AuthenticationService/ListUsersInGroup",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticationServiceServer).ListUsersInGroup(ctx, req.(*ListGroupRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthenticationService_ListGroups_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListAllGroupsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthenticationServiceServer).ListGroups(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/auth.AuthenticationService/ListGroups",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthenticationServiceServer).ListGroups(ctx, req.(*ListAllGroupsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _AuthenticationService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "auth.AuthenticationService",
	HandlerType: (*AuthenticationServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "AuthenticatePassword",
			Handler:    _AuthenticationService_AuthenticatePassword_Handler,
		},
		{
			MethodName: "VerifyUserToken",
			Handler:    _AuthenticationService_VerifyUserToken_Handler,
		},
		{
			MethodName: "GetUserByToken",
			Handler:    _AuthenticationService_GetUserByToken_Handler,
		},
		{
			MethodName: "GetUserDetail",
			Handler:    _AuthenticationService_GetUserDetail_Handler,
		},
		{
			MethodName: "CreateUser",
			Handler:    _AuthenticationService_CreateUser_Handler,
		},
		{
			MethodName: "GetUserByEmail",
			Handler:    _AuthenticationService_GetUserByEmail_Handler,
		},
		{
			MethodName: "AddUserToGroup",
			Handler:    _AuthenticationService_AddUserToGroup_Handler,
		},
		{
			MethodName: "RemoveUserFromGroup",
			Handler:    _AuthenticationService_RemoveUserFromGroup_Handler,
		},
		{
			MethodName: "ListUsersInGroup",
			Handler:    _AuthenticationService_ListUsersInGroup_Handler,
		},
		{
			MethodName: "ListGroups",
			Handler:    _AuthenticationService_ListGroups_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "proto/auth.proto",
}

func init() { proto.RegisterFile("proto/auth.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 624 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0xbc, 0x55, 0x4f, 0x6f, 0xd3, 0x4e,
	0x10, 0x95, 0x53, 0xdb, 0x4d, 0xa6, 0x6a, 0x9a, 0x6c, 0xf3, 0xf3, 0xcf, 0x32, 0x3d, 0x94, 0x45,
	0x48, 0x51, 0x81, 0x82, 0x82, 0x38, 0x20, 0xa1, 0x8a, 0xf4, 0x5f, 0x54, 0x14, 0x01, 0x0a, 0x05,
	0x0e, 0x9c, 0x4c, 0xb3, 0xa5, 0x16, 0x89, 0x1d, 0xbc, 0xeb, 0xa2, 0x7e, 0x16, 0xbe, 0x0a, 0x67,
	0x3e, 0x17, 0xda, 0xd9, 0x75, 0xbc, 0x49, 0x6a, 0x73, 0x40, 0xe2, 0xe6, 0xd9, 0x99, 0x79, 0x3b,
	0xfb, 0xe6, 0xbd, 0x04, 0x5a, 0xb3, 0x34, 0x11, 0xc9, 0xe3, 0x30, 0x13, 0x57, 0xfb, 0xf8, 0x49,
	0x6c, 0xf9, 0x4d, 0x9f, 0x81, 0x33, 0x48, 0x93, 0x6c, 0x46, 0x7c, 0x58, 0xc7, 0x8f, 0xb3, 0x63,
	0xdf, 0xda, 0xb5, 0xba, 0x8d, 0xd1, 0xfa, 0x17, 0x15, 0x12, 0x02, 0xf6, 0xeb, 0x70, 0xca, 0xfc,
	0x1a, 0x1e, 0xdb, 0x71, 0x38, 0x65, 0xf4, 0x3e, 0x6c, 0x7e, 0x60, 0x69, 0x74, 0x79, 0x33, 0x62,
	0xdf, 0x32, 0xc6, 0x05, 0xe9, 0x80, 0x73, 0x9e, 0x7c, 0x65, 0xb1, 0x6e, 0x76, 0x84, 0x0c, 0x68,
	0x17, 0x9a, 0x79, 0x19, 0x9f, 0x25, 0x31, 0x67, 0xc4, 0x03, 0xf7, 0x3d, 0x67, 0xe9, 0xfc, 0x16,
	0x37, 0xc3, 0x88, 0xee, 0x41, 0x6b, 0xc0, 0xc4, 0x31, 0x13, 0x61, 0x34, 0xc9, 0x31, 0xcb, 0x6a,
	0x7f, 0x5a, 0xd0, 0x36, 0x8a, 0xab, 0x91, 0xe5, 0x64, 0x27, 0xd3, 0x30, 0x9a, 0xe8, 0xf9, 0x1d,
	0x26, 0x03, 0xb2, 0x03, 0x8d, 0xd3, 0x28, 0xe5, 0x02, 0x5f, 0xb6, 0x86, 0x99, 0xc6, 0x65, 0x7e,
	0x40, 0x02, 0xa8, 0x0f, 0x43, 0x9d, 0xb4, 0x31, 0x59, 0x9f, 0x84, 0x45, 0xee, 0x6d, 0xc8, 0xf9,
	0xf7, 0x24, 0x1d, 0xfb, 0x8e, 0xca, 0xcd, 0x74, 0x4c, 0xee, 0x81, 0x8b, 0x24, 0x72, 0xdf, 0xdd,
	0x5d, 0xeb, 0x6e, 0xf4, 0x36, 0xf6, 0x91, 0x70, 0x3c, 0x1b, 0xb9, 0x48, 0x28, 0xa7, 0x6f, 0xe0,
	0x4e, 0x3f, 0x13, 0x57, 0x2c, 0x16, 0xd1, 0x45, 0x28, 0x58, 0x0e, 0x66, 0x30, 0xa9, 0xe6, 0xb5,
	0xcc, 0x79, 0xcd, 0x5b, 0x6b, 0x8b, 0xb7, 0xd2, 0x4f, 0xe0, 0x29, 0x96, 0x0b, 0x28, 0xcd, 0xc9,
	0x03, 0xb0, 0x25, 0x27, 0x08, 0xb5, 0xd1, 0xfb, 0x5f, 0x4f, 0xb3, 0x4c, 0xdd, 0xc8, 0x96, 0x54,
	0x15, 0x2b, 0xac, 0x99, 0x2b, 0xfc, 0x61, 0x41, 0xfb, 0x28, 0x65, 0xa1, 0x60, 0x12, 0x29, 0x1f,
	0x32, 0x80, 0xba, 0x0c, 0x91, 0x20, 0x35, 0x67, 0x3d, 0xd3, 0xf1, 0xbf, 0x24, 0x9c, 0xee, 0x01,
	0x91, 0x73, 0x1c, 0xde, 0xe0, 0x8d, 0x95, 0x14, 0xd2, 0x13, 0x68, 0xf7, 0xc7, 0xe3, 0xf3, 0x44,
	0x6d, 0xa3, 0x5a, 0x63, 0xa6, 0x1d, 0x6a, 0x0b, 0x76, 0xa0, 0xaf, 0xc0, 0x1b, 0xb1, 0x69, 0x72,
	0xcd, 0x4e, 0xd3, 0x64, 0xfa, 0x97, 0x58, 0x0f, 0xa1, 0x35, 0x8c, 0xb8, 0x58, 0x40, 0x29, 0x35,
	0x22, 0xed, 0x43, 0x4b, 0xe2, 0xcb, 0x8e, 0xf9, 0x86, 0x1f, 0x81, 0x23, 0xcf, 0xb8, 0x6f, 0xa1,
	0xe0, 0x4a, 0x57, 0xec, 0xc8, 0x59, 0x38, 0xf5, 0xa0, 0x23, 0xdb, 0xfb, 0x93, 0x89, 0xd2, 0xa9,
	0xbe, 0x94, 0x3e, 0x81, 0x06, 0x1e, 0xc8, 0xa4, 0xa1, 0x62, 0xab, 0x54, 0xc5, 0xbd, 0x5f, 0x0e,
	0xfc, 0x67, 0xc8, 0x38, 0x4a, 0xe2, 0x77, 0x2c, 0xbd, 0x8e, 0x2e, 0x18, 0xf9, 0x08, 0x9d, 0xdb,
	0xf4, 0x4d, 0xee, 0x2a, 0x98, 0x0a, 0xed, 0x07, 0x3b, 0xaa, 0xa4, 0x44, 0xcd, 0x2f, 0x60, 0x4b,
	0x65, 0xe4, 0x8b, 0x51, 0xaa, 0x64, 0xdb, 0x6c, 0xc8, 0x51, 0x3a, 0x8b, 0x87, 0xba, 0xfb, 0x00,
	0x9a, 0x03, 0x26, 0x94, 0x5a, 0x2a, 0x9a, 0xcb, 0x18, 0x24, 0x2f, 0x61, 0x53, 0xf7, 0xab, 0x04,
	0xf1, 0x56, 0x2a, 0xff, 0x80, 0x70, 0x00, 0x50, 0x38, 0x89, 0xe8, 0xb2, 0x15, 0x6f, 0x95, 0xf7,
	0x1f, 0x19, 0x2f, 0x40, 0x7d, 0x13, 0x5f, 0x95, 0xae, 0x5a, 0xa0, 0x1c, 0xe4, 0x10, 0x9a, 0xfd,
	0xf1, 0x58, 0x31, 0xa8, 0x7e, 0xf9, 0x75, 0xe9, 0x8a, 0x37, 0xca, 0x31, 0x86, 0xb0, 0xad, 0x2c,
	0x20, 0x61, 0xe6, 0x36, 0x20, 0x7a, 0x7b, 0xb7, 0xbb, 0xa3, 0x6a, 0x22, 0x34, 0x01, 0xca, 0xf8,
	0x2c, 0x56, 0x50, 0x9a, 0xdb, 0x65, 0x73, 0x04, 0x5e, 0xf1, 0xe0, 0x05, 0x1b, 0x3c, 0x07, 0x98,
	0xd7, 0x72, 0x12, 0x14, 0xdd, 0xcb, 0x4a, 0x0f, 0xb6, 0x0c, 0x31, 0xcb, 0x82, 0xcf, 0x2e, 0xfe,
	0x1d, 0x3e, 0xfd, 0x1d, 0x00, 0x00, 0xff, 0xff, 0x0e, 0x9b, 0x43, 0xeb, 0x22, 0x07, 0x00, 0x00,
}
