package main

import (
	"errors"
	"golang.conradwood.net/auth"
	pb "golang.conradwood.net/auth/proto"
)

type NilAuthenticator struct {
}

func (pga *NilAuthenticator) Authenticate(token string) (string, error) {
	return "", errors.New("NIL backend does not authenticate")
}
func (pga *NilAuthenticator) GetUserDetail(user string) (*auth.User, error) {
	return nil, errors.New("NIL backend does not provide UserDetails")
}
func (pga *NilAuthenticator) CreateVerifiedToken(email string, pw string) string {
	return ""
}
func (pga *NilAuthenticator) CreateUser(*pb.CreateUserRequest) (string, error) {
	return "", errors.New("CreateUser() not yet implemented")
}

func (pga *NilAuthenticator) GetUserByEmail(c *pb.UserByEmailRequest) ([]*auth.User, error) {
	return nil, errors.New("GetUserByEmail() not yet implemented")
}

func (pga *NilAuthenticator) AddUserToGroup(req *pb.AddToGroupRequest) ([]*auth.User, error) {
	return nil, errors.New("AddUserToGroup() not implemented")
}
func (pga *NilAuthenticator) RemoveUserFromGroup(req *pb.RemoveFromGroupRequest) ([]*auth.User, error) {
	return nil, errors.New("RemoveUserFromGroup() not implemented")
}
func (pga *NilAuthenticator) ListUsersInGroup(req *pb.ListGroupRequest) ([]*auth.User, error) {
	return nil, errors.New("ListUsersInGroup() not implemented")
}
