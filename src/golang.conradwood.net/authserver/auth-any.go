package main

// TODO: how/when do we close database connections? (pooling?)

import (
	"errors"
	"golang.conradwood.net/auth"
	pb "golang.conradwood.net/auth/proto"
)

type AnyAuthenticator struct {
}

func (pga *AnyAuthenticator) GetUserDetail(user string) (*auth.User, error) {
	au := auth.User{
		FirstName: "john",
		LastName:  "doe",
		Email:     "john.doe@microsoft.com",
		ID:        "1",
	}
	return &au, nil
}
func (pga *AnyAuthenticator) Authenticate(token string) (string, error) {
	return "1", nil
}

func (pga *AnyAuthenticator) CreateVerifiedToken(email string, pw string) string {
	return "generated_token"
}
func (pga *AnyAuthenticator) CreateUser(*pb.CreateUserRequest) (string, error) {
	return "", errors.New("CreateUser() not yet implemented")
}
func (pga *AnyAuthenticator) GetUserByEmail(c *pb.UserByEmailRequest) ([]*auth.User, error) {
	var res []*auth.User
	a, err := pga.GetUserDetail("")
	if err != nil {
		return nil, err
	}
	res = append(res, a)
	return res, nil
}

func (pga *AnyAuthenticator) AddUserToGroup(req *pb.AddToGroupRequest) ([]*auth.User, error) {
	return nil, errors.New("AddUserToGroup() not implemented")
}
func (pga *AnyAuthenticator) RemoveUserFromGroup(req *pb.RemoveFromGroupRequest) ([]*auth.User, error) {
	return nil, errors.New("RemoveUserFromGroup() not implemented")
}
func (pga *AnyAuthenticator) ListUsersInGroup(req *pb.ListGroupRequest) ([]*auth.User, error) {
	return nil, errors.New("ListUsersInGroup() not implemented")
}
