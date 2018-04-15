package main

// authenticate password against ldap
// save rest in postgres
// this is the backend currently used in production.
// take good care when modifying this!

import (
	"database/sql"
	"errors"
	"flag"
	"fmt"
	_ "github.com/lib/pq"
	"golang.conradwood.net/auth"
	pb "golang.conradwood.net/auth/proto"
	"net/mail"
)

var (
	dbhost = flag.String("dbhost", "postgres", "hostname of the postgres database rdms")
	dbdb   = flag.String("database", "rpcusers", "database to use for authentication")
	dbuser = flag.String("dbuser", "root", "username for the database to use for authentication")
	dbpw   = flag.String("dbpw", "pw", "password for the database to use for authentication")
)

type PsqlLdapAuthenticator struct {
	dbcon       *sql.DB
	dbinfo      string
	connDetails map[string]string
}
type dbUser struct {
	a      *auth.User
	ldapcn string
}

// return the userid if found
func (pga *PsqlLdapAuthenticator) Authenticate(token string) (string, error) {
	fmt.Printf("Attempting to authenticate token \"%s\"\n", token)
	rows, err := pga.dbcon.Query("SELECT userid FROM usertoken where token = $1", token)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	for rows.Next() {
		var uid int
		err = rows.Scan(&uid)
		if err != nil {
			return "", errors.New("error scanning row")
		}
		return fmt.Sprintf("%d", uid), nil

	}

	return "", errors.New(fmt.Sprintf("Not a valid token: \"%s\"", token))
}

func NewLdapPsqlAuthenticator() (auth.Authenticator, error) {
	var err error
	var now string
	host := *dbhost
	username := *dbuser
	database := *dbdb
	password := *dbpw
	fmt.Printf("Connecting to host %s\n", host)

	res := PsqlLdapAuthenticator{}

	res.dbinfo = fmt.Sprintf("host=%s user=%s password=%s dbname=%s sslmode=require",
		host, username, password, database)
	res.dbcon, err = sql.Open("postgres", res.dbinfo)
	if err != nil {
		fmt.Printf("Failed to connect to %s on host \"%s\" as \"%s\"\n", database, host, username)
		return nil, err
	}
	err = res.dbcon.QueryRow("SELECT NOW() as now").Scan(&now)
	if err != nil {
		fmt.Printf("Failed to scan %s on host \"%s\" as \"%s\"\n", database, host, username)
		return nil, err
	}
	fmt.Printf("Time in database: %s\n", now)
	return &res, nil
}

// we authenticate a user by email & password.
// we lookup email in postgres. if none we look up email as ldapcn.
// if there's neither we fail. Otherwise we use ldap to authenticate against ldap, otherwise fail
func (pga *PsqlLdapAuthenticator) CreateVerifiedToken(email string, pw string) string {
	uid := pga.getUserIDfromEmail(email)
	if uid == "" {
		fmt.Printf("User \"%s\" has no id (does not exist in database)\n", email)
		return ""
	}

	dbu, err := pga.getUser(uid)
	if err != nil {
		fmt.Printf("User %s with id %s has no user?\n", email, uid)
		return ""
	}
	cn := dbu.ldapcn
	tk := CheckLdapPassword(cn, pw)
	if tk == "" {
		fmt.Printf("Email %s (cn=%s) failed ldap authentication\n", cn, email)
		return ""
	}
	fmt.Printf("User \"%s\" has id %s\n", email, uid)
	err = pga.addTokenToUser(uid, tk, 10*365*24*60*60) // valid 10 years...
	if err != nil {
		fmt.Printf("Failed to add token to user: %s\n", err)
		return ""
	}
	fmt.Printf("Token: %s\n", tk)
	return tk
}

// given a userid returns user struct
func (pga *PsqlLdapAuthenticator) GetUserDetail(userid string) (*auth.User, error) {
	u, err := pga.getUser(userid)
	if err != nil {
		return nil, err
	}
	groups, err := GetLdapGroupsForUser(u.ldapcn)
	if err != nil {
		return nil, err
	}
	err = pga.backendGroupsToUniGroups(groups, ORIGIN_LDAP)
	if err != nil {
		return nil, err
	}
	u.a.Groups = groups
	return u.a, nil
}

// return userid or ""
func (pga *PsqlLdapAuthenticator) getUserIDfromEmail(email string) string {
	var userid int
	rows, err := pga.dbcon.Query("SELECT id FROM usertable where email = $1 or ldapcn = $1", email)
	if err != nil {
		fmt.Printf("Error quering database: %s\n", err)
		return ""
	}
	defer rows.Close()
	for rows.Next() {
		err = rows.Scan(&userid)
		if err != nil {
			fmt.Printf("Failed to scan row: %s\n", err)
			return ""
		}
		return fmt.Sprintf("%d", userid)
	}
	return ""
}

// given a userid this will retrieve the corresponding row from db and return user struct
func (pga *PsqlLdapAuthenticator) getUser(userid string) (*dbUser, error) {

	rows, err := pga.dbcon.Query("SELECT id,firstname,lastname,email,ldapcn FROM usertable where id = $1 order by id asc", userid)
	if err != nil {
		s := fmt.Sprintf("Error quering database: %s\n", err)
		return nil, errors.New(s)
	}
	defer rows.Close()
	for rows.Next() {
		user := auth.User{}
		dbUser := dbUser{a: &user}
		err = rows.Scan(&user.ID, &user.FirstName, &user.LastName, &user.Email, &dbUser.ldapcn)
		if err != nil {
			s := fmt.Sprintf("Failed to scan row: %s\n", err)
			return nil, errors.New(s)
		}
		return &dbUser, nil
	}
	return nil, errors.New("No matching user found")
}

// given a userid this will create a token and add it to the useraccount
func (pga *PsqlLdapAuthenticator) addTokenToUser(userid string, token string, validsecs int) error {
	_, err := pga.dbcon.Exec("insert into usertoken (token,userid) values ($1,$2)", token, userid)
	if err != nil {
		fmt.Printf("Error inserting usertoken: %s\n", err)
		return err
	}
	return nil

}
func (pga *PsqlLdapAuthenticator) CreateUser(c *pb.CreateUserRequest) (string, error) {
	pw := c.Password
	if pw == "" {
		pw = RandomString(64)
	}
	err := CreateLdapUser(c.UserName, c.LastName, c.UserName, pw)
	/*
		// continue anyways, perhaps botched 1. attempt and this is second?
				if err != nil {
					return "", err
				}
	*/
	_, err = pga.dbcon.Exec("insert into usertable (firstname,lastname,email,ldapcn) values ($1,$2,$3,$4)", c.FirstName, c.LastName, c.Email, c.UserName)
	if err != nil {
		return "", err
	}
	return pw, nil
}
func (pga *PsqlLdapAuthenticator) GetUserByEmail(c *pb.UserByEmailRequest) ([]*auth.User, error) {
	// first check the simple case: is there a user
	// with a dedicated email
	var res []*auth.User
	ea, err := mail.ParseAddress(c.Email)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse email \"%s\": %s", c.Email, err)
	}
	emailstring := ea.Address
	uid := pga.getUserIDfromEmail(emailstring)
	if uid != "" {
		a, err := pga.GetUserDetail(uid)
		if err != nil {
			return nil, fmt.Errorf("Failed to get user detail for %s: %s", uid, err)
		}
		res = append(res, a)
	}

	// now check sql for aliases
	rows, err := pga.dbcon.Query("SELECT userid FROM emailaliases where alias = $1", emailstring)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var userid int
	for rows.Next() {
		err = rows.Scan(&userid)
		if err != nil {
			return nil, err
		}
		a, err := pga.GetUserDetail(fmt.Sprintf("%d", userid))
		if err != nil {
			return nil, fmt.Errorf("Failed to get user detail for \"%s\": %s", userid, err)
		}
		res = append(res, a)
	}

	return res, nil
}

/*****
Groups are annoying. we can have groups in ldap, postgres, <other external tool>
we store all groups with their ID and their source in postgres. we only ever return
the ID in postgres and internally map/remap to the source to lookup membership
*****/
func (pga *PsqlLdapAuthenticator) AddUserToGroup(req *pb.AddToGroupRequest) ([]*auth.User, error) {
	return nil, errors.New("AddUserToGroup() not implemented")
}
func (pga *PsqlLdapAuthenticator) RemoveUserFromGroup(req *pb.RemoveFromGroupRequest) ([]*auth.User, error) {
	return nil, errors.New("RemoveUserFromGroup() not implemented")
}

func (pga *PsqlLdapAuthenticator) ListUsersInGroup(req *pb.ListGroupRequest) ([]*auth.User, error) {

	return nil, errors.New("ListUsersInGroup() not implemented")
}
