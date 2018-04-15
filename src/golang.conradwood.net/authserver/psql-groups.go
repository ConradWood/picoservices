package main

import (
	"fmt"
	"golang.conradwood.net/auth"
)

const (
	ORIGIN_DB   = 1
	ORIGIN_LDAP = 2
)

// given a backend and a an id, will workout the uniform ID
// it looks for a match in the DB (if none found will create one)
// and return the ID of the row
func (pga *PsqlLdapAuthenticator) backendGroupIDToUniID(backendgroup *auth.Group, backend int) error {
	rows, err := pga.dbcon.Query("SELECT id,groupname FROM groups where origin = $1 and foreignid = $2", backend, backendgroup.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		var name string
		err = rows.Scan(&id, &name)
		if err != nil {
			return err
		}
		backendgroup.ID = fmt.Sprintf("%d", id)
		backendgroup.Name = name
		return nil
	}
	irows, err := pga.dbcon.Query("insert into groups ( origin,foreignid,groupname) values ( $1, $2,$3 ) returning id", backend, backendgroup.ID, backendgroup.Name)
	defer irows.Close()
	for irows.Next() {
		var id int
		err = irows.Scan(&id)
		if err != nil {
			return err
		}
		return nil
	}

	return fmt.Errorf("groupids failed mysteriously")
}

func (pga *PsqlLdapAuthenticator) backendGroupsToUniGroups(groups []*auth.Group, backend int) error {
	for _, g := range groups {
		err := pga.backendGroupIDToUniID(g, backend)
		if err != nil {
			return err
		}
	}
	return nil
}
