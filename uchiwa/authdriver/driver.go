package authdriver

import (
	"crypto/tls"
	"errors"
	"fmt"

//	"github.com/sensu/uchiwa/uchiwa/logger"
	"gopkg.in/ldap.v2"
)

// Connect connects to the ldap backend
func (lc *LDAPClient) Connect() error {
	if lc.Conn == nil {
		var l *ldap.Conn
		var err error
		address := fmt.Sprintf("%s:%d", lc.Conf.Server, lc.Conf.Port)

        if lc.Conf.Security == "tls" {
            l, err = ldap.DialTLS("tcp", address, &tls.Config{InsecureSkipVerify: lc.Conf.Insecure})
            if err != nil {
                return err
            }
        } else if  lc.Conf.Security == "starttls" {
            err = l.StartTLS(&tls.Config{InsecureSkipVerify: lc.Conf.Insecure})
            if err != nil {
                return err
            }
        } else {
			l, err = ldap.Dial("tcp", address)
			if err != nil {
				return err
			}
        }
		lc.Conn = l
	}
	return nil
}

// Close closes the ldap backend connection
func (lc *LDAPClient) Close() {
	if lc.Conn != nil {
		lc.Conn.Close()
		lc.Conn = nil
	}
}

func (lc *LDAPClient) Authenticate(username, password string) (bool, *UserLdap, error) {
	err := lc.Connect()
	if err != nil {
        lc.Close()
		return false, nil, err
	}

	if lc.Conf.BindUser != "" && lc.Conf.BindPass != "" {
		err := lc.Conn.Bind(lc.Conf.BindUser, lc.Conf.BindPass)
		if err != nil {
            lc.Close()
			return false, nil, err
		}
	}

	//buscar nome, dn, etc.
	searchRequest := ldap.NewSearchRequest(
		lc.Conf.UserBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(lc.UserFilter, lc.Conf.UserObjectClass, lc.Conf.UserAttribute, username),
		lc.MapToArray(userLdapFields[lc.Conf.Dialect]),
		nil,
	)

	search, err := lc.Conn.Search(searchRequest)
	if err != nil {
        lc.Close()
		return false, nil, err
	}

	if len(search.Entries) < 1 {
        lc.Close()
		return false, nil, errors.New("User does not exist")
	}

	if len(search.Entries) > 1 {
        lc.Close()
		return false, nil, errors.New("Too many entries returned")
	}

	entry := search.Entries[0]

	user := UserLdap{
		Dn: entry.DN,
		Fullname: entry.GetAttributeValue(userLdapFields[lc.Conf.Dialect]["name"]),
		Groups:  append(entry.GetAttributeValues(userLdapFields[lc.Conf.Dialect]["members"])),
		Username:  username,
		Mail: entry.GetAttributeValue(userLdapFields[lc.Conf.Dialect]["mail"])}

	// Bind as the user to verify their password
	err = lc.Conn.Bind(user.Dn, password)
	if err != nil {
        lc.Close()
		return false, nil, err
	}
    lc.Close()

	return true, &user, nil
}

// GetGroupsOfUser returns the group for a user
func (lc *LDAPClient) GetGroupsOfUser(username string) ([]string, error) {
	err := lc.Connect()
	if err != nil {
		return nil, err
	}

	if lc.Conf.BindUser != "" && lc.Conf.BindPass != "" {
		err := lc.Conn.Bind(lc.Conf.BindUser, lc.Conf.BindPass)
		if err != nil {
            lc.Close()
			return nil, err
		}
	}

	searchRequest := ldap.NewSearchRequest(
		lc.Conf.GroupBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(lc.GroupFilter, matchLdapRule[lc.Conf.Dialect]["group"],ldap.EscapeFilter(username)),
		lc.MapToArray(groupLdapFields[lc.Conf.Dialect]),
		nil,
	)

	search, err := lc.Conn.Search(searchRequest)

	if err != nil {
        lc.Close()
		return nil, err
	}

	groups := []string{}
	for _, entry := range search.Entries {
		groups = append(groups, entry.GetAttributeValue("cn"))
	}

    lc.Close()
	return groups, nil
}

func (lc *LDAPClient) MapToArray(m map[string]string) []string {
	v := make([]string, 0, len(m))
	for  _, value := range m {
		v = append(v, value)
	}
	return v
}

