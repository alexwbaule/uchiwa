package authdriver

import (
    "fmt"
    "github.com/sensu/uchiwa/uchiwa/config"
    "github.com/sensu/uchiwa/uchiwa/authentication"
    "github.com/sensu/uchiwa/uchiwa/logger"
)

var ldapclient = LDAPClient{
	UserFilter      : "(&(objectClass=%s)(%s=%s))",
	GroupFilter     : "(&(objectclass=group)(%s=%s))",
}

func New(ldapconf config.Ldap) {
    ldapclient.Conf = ldapconf

	if ldapclient.Conf.Dialect == "" {
		ldapclient.Conf.Dialect = "ad"
	}

    if ldapclient.Conf.GroupObjectClass == "" {
		ldapclient.Conf.GroupObjectClass = objectLdapFields[ldapclient.Conf.Dialect]["groupobjectclass"]
	}
    if ldapclient.Conf.GroupMemberAttribute == "" {
		ldapclient.Conf.GroupMemberAttribute = objectLdapFields[ldapclient.Conf.Dialect]["groupmemberattribute"]
	}

    if ldapclient.Conf.UserObjectClass == "" {
		ldapclient.Conf.UserObjectClass = objectLdapFields[ldapclient.Conf.Dialect]["userobjectclass"]
	}
    if ldapclient.Conf.UserAttribute == "" {
		ldapclient.Conf.UserAttribute = objectLdapFields[ldapclient.Conf.Dialect]["userattribute"]
	}
}

func Ldap(u, p string) (*authentication.User, error) {
    ok, usuario, err := ldapclient.Authenticate(u, p)
    if err != nil {
		if ldapclient.Conf.Debug {
			logger.Debug(fmt.Sprintf("Error: %v - %s", err));
		}
        return &authentication.User{}, fmt.Errorf("invalid user '%s' or invalid password", u)
    }
    if !ok {
		if ldapclient.Conf.Debug {
			logger.Debug(fmt.Sprintf("Error: %v - %s", err));
		}
        return &authentication.User{}, fmt.Errorf("invalid user '%s' or invalid password", u)
    }

	role,err := RolesByUser(usuario.Dn, usuario.Username)

    user := authentication.User{
        Email : usuario.Mail,
        FullName : usuario.Fullname,
        Readonly : false,
        Role : role,
        Username : usuario.Username}

	if err != nil {
		return &user, err
	}

	if ldapclient.Conf.Debug {
		logger.Debug(fmt.Sprintf("Auth OK: %v - %+v", ok, usuario));
	}

    return &user, nil
}

func RolesByUser(dn, login string) (authentication.Role, error){
	groups, err := ldapclient.GetGroupsOfUser(dn)
	found := false

	if err != nil {
		if ldapclient.Conf.Debug {
			logger.Debug(fmt.Sprintf("GetGroups Err: %v", err));
		}
	}
	newRole := authentication.Role{}

//	role := authentication.Role{
//        AccessToken: string,
//        Members: []string{},
//        Name: string,
//        Readonly : bool,
//        Subscriptions: []string{},
//        Datacenters: []string{}}

	//Analise das regras
	for _,role := range ldapclient.Conf.Roles {
		logger.Debug(fmt.Sprintf("Role: %+v", role))
		for _, roleGroup := range role.Members {
			if login == roleGroup && role.Readonly == true {
				found                   = true
				newRole.Readonly        = true;
				newRole.Members         = append(newRole.Members, login)
				newRole.Subscriptions   = append(newRole.Subscriptions, role.Subscriptions...)
				newRole.Datacenters     = append(newRole.Datacenters, role.Datacenters...)
				goto FIND
			} else if login == roleGroup && role.Readonly == false {
				found                   = true
				newRole.Readonly        = false;
				newRole.Members         = append(newRole.Members, login)
				newRole.Subscriptions   = append(newRole.Subscriptions, role.Subscriptions...)
				newRole.Datacenters     = append(newRole.Datacenters, role.Datacenters...)
				goto FIND
			}
			for  _, group := range groups {
				if group == roleGroup && role.Readonly == true {
					found                   = true
					newRole.Readonly        = true;
					newRole.Members         = append(newRole.Members, group)
				    newRole.Subscriptions   = append(newRole.Subscriptions, role.Subscriptions...)
				    newRole.Datacenters     = append(newRole.Datacenters, role.Datacenters...)
					goto FIND
				} else if group == roleGroup && role.Readonly == false {
					found                   = true
					newRole.Readonly        = false;
					newRole.Members         = append(newRole.Members, group)
				    newRole.Subscriptions   = append(newRole.Subscriptions, role.Subscriptions...)
				    newRole.Datacenters     = append(newRole.Datacenters, role.Datacenters...)
					goto FIND
				}
			}
		}
	}
	if found == false{
		return newRole, fmt.Errorf("User '%s' without Authorization", login)
	}

FIND:
	return newRole, nil
}
