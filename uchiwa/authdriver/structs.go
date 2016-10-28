package authdriver

import (
	"github.com/sensu/uchiwa/uchiwa/config"
	"gopkg.in/ldap.v2"
)

type LDAPClient struct {
	Conn            *ldap.Conn
	Conf            config.Ldap
    UserFilter      string
    GroupFilter     string
}

type UserLdap struct {
	Dn			string
	Fullname	string
	Groups		[]string
	Username	string
	Mail		string
}
var (
    matchLdapRule = map[string]map[string]string{
        "ad": {
            "group":"member:1.2.840.113556.1.4.1941:",
        },
        "openldap":{
            "group":"member:1.2.840.113556.1.4.1941:",
        },
    }
    userLdapFields = map[string]map[string]string{
        "ad" : {
                "dn"        : "dn",
                "members"   : "memberOf",
                "name"      : "displayName",
                "mail"      : "userPrincipalName",
        },
        "openldap": {
                "dn"        : "dn",
                "members"   : "members",
                "name"      : "name",
                "mail"      : "mail",
       },
    }

    groupLdapFields = map[string]map[string]string{
        "ad": {
            "cn":"cn",
        },
        "openldap": {
            "cn":"cn",
        },
    }

    objectLdapFields = map[string]map[string]string{
        "ad": {
            "userattribute"         : "sAMAccountName",
            "groupmemberattribute"  : "member",
            "userobjectclass"       : "person",
            "groupobjectclass"      :"groupOfNames",
        },
        "openldap": {
            "userattribute"         : "uid",
            "groupmemberattribute"  : "uniqueMember",
            "userobjectclass"       : "inetOrgPerson",
            "groupobjectclass"      : "posixGroup",
        },
    }
)
