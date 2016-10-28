package main

import (
	"flag"

	"github.com/sensu/uchiwa/uchiwa"
	"github.com/sensu/uchiwa/uchiwa/audit"
	"github.com/sensu/uchiwa/uchiwa/authentication"
    "github.com/sensu/uchiwa/uchiwa/authdriver"
	"github.com/sensu/uchiwa/uchiwa/authorization"
	"github.com/sensu/uchiwa/uchiwa/config"
	"github.com/sensu/uchiwa/uchiwa/filters"
)

func main() {
	configFile := flag.String("c", "./config.json", "Full or relative path to the configuration file")
	configDir := flag.String("d", "", "Full or relative path to the configuration directory, or comma delimited directories")
	publicPath := flag.String("p", "public", "Full or relative path to the public directory")
	flag.Parse()

	config := config.Load(*configFile, *configDir)

	u := uchiwa.Init(config)
    filter := false
    auth := authentication.New(config.Uchiwa.Auth)
    if config.Uchiwa.Auth.Driver == "simple" {
        auth.Simple(config.Uchiwa.Users)
    } else if config.Uchiwa.Auth.Driver == "ldap" {
        authdriver.New(config.Uchiwa.Ldap)
        auth.Advanced(authdriver.Ldap, "ldap")
        filter = true
    } else {
        auth.None()
    }

	// Audit
	audit.Log = audit.LogMock

	// Authorization
	uchiwa.Authorization = &authorization.Uchiwa{}

	// Filters
    if filter {
        uchiwa.Filters = &filters.LdapFilter{}
    }else{
        uchiwa.Filters = &filters.Uchiwa{}
    }

	u.WebServer(publicPath, auth)
}
