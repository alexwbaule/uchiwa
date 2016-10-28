package filters

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/sensu/uchiwa/uchiwa/structs"
	"github.com/sensu/uchiwa/uchiwa/authentication"
)

type LdapFilter struct{ }

// Aggregates filters based on role's datacenters
func (f *LdapFilter) Aggregates(data *[]interface{}, token *jwt.Token) []interface{} {
    aggregates := make([]interface{}, 0)

    if token != nil {
        role, ok := authentication.GetRoleFromToken(token)
        if ok == nil {
            for _, c := range *data {
                check := c.(map[string]interface{})
                adddc := false
                dcfrom := check["dc"].(string)
                if role.Datacenters != nil {
                    for _,dc := range role.Datacenters {
                        if (dc == dcfrom || dc == "*"){
                            adddc = true
                        }
                    }
                }
                if adddc {
                    aggregates = append(aggregates, c)
                }
            }
        }
    }
	return aggregates
}

// Events filters based on role's datacenters and subscriptions
func (f *LdapFilter) Events(data *[]interface{}, token *jwt.Token) []interface{} {
    events := make([]interface{}, 0)
    if token != nil {
        var role *authentication.Role

        role, ok := authentication.GetRoleFromToken(token)
        if ok == nil {
            for _, c := range *data {
                check := c.(map[string]interface{})
                add := false
                adddc := false
                dcfrom := check["dc"].(string)
                if _, present := check["client"]; present {
                    client := check["client"].(map[string]interface{})
                    if _, ok := client["subscriptions"]; ok {
                        for _,s := range client["subscriptions"].([]interface{}) {
                            if role.Subscriptions != nil {
                                for _, tk := range role.Subscriptions {
                                if (tk == s.(string) || tk == "*"){
                                        add = true
                                    }
                                }
                            }
                            if role.Datacenters != nil {
                                for _,dc := range role.Datacenters {
                                    if (dc == dcfrom || dc == "*"){
                                        adddc = true
                                    }
                                }
                            }
                        }
                    }
                }
                if add && adddc {
                    events = append(events, c)
                }
            }
        }
    }
    return events
}

// Silenced filters based on role's datacenters
func (f *LdapFilter) Silenced(data *[]interface{}, token *jwt.Token) []interface{} {
	silenced := make([]interface{}, 0)

    if token != nil {
        role, ok := authentication.GetRoleFromToken(token)
        if ok == nil {
            for _, c := range *data {
                check := c.(map[string]interface{})
                adddc := false
                dcfrom := check["dc"].(string)
                if role.Datacenters != nil {
                    for _,dc := range role.Datacenters {
                        if (dc == dcfrom || dc == "*"){
                            adddc = true
                        }
                    }
                }
                if adddc {
                    silenced = append(silenced, c)
                }
            }
        }
    }
	return silenced
}

// Stashes filters based on role's datacenters
func (f *LdapFilter) Stashes(data *[]interface{}, token *jwt.Token) []interface{} {
    stashes := make([]interface{}, 0)

    if token != nil {
        role, ok := authentication.GetRoleFromToken(token)
        if ok == nil {
            for _, c := range *data {
                check := c.(map[string]interface{})
                adddc := false
                dcfrom := check["dc"].(string)
                if role.Datacenters != nil {
                    for _,dc := range role.Datacenters {
                        if (dc == dcfrom || dc == "*"){
                            adddc = true
                        }
                    }
                }
                if adddc {
                    stashes = append(stashes, c)
                }
            }
        }
    }
    return stashes
}

// GetRequest is a function that filters GET requests.
func (f *LdapFilter) GetRequest(dc string, token *jwt.Token) bool {
	return false
}

func (f *LdapFilter) Datacenters(data []*structs.Datacenter, token *jwt.Token) []*structs.Datacenter {
    datacenter := make([]*structs.Datacenter, 0)

    if token != nil {
        role, ok := authentication.GetRoleFromToken(token)
        if ok == nil {
            for _, dcenter := range data {
                adddc := false
                if role.Datacenters != nil {
                    for _,dc := range role.Datacenters{
                        if (dc == dcenter.Name || dc == "*"){
                            adddc = true
                        }
                    }
                }
                if adddc {
                    datacenter = append(datacenter, dcenter)
                }
            }
        }
    }
    return datacenter
}

func (f *LdapFilter) Checks(data *[]interface{}, token *jwt.Token) []interface{} {
    checks := make([]interface{}, 0)

    if token != nil {
        role, ok := authentication.GetRoleFromToken(token)
        if ok == nil {
            for _, c := range *data {
                check := c.(map[string]interface{})
                add := false
                adddc := false
                dcfrom := check["dc"].(string)
                if _, present := check["subscribers"]; present {
                    for _,s := range check["subscribers"].([]interface{}) {
                        if role.Subscriptions != nil {
                            for _, tk := range role.Subscriptions {
                                if (tk == s.(string) || tk == "*"){
                                    add = true
                                }
                            }
                        }
                        if role.Datacenters != nil {
                            for _,dc := range role.Datacenters {
                                if (dc == dcfrom || dc == "*"){
                                    adddc = true
                                }
                            }
                        }
                    }
                    if add && adddc {
                        checks = append(checks, c)
                    }
                }
            }
        }
    }
    return checks
}

func (f *LdapFilter) Subscriptions(data *[]structs.Subscription, token *jwt.Token) []structs.Subscription {
    subscriptions := make([]structs.Subscription, 0)

    if token != nil {
        role, ok := authentication.GetRoleFromToken(token)
        if ok == nil {
            for _, subs := range *data {
                add	  := false
                adddc := false

                if role.Subscriptions != nil {
                    for _, tk := range role.Subscriptions {
                        if (tk == subs.Name || tk == "*"){
                            add = true
                        }
                    }
                }
                if role.Datacenters != nil {
                    for _,dc := range role.Datacenters {
                        if (dc == subs.Dc || dc == "*"){
                            adddc = true
                        }
                    }
                }
                if add && adddc {
                    subscriptions = append(subscriptions, subs)
                }
            }
        }
    }
    return subscriptions
}

func (f *LdapFilter) Clients(data *[]interface{}, token *jwt.Token) []interface{} {
    clients := make([]interface{}, 0)

    if token != nil {
        role, ok := authentication.GetRoleFromToken(token)
        if ok == nil {
            for _, c := range *data {
                client := c.(map[string]interface{})
                add := false
                adddc := false
                dcfrom := client["dc"].(string)
                for _,s := range client["subscriptions"].([]interface{}) {
                    if role.Subscriptions != nil {
                        for _, tk := range role.Subscriptions {
                            if (tk == s.(string) || tk == "*"){
                                add = true
                            }
                        }
                    }
                    if role.Datacenters != nil {
                        for _,dc := range role.Datacenters {
                            if (dc == dcfrom || dc == "*"){
                                adddc = true
                            }
                        }
                    }
                }
                if add && adddc {
                    clients = append(clients, c)
                }
            }
        }
    }
    return clients
}
