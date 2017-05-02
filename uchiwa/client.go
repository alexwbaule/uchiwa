package uchiwa

import (
	"fmt"

	"github.com/sensu/uchiwa/uchiwa/helpers"
	"github.com/sensu/uchiwa/uchiwa/logger"
)

func (u *Uchiwa) buildClientHistory(client, dc string, history []interface{}) []interface{} {
	for _, h := range history {
		m, ok := h.(map[string]interface{})
		if !ok {
			logger.Warningf("Could not assert this client history to an interface: %+v", h)
			continue
		}

		m["client"] = client
		m["dc"] = dc

		check, ok := m["last_result"].(map[string]interface{})
		if !ok {
			logger.Warningf("Could not assert this check to a struct: %+v", m["last_result"])
			continue
		}

		m["silenced"], m["silenced_by"] = helpers.IsCheckSilenced(check, client, dc, u.Data.Silenced)
	}

	return history
}

// DeleteClient send a DELETE request to the /clients/*client* endpoint in order to delete a client
func (u *Uchiwa) DeleteClient(dc, name string) error {
	api, err := getAPI(u.Datacenters, dc)
	if err != nil {
		logger.Warning(err)
		return err
	}

	err = api.DeleteClient(name)
	if err != nil {
		logger.Warning(err)
		return err
	}

	return nil
}

func (u *Uchiwa) findClient(name string) ([]interface{}, error) {
	var clients []interface{}
	for _, c := range u.Data.Clients {
		m, ok := c.(map[string]interface{})
		if !ok {
			logger.Warningf("Could not assert this client to an interface %+v", c)
			continue
		}
		if m["name"] == name {
			clients = append(clients, m)
		}
	}

	if len(clients) == 0 {
		return nil, fmt.Errorf("Could not find any client with the name '%s'", name)
	}

	return clients, nil
}

func (u *Uchiwa) findOutput(id *string, h map[string]interface{}, dc *string) string {
	if h["last_status"] == 0 {
		return ""
	}

	for _, e := range u.Data.Events {
		// does the dc match?
		m, ok := e.(map[string]interface{})
		if !ok {
			logger.Warningf("Could not assert this event to an interface %+v", e)
			continue
		}
		if m["dc"] != *dc {
			continue
		}

		// does the client match?
		c, ok := m["client"].(map[string]interface{})
		if !ok {
			logger.Warningf("Could not assert this client to an interface: %+v", c)
			continue
		}

		if c["name"] != *id {
			continue
		}

		// does the check match?
		k := m["check"].(map[string]interface{})
		if !ok {
			logger.Warningf("Could not assert this check to an interface: %+v", k)
			continue
		}
		if k["name"] != h["check"] {
			continue
		}
		return k["output"].(string)
	}

	return ""
}

// GetClient retrieves a specific client
func (u *Uchiwa) GetClient(dc, name string) (map[string]interface{}, error) {
	api, err := getAPI(u.Datacenters, dc)
	if err != nil {
		logger.Warning(err)
		return nil, err
	}

	client, err := api.GetClient(name)
	if err != nil {
		logger.Warning(err)
		return nil, err
	}

	// lock results
	u.Mu.Lock()
	defer u.Mu.Unlock()

	client["_id"] = fmt.Sprintf("%s/%s", dc, name)
	client["dc"] = dc
	client["silenced"] = helpers.IsClientSilenced(name, dc, u.Data.Silenced)

	return client, nil
}

// GetClientHistory retrieves a specific client history
func (u *Uchiwa) GetClientHistory(dc, name string) ([]interface{}, error) {
	api, err := getAPI(u.Datacenters, dc)
	if err != nil {
		logger.Warning(err)
		return nil, err
	}

	h, err := api.GetClientHistory(name)
	if err != nil {
		logger.Warning(err)
		return nil, err
	}

	// lock results
	u.Mu.Lock()
	defer u.Mu.Unlock()

	history := u.buildClientHistory(name, dc, h)

	return history, nil
}

func (u *Uchiwa) UpdateClient(payload interface{}) error {
	client, ok := payload.(map[string]interface{})
	if !ok {
		return fmt.Errorf("Unable to decode the payload")
	}

	dc, ok := client["dc"].(string)
	if !ok {
		return fmt.Errorf("Unable to identify the datacenter")
	}

	api, err := getAPI(u.Datacenters, dc)
	if err != nil {
		logger.Warning(err)
		return err
	}

	_, err = api.UpdateClient(payload)
	if err != nil {
		return err
	}

	return nil
}
