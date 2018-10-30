package daemon

import "github.com/sensu/uchiwa/uchiwa/structs"

func (f *DatacenterFetcher) buildDatacenter(name *string, info *structs.Info) *structs.Datacenter {
	datacenter := structs.Datacenter{
		Name:    *name,
		Info:    *info,
		Metrics: make(map[string]int, 5),
	}

	return &datacenter
}
