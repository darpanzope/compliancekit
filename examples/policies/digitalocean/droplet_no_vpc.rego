package compliancekit.do.droplet.no_vpc

# Rego twin of internal/checks/digitalocean/droplets.go § no-vpc.
# Flags any droplet attached only to the default network (no VPC).

metadata := {
	"id": "rego-do-droplet-no-vpc",
	"title": "Droplets should be attached to a private VPC (Rego)",
	"description": "Rego reimplementation of do-droplet-no-vpc. Droplets in the default network share the broadcast domain with every other default-network droplet in the region. Move workloads onto a private VPC.",
	"severity": "medium",
	"provider": "digitalocean",
	"service": "droplets",
	"resource_type": "digitalocean.droplet",
	"remediation": "Rebuild the droplet into a private VPC (DigitalOcean does not support in-place VPC reassignment).",
	"frameworks": {
		"soc2": ["CC6.6"],
		"iso27001": ["A.8.22"],
		"cis-v8": ["12.2"],
	},
	"tags": ["droplet", "network-segmentation"],
}

findings := [f |
	r := input.resources[_]
	r.type == "digitalocean.droplet"
	compliancekit.attr_str(r, "vpc_uuid") == ""
	f := {
		"resource_id": r.id,
		"status": "fail",
		"message": sprintf("droplet %q: no VPC attached", [r.name]),
	}
]
