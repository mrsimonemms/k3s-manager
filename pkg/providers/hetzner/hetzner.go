/*
 * Copyright 2024 Simon Emms <simon@simonemms.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package hetzner

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"net"
	"os"
	"strconv"
	"text/template"
	"time"

	"github.com/appleboy/easyssh-proxy"
	"github.com/go-playground/validator/v10"
	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/mrsimonemms/golang-helpers/logger"
	"github.com/mrsimonemms/k3s-manager/pkg/common"
	"github.com/mrsimonemms/k3s-manager/pkg/config"
	"github.com/mrsimonemms/k3s-manager/pkg/provider"
	"github.com/mrsimonemms/k3s-manager/pkg/ssh"
	"github.com/sirupsen/logrus"
)

//go:embed cloud-init/manager.yaml.tpl
var cloudInitManager []byte

type Config struct {
	Token string `validate:"required"`
	SSHKey
}

type server struct {
	Type    common.NodeType
	Machine *hcloud.Server
	Node    provider.Node
}

type SSHKey struct {
	Public         string `validate:"required,file"`
	publicContent  []byte
	Private        string `validate:"required,file"`
	privateContent []byte
	Passphase      string
}

func (c *Config) load() error {
	publicContent, err := os.ReadFile(c.SSHKey.Public)
	if err != nil {
		return err
	}
	c.SSHKey.publicContent = publicContent

	privateContent, err := os.ReadFile(c.SSHKey.Private)
	if err != nil {
		return err
	}
	c.SSHKey.privateContent = privateContent

	return nil
}

func (c *Config) Validate() error {
	validate := validator.New(validator.WithRequiredStructEnabled())

	return validate.Struct(c)
}

type Hetzner struct {
	cfg         *config.Config
	client      *hcloud.Client
	providerCfg Config
	logger      *logrus.Entry
}

func (h *Hetzner) ApplyCSI(context.Context) (*provider.ApplyCSIResponse, error) {
	return nil, errNotImplemented
}

func (h *Hetzner) DatastoreCreate(context.Context) (*provider.DatastoreCreateResponse, error) {
	return nil, errNotImplemented
}

func (h *Hetzner) DatastoreDelete(context.Context) (*provider.DatastoreDeleteResponse, error) {
	return nil, errNotImplemented
}

func (h *Hetzner) GetProviderSecrets(ctx context.Context) (map[string]string, error) {
	return map[string]string{
		"privateSSHKey": string(h.providerCfg.privateContent),
		"publicSSHKey":  string(h.providerCfg.publicContent),
	}, nil
}

func (h *Hetzner) LoadBalancerCreate(context.Context) (*provider.LoadBalancerCreateResponse, error) {
	return nil, errNotImplemented
}

func (h *Hetzner) LoadBalancerDelete(context.Context) (*provider.LoadBalancerDeleteResponse, error) {
	return nil, errNotImplemented
}

func (h *Hetzner) ManagerAddress(ctx context.Context) (*provider.ManagerAddressResponse, error) {
	servers, err := h.listNodes(ctx, &provider.NodeListRequest{Type: common.NodeTypeManager})
	if err != nil {
		return nil, err
	}

	serverCount := len(servers)
	if serverCount == 0 {
		return nil, provider.ErrNotConfigured
	} else if serverCount == 1 {
		server := servers[0]

		return &provider.ManagerAddressResponse{
			Address: server.Machine.PublicNet.IPv4.IP.String(),
		}, nil
	}

	return nil, errNotImplemented
}

func (h *Hetzner) NodeCreate(ctx context.Context, opts *provider.NodeCreateRequest) (*provider.NodeCreateResponse, error) {
	labels := h.defaultLabels()

	// Ensure default values set
	opts.Pool = h.SetClusterNodePoolDefaults(opts.Pool)

	l := logger.Log().WithFields(logrus.Fields{
		"labels":   labels,
		"nodeType": opts.NodeType,
		"count":    opts.Count,
		"poolName": opts.Pool.Name,
	})

	// Get network
	l.Debug("Getting network")
	network, err := h.getNetwork(ctx, labels)
	if err != nil {
		l.WithError(err).Error("Error getting network")
		return nil, err
	}

	// Get SSH key
	l.Debug("Getting SSH key")
	sshKey, err := h.ensureSSHKeys(ctx, labels, false)
	if err != nil {
		l.WithError(err).Error("Error ensuring SSH keys")
		return nil, err
	}

	// Add additional label info
	labels[generateLabelKey(LabelKeyType)] = string(opts.NodeType)
	labels[generateLabelKey(LabelKeyPool)] = opts.Pool.Name
	if err := labels.Validate(); err != nil {
		return nil, err
	}
	l = logger.Log().WithField("labels", labels)

	// Ensure placement group for pool
	placementGroup, err := h.ensurePlacementGroup(ctx, labels, opts.Pool.Name)
	if err != nil {
		l.WithError(err).Error("Error ensuring placement group")
		return nil, err
	}

	// Add pool count to the label
	labels[generateLabelKey(LabelKeyCount)] = strconv.Itoa(opts.Count)
	if err := labels.Validate(); err != nil {
		return nil, err
	}

	server, err := h.CreateServer(ctx, provider.GenerateNodeName(h.cfg.Name, opts.Pool.Name, opts.Count), opts.Pool, labels, sshKey, placementGroup, opts.NodeType, network)
	if err != nil {
		l.WithError(err).Error("Error creating server")
		return nil, err
	}

	return &provider.NodeCreateResponse{
		Node: provider.NewNode(
			strconv.FormatInt(server.ID, 10),
			server.Name,
			server.PublicNet.IPv4.IP.String(),
			opts.NodeType,
			&opts.Count,
			&opts.Pool.Name,
			h.createServerSSH(server),
			provider.ProviderOpts{
				Location:    server.Datacenter.Location.Name,
				MachineType: server.ServerType.Name,
				Arch:        string(server.Image.Architecture),
				Image:       server.Image.Name,
			},
		),
	}, nil
}

func (h *Hetzner) NodeDelete(ctx context.Context, opts *provider.NodeDeleteRequest) (*provider.NodeDeleteResponse, error) {
	l := logger.Log().WithField("id", opts.ID)

	l.Debug("Parsing server ID to int64")
	id, err := strconv.ParseInt(opts.ID, 10, 64)
	if err != nil {
		l.WithError(err).Error("Server ID is invalid")
		return nil, err
	}
	l = l.WithField("id", id)

	l.Debug("Getting server")
	server, _, err := h.client.Server.GetByID(ctx, id)
	if err != nil {
		l.WithError(err).Error("Cannot retrieve server")
		return nil, err
	}
	if server == nil {
		l.Error("Server is unknown")
	}

	l.Debug("Deleting server")
	result, _, err := h.client.Server.DeleteWithResult(ctx, server)
	if err != nil {
		l.WithError(err).Error("Unable to delete server")
		return nil, err
	}

	if err := h.waitForActionCompletion(ctx, result.Action, time.Minute*5); err != nil {
		l.WithError(err).Error("Error deleting server")
		return nil, err
	}

	return &provider.NodeDeleteResponse{
		ID: opts.ID,
	}, nil
}

func (h *Hetzner) NodeList(ctx context.Context, opts *provider.NodeListRequest) (*provider.NodeListResponse, error) {
	servers, err := h.listNodes(ctx, opts)
	if err != nil {
		return nil, err
	}

	machines := make([]provider.Node, 0)
	for _, s := range servers {
		machines = append(machines, s.Node)
	}

	return &provider.NodeListResponse{
		Machines: machines,
	}, nil
}

func (h *Hetzner) Prepare(ctx context.Context) (*provider.PrepareResponse, error) {
	labels := h.defaultLabels()

	// Ensure network
	network, err := h.ensureNetwork(ctx, labels)
	if err != nil {
		return nil, err
	}

	// Ensure firewall
	if _, err := h.ensureFirewall(ctx, labels, network); err != nil {
		return nil, err
	}

	// Ensure SSH key
	sshKey, err := h.ensureSSHKeys(ctx, labels, true)
	if err != nil {
		return nil, err
	}

	// Add the manager type to the labels
	labels[generateLabelKey(LabelKeyType)] = string(common.NodeTypeManager)
	if err := labels.Validate(); err != nil {
		return nil, err
	}

	// Ensure placement group for managers
	placementGroup, err := h.ensurePlacementGroup(ctx, labels, "manager")
	if err != nil {
		return nil, err
	}

	// Ensure at least one manager server - this will only return one, but allow for extension
	managers, err := h.ensureManagerServer(ctx, labels, sshKey, placementGroup, network)
	if err != nil {
		return nil, err
	}

	// Ensure manager load balancer if multiple manager nodes
	if h.cfg.Cluster.ManagerPool.Count > 1 {
		// Add the load balancer IP in the TLS SANs
		return nil, errNotImplemented
		// if _, err := h.ensureManagerLoadBalancer(ctx, labels) ; err != nil {
		// 	return nil, err
		// }
	}

	managerList := make([]provider.Node, 0)

	for _, s := range managers {
		managerList = append(managerList, s.Node)
	}

	return &provider.PrepareResponse{
		Managers: managerList,
	}, nil
}

func (h *Hetzner) SetClusterNodePoolDefaults(c config.ClusterNodePool) config.ClusterNodePool {
	if c.Image == nil {
		c.Image = hcloud.Ptr(DefaultImage)
	}
	if c.Arch == nil {
		c.Arch = hcloud.Ptr(DefaultArch)
	}

	return c
}

func (h *Hetzner) CreateServer(ctx context.Context, name string, nodeConfig config.ClusterNodePool, labels labelSelector, sshKey *hcloud.SSHKey, placementGroup *hcloud.PlacementGroup, nodeType common.NodeType, network *hcloud.Network) (*hcloud.Server, error) {
	l := h.logger.WithFields(logrus.Fields{
		"name":      name,
		"type":      nodeConfig.Type,
		"location":  nodeConfig.Location,
		"labels":    labels,
		"image":     *nodeConfig.Image,
		"arch":      *nodeConfig.Arch,
		"nodeType":  nodeType,
		"networkId": network.ID,
	})

	l.Info("Creating new server")

	l.Debug("Validating server type")
	serverType, _, err := h.client.ServerType.GetByName(ctx, nodeConfig.Type)
	if err != nil {
		l.WithError(err).Error("Error retrieving server type")
		return nil, err
	}
	if serverType == nil {
		l.Error("Unknown server type")
		return nil, ErrUnknownServerType
	}

	l.Debug("Validating server location")
	location, _, err := h.client.Location.GetByName(ctx, nodeConfig.Location)
	if err != nil {
		l.WithError(err).Error("Error retrieving server location")
		return nil, err
	}
	if location == nil {
		l.Error("Unknown server location")
		return nil, ErrUnknownLocation
	}

	l.Debug("Validating server image")
	image, _, err := h.client.Image.GetByNameAndArchitecture(ctx, *nodeConfig.Image, hcloud.Architecture(*nodeConfig.Arch))
	if err != nil {
		l.WithError(err).Error("Error retrieving image")
		return nil, err
	}
	if image == nil {
		l.Error("Unknown server image")
		return nil, ErrUnknownImage
	}

	var userDataTpl string
	if nodeType == common.NodeTypeManager {
		userDataTpl = string(cloudInitManager)
	}

	l.Debug("Parse cloud-init template")
	tpl, err := template.New("cloud-init").Parse(userDataTpl)
	if err != nil {
		l.WithError(err).Error("Unable to parse cloud-init template")
		return nil, err
	}
	var userData bytes.Buffer
	if err := tpl.Execute(&userData, map[string]any{
		"PublicKey": string(h.providerCfg.publicContent),
		"SSHPort":   h.cfg.Networking.SSHPort,
		"User":      common.MachineUser,
	}); err != nil {
		l.WithError(err).Error("Error executing cloud-init template")
		return nil, err
	}

	l.Debug("Create the server")
	result, _, err := h.client.Server.Create(ctx, hcloud.ServerCreateOpts{
		Name:           name,
		Location:       location,
		ServerType:     serverType,
		Image:          image,
		Labels:         labels,
		Networks:       []*hcloud.Network{network},
		SSHKeys:        []*hcloud.SSHKey{sshKey},
		PlacementGroup: placementGroup,
		UserData:       userData.String(),
	})
	if err != nil {
		l.WithError(err).Error("Error triggering manager server creation")
		return nil, err
	}

	if err := h.waitForActionCompletion(ctx, result.Action, time.Minute*5); err != nil {
		l.WithError(err).Error("Error creating manager server")
		return nil, err
	}

	l = l.WithField("serverId", result.Server.ID)

	l.Info("Server created")

	return result.Server, nil
}

func (h *Hetzner) createServerSSH(server *hcloud.Server) ssh.SSH {
	return ssh.New(easyssh.MakeConfig{
		User:       common.MachineUser,
		Server:     server.PublicNet.IPv4.IP.String(),
		Passphrase: h.providerCfg.Passphase,
		Port:       strconv.Itoa(h.cfg.Networking.SSHPort),
		Key:        string(h.providerCfg.privateContent),
		Timeout:    10 * time.Second,
	})
}

func (h *Hetzner) defaultLabels() labelSelector {
	return labelSelector{
		generateLabelKey(LabelKeyCluster): h.cfg.Name,
	}
}

func (h *Hetzner) ensureManagerServer(ctx context.Context, labels labelSelector, sshKey *hcloud.SSHKey, placementGroup *hcloud.PlacementGroup, network *hcloud.Network) ([]server, error) {
	l := h.logger.WithField("labels", labels)

	// Don't use the upsert workflow as may be multiple servers
	l.Info("Ensuring manager server exists")
	servers, err := h.listNodes(ctx, &provider.NodeListRequest{Type: common.NodeTypeManager})
	if err != nil {
		return nil, err
	}

	serverCount := len(servers)
	l.WithField("count", serverCount).Debug("Number of servers found")

	if serverCount == 0 {
		labels[generateLabelKey(LabelKeyCount)] = "0"

		h.cfg.ManagerPool = h.SetClusterNodePoolDefaults(h.cfg.ManagerPool)

		s, err := h.CreateServer(ctx, provider.GenerateNodeName(h.cfg.Name, h.cfg.ManagerPool.Name, 0), h.cfg.ManagerPool, labels, sshKey, placementGroup, common.NodeTypeManager, network)
		if err != nil {
			return nil, err
		}

		return []server{
			{
				Type:    common.NodeTypeManager,
				Machine: s,
				Node: provider.NewNode(
					strconv.FormatInt(s.ID, 10),
					s.Name,
					s.PublicNet.IPv4.IP.String(),
					common.NodeTypeManager,
					common.Ptr(0),
					nil,
					h.createServerSSH(s),
					provider.ProviderOpts{
						Location:    s.Datacenter.Location.Name,
						MachineType: s.ServerType.Name,
						Arch:        string(s.Image.Architecture),
						Image:       s.Image.Name,
					},
				),
			},
		}, nil
	}

	return servers, nil
}

func (h *Hetzner) ensureSSHKeys(ctx context.Context, labels labelSelector, uploadIfNotPresent bool) (*hcloud.SSHKey, error) {
	fingerprint, err := generateSSHKeyFingerprint(string(h.providerCfg.publicContent))
	if err != nil {
		return nil, err
	}

	sshKey, _, err := h.client.SSHKey.GetByFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, err
	}

	if sshKey == nil {
		if !uploadIfNotPresent {
			return nil, ErrSSHKeyNotPresent
		}

		// Upload the key
		uploadedSSHKey, _, err := h.client.SSHKey.Create(ctx, hcloud.SSHKeyCreateOpts{
			Name:      common.AppendRandomString(h.cfg.Name, 6),
			PublicKey: string(h.providerCfg.publicContent),
			Labels:    labels,
		})
		if err != nil {
			return nil, err
		}

		sshKey = uploadedSSHKey
	}

	return sshKey, nil
}

// Placement groups ensure that virtual servers run on different physical machines
func (h *Hetzner) ensurePlacementGroup(ctx context.Context, labels labelSelector, nameSuffix string) (*hcloud.PlacementGroup, error) {
	l := h.logger.WithField("labels", labels)

	resourceName := fmt.Sprintf("%s-%s", h.cfg.Name, nameSuffix)

	return upsert[hcloud.PlacementGroup]{
		logger:       l,
		resourceType: "placement group",
		getId: func(pg *hcloud.PlacementGroup) any {
			return pg.ID
		},
		list: func(ctx context.Context) ([]*hcloud.PlacementGroup, error) {
			groups, _, err := h.client.PlacementGroup.List(ctx, hcloud.PlacementGroupListOpts{
				ListOpts: hcloud.ListOpts{
					LabelSelector: labels.String(),
				},
			})

			return groups, err
		},
		create: func(ctx context.Context) (*hcloud.PlacementGroup, error) {
			result, _, err := h.client.PlacementGroup.Create(ctx, hcloud.PlacementGroupCreateOpts{
				Name:   resourceName,
				Labels: labels,
				Type:   hcloud.PlacementGroupTypeSpread,
			})
			if err != nil {
				return nil, err
			}

			if err := h.waitForActionCompletion(ctx, result.Action); err != nil {
				return nil, err
			}

			return result.PlacementGroup, err
		},
		update: func(ctx context.Context, pg *hcloud.PlacementGroup) (*hcloud.PlacementGroup, error) {
			group, _, err := h.client.PlacementGroup.Update(ctx, pg, hcloud.PlacementGroupUpdateOpts{
				Name:   resourceName,
				Labels: labels,
			})

			return group, err
		},
	}.exec(ctx)
}

func (h *Hetzner) ensureFirewall(ctx context.Context, labels labelSelector, network *hcloud.Network) (*hcloud.Firewall, error) {
	l := h.logger.WithField("labels", labels)

	firewall, err := upsert[hcloud.Firewall]{
		logger:       l,
		resourceType: "firewall",
		getId: func(f *hcloud.Firewall) any {
			return f.ID
		},
		list: func(ctx context.Context) ([]*hcloud.Firewall, error) {
			firewalls, _, err := h.client.Firewall.List(ctx, hcloud.FirewallListOpts{
				ListOpts: hcloud.ListOpts{
					LabelSelector: labels.String(),
				},
			})

			return firewalls, err
		},
		create: func(ctx context.Context) (*hcloud.Firewall, error) {
			result, _, err := h.client.Firewall.Create(ctx, hcloud.FirewallCreateOpts{
				Name:   h.cfg.Name,
				Labels: labels,
			})
			if err != nil {
				return nil, err
			}

			for _, a := range result.Actions {
				if err := h.waitForActionCompletion(ctx, a); err != nil {
					return nil, err
				}
			}

			return result.Firewall, err
		},
		update: func(ctx context.Context, f *hcloud.Firewall) (*hcloud.Firewall, error) {
			firewall, _, err := h.client.Firewall.Update(ctx, f, hcloud.FirewallUpdateOpts{
				Name:   h.cfg.Name,
				Labels: labels,
			})

			return firewall, err
		},
	}.exec(ctx)
	if err != nil {
		return nil, err
	}

	_, sshAllowed, err := net.ParseCIDR(h.cfg.Networking.NetworkingAllowed.SSH)
	if err != nil {
		l.WithError(err).Error("Invalid SSH allowlist provided for firewall")
		return nil, err
	}

	_, apiAllowed, err := net.ParseCIDR(h.cfg.Networking.NetworkingAllowed.API)
	if err != nil {
		l.WithError(err).Error("Invalid API allowlist provided for firewall")
		return nil, err
	}

	_, global, err := net.ParseCIDR(config.GlobalCIDR)
	if err != nil {
		return nil, err
	}

	_, globalv6, err := net.ParseCIDR(config.GlobalCIDRv6)
	if err != nil {
		return nil, err
	}

	l.Info("Setting firewall rules")
	actions, _, err := h.client.Firewall.SetRules(ctx, firewall, hcloud.FirewallSetRulesOpts{
		Rules: []hcloud.FirewallRule{
			{
				Description: hcloud.Ptr("SSH port"),
				Direction:   hcloud.FirewallRuleDirectionIn,
				Protocol:    hcloud.FirewallRuleProtocolTCP,
				Port:        hcloud.Ptr[string](strconv.Itoa(h.cfg.Networking.SSHPort)),
				SourceIPs: []net.IPNet{
					*sshAllowed,
				},
			},
			{
				Description: hcloud.Ptr("ICMP"),
				Direction:   hcloud.FirewallRuleDirectionIn,
				Protocol:    hcloud.FirewallRuleProtocolICMP,
				SourceIPs: []net.IPNet{
					*global,
					*globalv6,
				},
			},
			{
				Description: hcloud.Ptr("Allow all TCP traffic on private network"),
				Direction:   hcloud.FirewallRuleDirectionIn,
				Protocol:    hcloud.FirewallRuleProtocolTCP,
				Port:        hcloud.Ptr("any"),
				SourceIPs: []net.IPNet{
					*network.IPRange,
				},
			},
			{
				Description: hcloud.Ptr("Allow all UDP traffic on private network"),
				Direction:   hcloud.FirewallRuleDirectionIn,
				Protocol:    hcloud.FirewallRuleProtocolUDP,
				Port:        hcloud.Ptr("any"),
				SourceIPs: []net.IPNet{
					*network.IPRange,
				},
			},
			{
				Description: hcloud.Ptr("Allow access to KubeAPI"),
				Direction:   hcloud.FirewallRuleDirectionIn,
				Protocol:    hcloud.FirewallRuleProtocolTCP,
				Port:        hcloud.Ptr("6443"),
				SourceIPs: []net.IPNet{
					*apiAllowed,
				},
			},
		},
	})
	if err != nil {
		l.WithError(err).Error("Failed to create firewall rules")
		return nil, err
	}
	for _, a := range actions {
		if err := h.waitForActionCompletion(ctx, a); err != nil {
			l.WithError(err).Error("Firewall action errored")
			return nil, err
		}
	}

	l.Debug("Removing old firewall label rules")
	actions, _, err = h.client.Firewall.RemoveResources(ctx, firewall, firewall.AppliedTo)
	if err != nil {
		l.WithError(err).Error("Failed to remove old firewall label rules")
	}
	for _, a := range actions {
		if err := h.waitForActionCompletion(ctx, a); err != nil {
			l.WithError(err).Error("Firewall action errored")
			return nil, err
		}
	}

	l.Debug("Applying firewall label rules")
	actions, _, err = h.client.Firewall.ApplyResources(ctx, firewall, []hcloud.FirewallResource{
		{
			Type: hcloud.FirewallResourceTypeLabelSelector,
			LabelSelector: &hcloud.FirewallResourceLabelSelector{
				Selector: labels.String(),
			},
		},
	})
	if err != nil {
		l.WithError(err).Error("Failed to apply firewall label rules")
		return nil, err
	}

	for _, a := range actions {
		if err := h.waitForActionCompletion(ctx, a); err != nil {
			l.WithError(err).Error("Firewall label action errored")
			return nil, err
		}
	}

	return firewall, nil
}

func (h *Hetzner) getNetwork(ctx context.Context, labels labelSelector) (*hcloud.Network, error) {
	networks, _, err := h.client.Network.List(ctx, hcloud.NetworkListOpts{
		ListOpts: hcloud.ListOpts{
			LabelSelector: labels.String(),
		},
	})
	if err != nil {
		return nil, err
	}

	return ensureOnlyOneResource(networks, "network")
}

func (h *Hetzner) ensureNetwork(ctx context.Context, labels labelSelector) (*hcloud.Network, error) {
	l := h.logger.WithField("labels", labels)

	_, subnet, err := net.ParseCIDR(h.cfg.Networking.Subnet)
	if err != nil {
		l.WithError(err).Error("Invalid subnet provided for network")
		return nil, err
	}

	return upsert[hcloud.Network]{
		logger:       l,
		resourceType: "network",
		getId: func(n *hcloud.Network) any {
			return n.ID
		},
		list: func(ctx context.Context) ([]*hcloud.Network, error) {
			networks, _, err := h.client.Network.List(ctx, hcloud.NetworkListOpts{
				ListOpts: hcloud.ListOpts{
					LabelSelector: labels.String(),
				},
			})

			return networks, err
		},
		create: func(ctx context.Context) (*hcloud.Network, error) {
			network, _, err := h.client.Network.Create(ctx, hcloud.NetworkCreateOpts{
				Name:    h.cfg.Name,
				IPRange: subnet,
				Labels:  labels,
				Subnets: []hcloud.NetworkSubnet{
					{
						Type:        hcloud.NetworkSubnetTypeCloud,
						IPRange:     subnet,
						NetworkZone: hcloud.NetworkZone(h.cfg.Networking.Location),
					},
				},
			})

			return network, err
		},
		update: func(ctx context.Context, network *hcloud.Network) (*hcloud.Network, error) {
			// @todo(sje): handle changes to the network subnet
			return network, nil
		},
	}.exec(ctx)
}

func (h *Hetzner) listNodes(ctx context.Context, opts *provider.NodeListRequest) ([]server, error) {
	labels := h.defaultLabels()

	// Let's do a bit of defensive coding
	if opts == nil {
		opts = &provider.NodeListRequest{}
	}

	if opts.Type == common.NodeTypeManager {
		labels[generateLabelKey(LabelKeyType)] = string(common.NodeTypeManager)
	} else if opts.Type == common.NodeTypeWorker {
		labels[generateLabelKey(LabelKeyType)] = string(common.NodeTypeWorker)
	}

	l := logger.Log().WithField("labels", labels)

	servers, _, err := h.client.Server.List(ctx, hcloud.ServerListOpts{
		ListOpts: hcloud.ListOpts{
			LabelSelector: labels.String(),
		},
	})
	if err != nil {
		l.WithError(err).Error("Error listing servers")
		return nil, err
	}

	serverList := make([]server, 0)
	for _, s := range servers {
		var count *int
		if c, ok := s.Labels[generateLabelKey(LabelKeyCount)]; ok {
			countI, err := strconv.Atoi(c)
			if err == nil {
				count = &countI
			}
		}
		var poolName *string
		if p, ok := s.Labels[generateLabelKey(LabelKeyPool)]; ok {
			poolName = &p
		}
		var nodeType common.NodeType
		if t, ok := s.Labels[generateLabelKey(LabelKeyType)]; ok {
			nodeType = common.NodeType(t)
		}

		out := server{
			Machine: s,
			Type:    nodeType,
			Node: provider.NewNode(
				strconv.FormatInt(s.ID, 10),
				s.Name,
				s.PublicNet.IPv4.IP.String(),
				nodeType,
				count,
				poolName,
				ssh.New(easyssh.MakeConfig{
					User:       common.MachineUser,
					Server:     s.PublicNet.IPv4.IP.String(),
					Port:       strconv.Itoa(h.cfg.Networking.SSHPort),
					Key:        string(h.providerCfg.privateContent),
					Passphrase: h.providerCfg.Passphase,
					Timeout:    10 * time.Second,
				}),
				provider.ProviderOpts{
					Location:    s.Datacenter.Location.Name,
					MachineType: s.ServerType.Name,
					Arch:        string(s.Image.Architecture),
					Image:       s.Image.Name,
				},
			),
		}

		serverList = append(serverList, out)
	}

	return serverList, nil
}

// waitForActionCompletion if a command returns an *hcloud.Action struct, this is a long-running job on the Hetzner side.
// If we need to wait for it to finish to rely upon it later, this command will wait until we have success or that
// there's an error
func (h *Hetzner) waitForActionCompletion(ctx context.Context, action *hcloud.Action, timeout ...time.Duration) error {
	if action == nil {
		h.logger.Trace("No action received")
		return nil
	}

	if len(timeout) == 0 {
		timeout = []time.Duration{
			time.Minute,
		}
	}

	startTime := time.Now()
	timeoutTime := startTime.Add(timeout[0])

	for {
		time.Sleep(time.Second)

		now := time.Now()

		l := h.logger.WithField("actionId", action.ID)

		if now.After(timeoutTime) {
			l.WithFields(logrus.Fields{
				"startTime":   startTime,
				"currentTime": now,
				"timeoutTime": timeout,
			}).Error("Action timedout")

			return fmt.Errorf("action timed out")
		}

		l.Debug("Checking action status")

		status, _, err := h.client.Action.GetByID(ctx, action.ID)
		if err != nil {
			return err
		}

		l.WithField("status", status.Status).Debug("Current status")

		if status.Status == hcloud.ActionStatusError {
			l.WithFields(logrus.Fields{
				"errorCode": status.ErrorCode,
				"errorMsg":  status.ErrorMessage,
			}).Error("Error completing action")
			return fmt.Errorf("%s: %s", status.ErrorCode, status.ErrorMessage)
		}

		if status.Status == hcloud.ActionStatusSuccess {
			break
		}
	}

	return nil
}
