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
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"text/template"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/mrsimonemms/k3s-manager/pkg/common"
	"github.com/mrsimonemms/k3s-manager/pkg/config"
	"github.com/mrsimonemms/k3s-manager/pkg/provider"
	"github.com/sirupsen/logrus"
)

//go:embed cloud-init/manager.yaml.tpl
var cloudInitManager []byte

type Config struct {
	Token string `validate:"required"`
	SSHKey
}

type SSHKey struct {
	Public         string `validate:"required,file"`
	publicContent  []byte
	Private        string `validate:"required,file"`
	privateContent []byte
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

var errNotImplemented = errors.New("command not yet implemented")

func (h *Hetzner) ApplyCSI(context.Context) (*provider.ApplyCSIResponse, error) {
	return nil, errNotImplemented
}

func (h *Hetzner) DatastoreCreate(context.Context) (*provider.DatastoreCreateResponse, error) {
	return nil, errNotImplemented
}

func (h *Hetzner) DatastoreDelete(context.Context) (*provider.DatastoreDeleteResponse, error) {
	return nil, errNotImplemented
}

func (h *Hetzner) LoadBalancerCreate(context.Context) (*provider.LoadBalancerCreateResponse, error) {
	return nil, errNotImplemented
}

func (h *Hetzner) LoadBalancerDelete(context.Context) (*provider.LoadBalancerDeleteResponse, error) {
	return nil, errNotImplemented
}

func (h *Hetzner) NodeCreate(context.Context) (*provider.NodeCreateResponse, error) {
	return nil, errNotImplemented
}

func (h *Hetzner) NodeDelete(context.Context) (*provider.NodeDeleteResponse, error) {
	return nil, errNotImplemented
}

func (h *Hetzner) Prepare(ctx context.Context) (*provider.PrepareResponse, error) {
	labels := labelSelector{
		generateLabelKey("cluster"): h.cfg.Name,
	}

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
	sshKey, err := h.ensureSSHKeys(ctx, labels)
	if err != nil {
		return nil, err
	}

	// Ensure placement group for managers
	placementGroup, err := h.ensurePlacementGroup(ctx, labels)
	if err != nil {
		return nil, err
	}

	// Add the manager type to the labels
	labels[generateLabelKey("type")] = string(common.NodeTypeManager)
	if err := labels.Validate(); err != nil {
		return nil, err
	}

	// Ensure at least one manager server
	if _, err := h.ensureManagerServer(ctx, labels, sshKey, placementGroup); err != nil {
		return nil, err
	}

	// Ensure manager load balancer if multiple manager nodes
	if h.cfg.Cluster.ManagerPool.Count > 1 {
		return nil, errNotImplemented
		// if _, err := h.ensureManagerLoadBalancer(ctx, labels) ; err != nil {
		// 	return nil, err
		// }
	}

	return nil, nil
}

func (h *Hetzner) CreateServer(ctx context.Context, name string, nodeConfig config.ClusterNodePool, labels labelSelector, sshKey *hcloud.SSHKey, placementGroup *hcloud.PlacementGroup, nodeType common.NodeType) (*hcloud.Server, error) {
	if nodeConfig.Image == nil {
		nodeConfig.Image = hcloud.Ptr(DefaultImage)
	}
	if nodeConfig.Arch == nil {
		nodeConfig.Arch = hcloud.Ptr(DefaultArch)
	}

	l := h.logger.WithFields(logrus.Fields{
		"name":     name,
		"type":     nodeConfig.Type,
		"location": nodeConfig.Location,
		"labels":   labels,
		"image":    nodeConfig.Image,
		"arch":     nodeConfig.Arch,
		"nodeType": nodeType,
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
		"SSHPort": h.cfg.Networking.SSHPort,
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

	l.Info("Server created")

	return result.Server, nil
}

func (h *Hetzner) ensureManagerServer(ctx context.Context, labels labelSelector, sshKey *hcloud.SSHKey, placementGroup *hcloud.PlacementGroup) ([]*hcloud.Server, error) {
	l := h.logger.WithField("labels", labels)

	// Don't use the upsert workflow as may be multiple servers
	l.Info("Ensuring manager server exists")
	servers, _, err := h.client.Server.List(ctx, hcloud.ServerListOpts{
		ListOpts: hcloud.ListOpts{
			LabelSelector: labels.String(),
		},
	})
	if err != nil {
		l.WithError(err).Error("Error listing servers")
		return nil, err
	}

	serverCount := len(servers)
	l.WithField("count", serverCount).Debug("Number of servers found")

	if serverCount == 0 {
		server, err := h.CreateServer(ctx, fmt.Sprintf("%s-%s-%d", h.cfg.Name, h.cfg.ManagerPool.Name, 0), h.cfg.ManagerPool, labels, sshKey, placementGroup, common.NodeTypeManager)
		if err != nil {
			return nil, err
		}

		return []*hcloud.Server{
			server,
		}, nil
	}

	return servers, nil
}

func (h *Hetzner) ensureSSHKeys(ctx context.Context, labels labelSelector) (*hcloud.SSHKey, error) {
	fingerprint, err := generateSSHKeyFingerprint(string(h.providerCfg.publicContent))
	if err != nil {
		return nil, err
	}

	sshKey, _, err := h.client.SSHKey.GetByFingerprint(ctx, fingerprint)
	if err != nil {
		return nil, err
	}

	if sshKey == nil {
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
func (h *Hetzner) ensurePlacementGroup(ctx context.Context, labels labelSelector) (*hcloud.PlacementGroup, error) {
	l := h.logger.WithField("labels", labels)

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
				Name:   h.cfg.Name,
				Labels: labels,
				Type:   hcloud.PlacementGroupTypeSpread,
			})
			if err != nil {
				return nil, err
			}

			if err := h.waitForActionCompletion(ctx, result.Action); err != nil {
				return nil, err
			}

			fmt.Println(result.PlacementGroup)

			return result.PlacementGroup, err
		},
		update: func(ctx context.Context, pg *hcloud.PlacementGroup) (*hcloud.PlacementGroup, error) {
			group, _, err := h.client.PlacementGroup.Update(ctx, pg, hcloud.PlacementGroupUpdateOpts{
				Name:   h.cfg.Name,
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
				Protocol:    hcloud.FirewallRuleProtocolUDP,
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
			})

			return network, err
		},
		update: func(ctx context.Context, network *hcloud.Network) (*hcloud.Network, error) {
			networkSubnets := []hcloud.NetworkSubnet{
				{
					Type:        hcloud.NetworkSubnetTypeCloud,
					IPRange:     subnet,
					NetworkZone: hcloud.NetworkZone(h.cfg.Networking.Location),
				},
			}

			for _, s := range network.Subnets {
				l1 := l.WithField("subnet", s)

				l1.Debug("Deleting old subnet")
				action, _, err := h.client.Network.DeleteSubnet(ctx, network, hcloud.NetworkDeleteSubnetOpts{
					Subnet: s,
				})
				if err != nil {
					l1.WithError(err).Error("Error registering subnet deletion action")
					return nil, err
				}

				if err := h.waitForActionCompletion(ctx, action); err != nil {
					l1.WithError(err).Error("Error deleting subnet")
					return nil, err
				}
			}

			for _, s := range networkSubnets {
				l1 := l.WithField("subnet", s)

				l1.Debug("Adding new subnet")
				action, _, err := h.client.Network.AddSubnet(ctx, network, hcloud.NetworkAddSubnetOpts{
					Subnet: s,
				})
				if err != nil {
					l1.WithError(err).Error("Error registering subnet add action")
					return nil, err
				}

				if err := h.waitForActionCompletion(ctx, action); err != nil {
					l1.WithError(err).Error("Error adding subnet")
					return nil, err
				}
			}

			return network, nil
		},
	}.exec(ctx)
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
