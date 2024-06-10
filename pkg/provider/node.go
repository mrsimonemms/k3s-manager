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

package provider

import (
	"fmt"

	"github.com/mrsimonemms/golang-helpers/logger"
	"github.com/mrsimonemms/k3s-manager/pkg/common"
	"github.com/mrsimonemms/k3s-manager/pkg/k3s"
	"github.com/mrsimonemms/k3s-manager/pkg/ssh"
	"github.com/sirupsen/logrus"
)

// This is used to normalise the identification of a node and it's parameters.
// Typically, this data will either be known to the provider or will be taken
// from labels/tags set to the node.
type Node struct {
	ID       string // This is a unique ID set by the provider
	Name     string
	NodeType common.NodeType
	Address  string
	SSH      ssh.SSH // This allows direct connection with the machine

	PoolName *string // Only populated for worker nodes
	Count    *int    // Use a pointer to ensure values are set

	ProviderOpts // All values are decided by the provider
}

type ProviderOpts struct {
	Location    string
	MachineType string
	Arch        string
	Image       string
}

func (n *Node) GetKubeconfig(kubeconfigHost string) ([]byte, error) {
	if n.NodeType != common.NodeTypeManager {
		return nil, ErrNotManager
	}

	return k3s.GetKubeconfig(n.SSH, kubeconfigHost)
}

func (n *Node) GetJoinToken() ([]byte, error) {
	if n.NodeType != common.NodeTypeManager {
		return nil, ErrNotManager
	}

	return k3s.GetJoinToken(n.SSH)
}

// Do the parameters that matter match?
func (n *Node) Matches(node *Node) bool {
	if n.Name != node.Name {
		logger.Logger.WithFields(logrus.Fields{
			"current": n.Name,
			"target":  node.Name,
		}).Debug("Node names don't match")
		return false
	}
	if n.NodeType != node.NodeType {
		logger.Logger.WithFields(logrus.Fields{
			"current": n.NodeType,
			"target":  node.NodeType,
		}).Debug("Node types don't match")
		return false
	}
	// Pool name only set for work nodes
	if n.PoolName != nil && node.PoolName != nil {
		if *n.PoolName != *node.PoolName {
			logger.Logger.WithFields(logrus.Fields{
				"current": *n.PoolName,
				"target":  *node.PoolName,
			}).Debug("Pool names don't match")
			return false
		}
	}
	if *n.Count != *node.Count {
		logger.Logger.WithFields(logrus.Fields{
			"current": *n.Count,
			"target":  *node.Count,
		}).Debug("Node counts don't match")
		return false
	}
	if n.ProviderOpts != node.ProviderOpts {
		logger.Logger.WithFields(logrus.Fields{
			"current": n.ProviderOpts,
			"target":  node.ProviderOpts,
		}).Debug("Node provider options don't match")
		return false
	}

	// Everything we care about matches - bingo bango!
	return true
}

func NewNode(id, name, address string, nodeType common.NodeType, count *int, poolName *string, ssh ssh.SSH, providerOpts ProviderOpts) Node {
	if nodeType != common.NodeTypeWorker {
		poolName = nil
	}

	return Node{
		ID:           id,
		Name:         name,
		Address:      address,
		NodeType:     nodeType,
		PoolName:     poolName,
		Count:        count,
		SSH:          ssh,
		ProviderOpts: providerOpts,
	}
}

func GenerateNodeName(clusterName, poolName string, count int) string {
	return fmt.Sprintf("%s-%s-%d", clusterName, poolName, count)
}
