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

	"github.com/mrsimonemms/k3s-manager/pkg/common"
	"github.com/mrsimonemms/k3s-manager/pkg/k3s"
	"github.com/mrsimonemms/k3s-manager/pkg/ssh"
)

type Node struct {
	Name        string
	NodeType    common.NodeType
	Address     string
	Location    string  // Populated by the provider
	MachineType string  // Populated by the provider
	SSH         ssh.SSH // This allows direct connection with the machine
	Count       *int    // Use pointer to ensure values are set
	Pool        *string // Only populated for worker nodes
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

func NewNode(name, address string, nodeType common.NodeType, machineType, location string, count *int, pool *string, ssh ssh.SSH) Node {
	if nodeType != common.NodeTypeWorker {
		pool = nil
	}
	return Node{
		Name:        name,
		Address:     address,
		NodeType:    nodeType,
		MachineType: machineType,
		Location:    location,
		Count:       count,
		Pool:        pool,
		SSH:         ssh,
	}
}

func GenerateNodeName(clusterName, poolName string, count int) string {
	return fmt.Sprintf("%s-%s-%d", clusterName, poolName, count)
}