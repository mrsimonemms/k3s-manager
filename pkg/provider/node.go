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
	"github.com/mrsimonemms/k3s-manager/pkg/common"
	"github.com/mrsimonemms/k3s-manager/pkg/k3s"
	"github.com/mrsimonemms/k3s-manager/pkg/ssh"
)

type Node struct {
	Name    string
	Type    common.NodeType
	Address string
	SSH     ssh.SSH // This allows direct connection with the machine
}

func (n *Node) GetKubeconfig(kubeconfigHost string) ([]byte, error) {
	if n.Type != common.NodeTypeManager {
		return nil, ErrNotManager
	}

	return k3s.GetKubeconfig(n.SSH, kubeconfigHost)
}

func (n *Node) GetJoinToken() ([]byte, error) {
	if n.Type != common.NodeTypeManager {
		return nil, ErrNotManager
	}

	return k3s.GetJoinToken(n.SSH)
}

func NewNode(name, address string, machineType common.NodeType, ssh ssh.SSH) Node {
	return Node{
		Name:    name,
		Address: address,
		Type:    machineType,
		SSH:     ssh,
	}
}
