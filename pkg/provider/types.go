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
	"context"

	"github.com/mrsimonemms/k3s-manager/pkg/common"
	"github.com/mrsimonemms/k3s-manager/pkg/config"
)

type Provider interface {
	// CSI management
	//
	// A Container Storage Interface allows Kubernetes to use volumes provided
	// by the cloud provider
	//
	// @link https://kubernetes.io/blog/2019/01/15/container-storage-interface-ga/
	ApplyCSI(context.Context) (*ApplyCSIResponse, error) // Apply the CSI to the cluster

	// Datastore management
	//
	// K3s requires a datastore for workload management. This command is only
	// used if not using in-cluster etcd.
	//
	// This may not be provided by all providers
	//
	// @link https://docs.k3s.io/datastore
	DatastoreCreate(context.Context) (*DatastoreCreateResponse, error) // Create the datastore
	DatastoreDelete(context.Context) (*DatastoreDeleteResponse, error) // Delete the datastore

	// Provider secrets
	//
	// Returns any secrets required to make the in-cluster part
	// of the application work. This could be anything that is
	// inferred from the provider config section, such as the content
	// of an SSH key
	GetProviderSecrets(context.Context) (map[string]string, error)

	// Load balancer management
	//
	// Load balancers are used for multi-node manager clusters and may be
	// used by worker nodes.
	LoadBalancerCreate(context.Context) (*LoadBalancerCreateResponse, error)
	LoadBalancerDelete(context.Context) (*LoadBalancerDeleteResponse, error)

	// Node management
	//
	// Nodes are the servers in the cluster. They can be managers or
	// workers and may be manually or automatically scaled. At it's
	// smallest, there must be at least one manager node.
	ManagerAddress(context.Context) (*ManagerAddressResponse, error)
	NodeCreate(context.Context, *NodeCreateRequest) (*NodeCreateResponse, error)
	NodeDelete(context.Context, *NodeDeleteRequest) (*NodeDeleteResponse, error)
	NodeList(context.Context, *NodeListRequest) (*NodeListResponse, error)

	// Prepare
	//
	// Prepare the cloud for installing K3s. This typically would
	// involve ensuring a network, a firewall and at least one server.
	// This must be an idempotent command that ensures these things
	// exist.
	Prepare(context.Context) (*PrepareResponse, error)

	// Ensures that any non-required cluster node pool data has provider defaults set
	SetClusterNodePoolDefaults(config.ClusterNodePool) config.ClusterNodePool
}

type ApplyCSIResponse struct{}

type DatastoreCreateResponse struct{}

type DatastoreDeleteResponse struct{}

type LoadBalancerCreateResponse struct{}

type LoadBalancerDeleteResponse struct{}

type ManagerAddressResponse struct {
	Address string
}

type NodeCreateRequest struct {
	Count    int
	Pool     config.ClusterNodePool
	NodeType common.NodeType
}

type NodeCreateResponse struct {
	Node Node
}

type NodeDeleteRequest struct {
	ID   string
	Pool config.ClusterNodePool
}

type NodeDeleteResponse struct {
	ID string
}
