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

package k3smanager

import (
	"context"
	"errors"

	"github.com/mrsimonemms/golang-helpers/logger"
	"github.com/mrsimonemms/k3s-manager/pkg/common"
	"github.com/mrsimonemms/k3s-manager/pkg/config"
	"github.com/mrsimonemms/k3s-manager/pkg/provider"
	"github.com/mrsimonemms/k3s-manager/pkg/ssh"
	"github.com/sirupsen/logrus"
)

type createNodeInfo struct {
	provider.Node
	provider.NodeCreateRequest
}

type destroyNodeInfo struct {
	provider.Node
	provider.NodeDeleteRequest
}

type nodesToUpdate struct {
	create  []createNodeInfo
	destroy []destroyNodeInfo
}

func ensureNodeCorrect(p provider.Provider, nodeType common.NodeType, pool config.ClusterNodePool, cfg config.Config, count int, updates *nodesToUpdate, existing map[string]provider.Node) error {
	c := p.SetClusterNodePoolDefaults(pool)

	t := createNodeInfo{
		Node: provider.NewNode(
			"", // Not known at this point
			provider.GenerateNodeName(cfg.Name, pool.Name, count),
			"", // Not known at this point
			nodeType,
			&count,
			&pool.Name,
			ssh.SSH{}, // Not known at this point
			provider.ProviderOpts{
				Location:    c.Location,
				MachineType: c.Type,
				Arch:        *c.Arch,
				Image:       *c.Image,
			},
		),
		NodeCreateRequest: provider.NodeCreateRequest{
			Count:    count,
			Pool:     pool,
			NodeType: nodeType,
		},
	}

	if e, found := existing[t.Name]; !found {
		// The node doesn't exist - set it to be created
		updates.create = append(updates.create, t)
	} else {
		delete(existing, t.Name)

		if !e.Matches(&t.Node) {
			// Node exists, but it has changes
			if nodeType == common.NodeTypeManager && pool.Count == 1 {
				logger.Log().Error("Trying to change the specification of a single node manager setup is not allowed")
				return ErrCannotChangeSingleManagerNode
			}

			// Add to both create and destroy
			updates.create = append(updates.create, t)
			updates.destroy = append(updates.destroy, destroyNodeInfo{
				Node: e,
				NodeDeleteRequest: provider.NodeDeleteRequest{
					ID: e.ID,
				},
			})
		}
	}

	return nil
}

func Check(ctx context.Context, cfg *config.Config, p provider.Provider) error {
	logger.Log().Info("Listing nodes")
	nodeList, err := p.NodeList(ctx, &provider.NodeListRequest{})
	if err != nil {
		logger.Log().WithError(err).Error("Error listing nodes")
		return err
	}

	updates := nodesToUpdate{}                 // This is what needs to change
	existing := make(map[string]provider.Node) // This is what currently exists

	for _, n := range nodeList.Machines {
		existing[n.Name] = n
	}

	// Iterate through the manager pool
	for i := 0; i < cfg.ManagerPool.Count; i++ {
		if err := ensureNodeCorrect(p, common.NodeTypeManager, cfg.ManagerPool, *cfg, i, &updates, existing); err != nil {
			return err
		}
	}

	// Iterate through the worker pools
	for _, pool := range cfg.WorkerPools {
		for i := 0; i < pool.Count; i++ {
			if err := ensureNodeCorrect(p, common.NodeTypeWorker, pool, *cfg, i, &updates, existing); err != nil {
				return err
			}
		}
	}

	// Remove existing machines that are no longer required
	for _, e := range existing {
		updates.destroy = append(updates.destroy, destroyNodeInfo{
			Node: e,
			NodeDeleteRequest: provider.NodeDeleteRequest{
				ID: e.ID,
			},
		})
	}

	for _, d := range updates.destroy {
		l := logger.Log().WithFields(logrus.Fields{
			"id": d.Node.ID,
		})

		// @todo(sje): remove node from cluster before deleting

		l.Info("Deleting node")
		_, err := p.NodeDelete(ctx, &d.NodeDeleteRequest)
		if err != nil {
			l.WithError(err).Error("Problem deleting node")
			return err
		}
	}

	for _, c := range updates.create {
		l := logger.Log().WithFields(logrus.Fields{
			"count":    c.NodeCreateRequest.Count,
			"poolName": c.NodeCreateRequest.Pool.Name,
			"nodeType": c.NodeCreateRequest.NodeType,
		})

		l.Info("Creating new node")
		_, err := p.NodeCreate(ctx, &c.NodeCreateRequest)
		if err != nil {
			l.WithError(err).Error("Problem creating new node")
			return err
		}

		// @todo(sje): add node to cluster after creating
	}

	return nil
}

func Watch() error {
	return errors.New("command not yet implemented")
}
