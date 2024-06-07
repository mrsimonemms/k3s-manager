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
	"fmt"
	"os"

	"github.com/mrsimonemms/golang-helpers/logger"
	"github.com/mrsimonemms/k3s-manager/pkg/common"
	"github.com/mrsimonemms/k3s-manager/pkg/config"
	"github.com/mrsimonemms/k3s-manager/pkg/provider"
)

type nodelist map[string][]provider.Node

type pool struct {
	machineType common.NodeType
	config      config.ClusterNodePool
	existing    []provider.Node
}

type changes struct {
	create  []target
	destroy []target
}

type target struct {
	nodeType    common.NodeType
	name        string
	location    string  // Provider-specified
	machineType string  // Provider-specified
	image       *string // Provider-specified
	arch        *string // Provider-specified
	config      config.ClusterNodePool
	existing    *provider.Node // Only populated if deleting
}

func Check(ctx context.Context, cfg *config.Config, p provider.Provider) error {
	logger.Log().Info("Listing nodes")
	nodeList, err := p.NodeList(ctx, &provider.NodeListRequest{})
	if err != nil {
		logger.Log().WithError(err).Error("Error listing nodes")
		return err
	}

	managerNodes := make(nodelist)
	workerNodes := make(nodelist)

	for _, n := range nodeList.Machines {
		if n.NodeType == common.NodeTypeManager {
			managerNodes["manager"] = append(managerNodes["manager"], n)
		} else {
			var pool string
			if n.Pool == nil {
				logger.Log().WithField("node", n.Name).Warn("Worker node with no pool information received")
				pool = "unknown"
			} else {
				pool = *n.Pool
			}

			workerNodes[pool] = append(workerNodes[pool], n)
		}
	}

	pools := make([]pool, 0)

	existingManager := make([]provider.Node, 0)
	if nodes, ok := managerNodes["manager"]; ok {
		existingManager = append(existingManager, nodes...)
	}

	pools = append(pools, pool{
		machineType: common.NodeTypeManager,
		config:      cfg.ManagerPool,
		existing:    existingManager,
	})

	for _, c := range cfg.WorkerPools {
		existing := make([]provider.Node, 0)
		if nodes, ok := workerNodes[c.Name]; ok {
			existing = append(existing, nodes...)
		}

		pools = append(pools, pool{
			machineType: common.NodeTypeWorker,
			config:      c,
			existing:    existing,
		})
	}

	delta := changes{
		create:  []target{},
		destroy: []target{},
	}

	for _, p := range pools {
		// @todo(sje): implement the managers
		if p.machineType == common.NodeTypeManager {
			continue
		}

		targets := make([]target, 0)

		for i := 0; i < p.config.Count; i++ {
			// Define the target
			targets = append(targets, target{
				nodeType:    common.NodeTypeWorker,
				name:        provider.GenerateNodeName(cfg.Name, p.config.Name, i),
				location:    p.config.Location,
				machineType: p.config.Type,
				arch:        p.config.Arch,
				image:       p.config.Image,
			})
		}

		// Search through the pool
		fmt.Printf("%+v\n", targets)
	}

	fmt.Println(delta)
	os.Exit(1)

	return nil
}

func Watch() error {
	return errors.New("command not yet implemented")
}
