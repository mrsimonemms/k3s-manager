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
	"time"

	"github.com/mrsimonemms/golang-helpers/logger"
	"github.com/mrsimonemms/k3s-manager/pkg/config"
	"github.com/mrsimonemms/k3s-manager/pkg/k3s"
	"github.com/mrsimonemms/k3s-manager/pkg/ssh"
)

type PrepareResponse struct {
	Managers []PrepareResponseServer
	TLSSANs  []string
}

type PrepareResponseServer struct {
	SSH ssh.SSH
}

// EnsureK3sManager applies K3s to the specified manager clusters to the given configuration
func (p *PrepareResponse) EnsureK3sManager(ctx context.Context, cfg *config.Config) error {
	// @todo(sje): find a nicer way of handling multiple managers
	if len(p.Managers) != 1 {
		return ErrNotOneManagerProvided
	}

	manager := p.Managers[0]

	logger.Log().Info("Waiting for manager to become ready")
	if err := manager.SSH.WaitUntilCloudInitReady(ctx); err != nil {
		return err
	}
	logger.Log().Info("Manager ready")

	command := k3s.K3s{
		IsAgent:    false,
		JoinToken:  nil, // Initial manager
		NodeLabels: cfg.ManagerPool.Labels,
		NodeTaints: cfg.ManagerPool.Taints,
		TLSSANs:    p.TLSSANs,

		K3sVersion: "", // @todo(sje): add version
	}

	logger.Log().Info("Installing K3s")
	_, stderr, _, err := manager.SSH.Run(command.GenerateInstallCommand(), time.Minute*5)
	if err != nil {
		logger.Log().WithError(err).WithField("stderr", stderr).Error("Error executing k3s install script")
		return err
	}

	logger.Log().Debug("Ensuring k3s is started")
	_, stderr, _, err = manager.SSH.Run("sudo systemctl start k3s", time.Minute*5)
	if err != nil {
		logger.Log().WithError(err).WithField("stderr", stderr).Error("Error executing k3s install script")
		return err
	}

	logger.Log().Info("K3s is installed to the manager node")

	return nil
}
