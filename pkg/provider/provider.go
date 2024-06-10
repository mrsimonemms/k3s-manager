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
)

type Factory func(*config.Config) (Provider, error)

var providers map[string]Factory = make(map[string]Factory)

func Get(name string) (Factory, error) {
	if provider, ok := providers[name]; ok {
		return provider, nil
	}

	return nil, ErrUnknownProvider(name)
}

func List() map[string]Factory {
	return providers
}

func Register(name string, provider Factory) error {
	if _, err := Get(name); err != nil && err != ErrUnknownProvider(name) {
		providers[name] = provider

		return nil
	}

	return ErrProviderExists(name)
}

func ensureOneManager(managers []Node) (*Node, error) {
	// @todo(sje): find a nicer way of handling multiple managers
	if len(managers) != 1 {
		return nil, ErrNotOneManagerProvided
	}

	return &managers[0], nil
}

// EnsureK3s applies K3s to the specified manager clusters to the given configuration
func EnsureK3s(ctx context.Context, cfg *config.Config, managers []Node, kubeconfigHost string) error {
	manager, err := ensureOneManager(managers)
	if err != nil {
		return err
	}

	l := logger.Log().WithField("kubehost", kubeconfigHost)

	l.Info("Waiting for manager to become ready")
	if err := manager.SSH.WaitUntilCloudInitReady(ctx); err != nil {
		return err
	}
	l.Info("Manager ready")

	command := k3s.K3s{
		IsAgent:    false,
		JoinToken:  nil, // Initial manager
		NodeLabels: cfg.ManagerPool.Labels,
		NodeTaints: cfg.ManagerPool.Taints,
		TLSSANs:    []string{kubeconfigHost},

		K3sVersion: "", // @todo(sje): add version
	}

	l.Info("Installing K3s")
	_, stderr, _, err := manager.SSH.Run(command.GenerateInstallCommand(), time.Minute*5)
	if err != nil {
		l.WithError(err).WithField("stderr", stderr).Error("Error executing k3s install script")
		return err
	}

	l.Debug("Ensuring k3s is started")
	_, stderr, _, err = manager.SSH.Run("sudo systemctl start k3s", time.Minute*5)
	if err != nil {
		l.WithError(err).WithField("stderr", stderr).Error("Error executing k3s install script")
		return err
	}

	l.Info("K3s is installed to the manager node")

	return nil
}

func GetK3sAccessSecrets(managers []Node, kubeconfigHost string) (*K3sAccessSecrets, error) {
	manager, err := ensureOneManager(managers)
	if err != nil {
		return nil, err
	}

	kubeconfig, err := manager.GetKubeconfig(kubeconfigHost)
	if err != nil {
		return nil, err
	}

	joinToken, err := manager.GetJoinToken()
	if err != nil {
		return nil, err
	}

	return &K3sAccessSecrets{
		JoinToken:  joinToken,
		Kubeconfig: kubeconfig,
	}, nil
}
