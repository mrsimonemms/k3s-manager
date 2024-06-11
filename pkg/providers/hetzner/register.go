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
	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/mitchellh/mapstructure"
	"github.com/mrsimonemms/golang-helpers/logger"
	"github.com/mrsimonemms/k3s-manager/pkg/config"
	"github.com/mrsimonemms/k3s-manager/pkg/provider"
	"github.com/sirupsen/logrus"
)

func init() {
	if err := provider.Register(Name, factory); err != nil {
		logger.Log().WithField("name", Name).WithError(err).Panic("Provider name already registered")
	}
}

type debugWriter struct {
	logger *logrus.Entry
}

func (d *debugWriter) Write(p []byte) (n int, err error) {
	d.logger.WithField("data", string(p)).Trace("Hetzner API call")

	return len(p), nil
}

func factory(k3m *config.Config) (provider.Provider, error) {
	l := logger.Log().WithField("provider", Name)

	l.Debug("Loading provider")

	// Load with sensible defaults
	var cfg Config
	if err := mapstructure.Decode(k3m.Provider.Config, &cfg); err != nil {
		return nil, err
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	if err := cfg.load(); err != nil {
		return nil, err
	}

	return &Hetzner{
		client: hcloud.NewClient(
			hcloud.WithToken(cfg.Token),
			hcloud.WithDebugWriter(&debugWriter{
				logger: l,
			}),
		),
		cfg:         k3m,
		providerCfg: cfg,
		logger:      l,
	}, nil
}
