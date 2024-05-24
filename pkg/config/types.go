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

package config

import (
	"fmt"

	"github.com/caarlos0/env/v11"
	"github.com/mrsimonemms/k3s-manager/pkg/common"
	"sigs.k8s.io/yaml"
)

type Config struct {
	APIVersion string `json:"apiVersion"`

	Cluster `json:"cluster" envPrefix:"CLUSTER_"`
}

type Cluster struct {
	Name string `json:"name,omitempty" env:"NAME" envDefault:"k3s-manager"`
}

func (c *Config) ToYAML() ([]byte, error) {
	return yaml.Marshal(c)
}

func Load() (*Config, error) {
	return nil, nil
}

func New() (*Config, error) {
	cfg := &Config{
		APIVersion: APIVersion,
	}

	if err := env.ParseWithOptions(cfg, env.Options{
		Prefix: fmt.Sprintf("%s_", common.EnvPrefix),
	}); err != nil {
		return nil, err
	}

	return cfg, nil
}
