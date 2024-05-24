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

package config_test

import (
	"testing"

	"github.com/mrsimonemms/k3s-manager/pkg/config"
	"github.com/stretchr/testify/assert"
)

func TestNewFunc(t *testing.T) {
	tests := []struct {
		Name   string
		Env    map[string]string
		Target *config.Config
	}{
		{
			Name: "default",
			Target: &config.Config{
				APIVersion: config.APIVersion,
				Cluster: config.Cluster{
					Name: "k3s-manager",
				},
			},
		},
		{
			Name: "cluster_name",
			Env: map[string]string{
				"K3M_CLUSTER_NAME": "some-name",
			},
			Target: &config.Config{
				APIVersion: config.APIVersion,
				Cluster: config.Cluster{
					Name: "some-name",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			for key, value := range test.Env {
				t.Setenv(key, value)
			}

			assert := assert.New(t)

			cfg, err := config.New()

			assert.Nil(err)
			assert.Equal(cfg, test.Target)
		})
	}
}
