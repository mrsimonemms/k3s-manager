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
	"fmt"
	"testing"

	"github.com/mrsimonemms/k3s-manager/pkg/config"
	"github.com/stretchr/testify/assert"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		Name   string
		Config *config.Config
		Err    error
	}{
		{
			Name: "valid",
			Config: &config.Config{
				APIVersion: config.APIVersion,
				Cluster: config.Cluster{
					Name: "some-cluster",
					ManagerPool: config.ClusterNodePool{
						Name:     "name",
						Count:    1,
						Type:     "some-type",
						Location: "some-location",
					},
				},
			},
		},
		{
			Name: "invalid api version",
			Config: &config.Config{
				APIVersion: "some-bad-api-version",
				Cluster: config.Cluster{
					Name: "some-cluster",
				},
			},
			Err: config.ErrInvalidAPIVersion,
		},
		{
			Name: "invalid config",
			Config: &config.Config{
				APIVersion: config.APIVersion,
			},
			Err: fmt.Errorf("Key: 'Config.Cluster.Name' Error:Field validation for 'Name' failed on the 'required' tag"),
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			assert := assert.New(t)

			err := test.Config.Validate()

			if test.Err == nil {
				assert.NoError(err)
			} else {
				assert.Error(err, test.Err)
			}
		})
	}
}

func TestLoadFunc(t *testing.T) {
	tests := []struct {
		Name           string
		YAML           string
		ExpectedError  error
		ExpectedResult *config.Config
	}{
		{
			Name: "no error",
			YAML: `apiVersion: v1alpha1
cluster:
  name: some-name`,
			ExpectedError: nil,
			ExpectedResult: &config.Config{
				APIVersion: "v1alpha1",
				Cluster: config.Cluster{
					Name: "some-name",
				},
			},
		},
		{
			Name: "invalid api",
			YAML: `apiVersion: v1
cluster:
  name: some-name2`,
			ExpectedError:  config.ErrInvalidAPIVersion,
			ExpectedResult: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			assert := assert.New(t)

			cfg, err := config.Load([]byte(test.YAML))

			assert.Equal(test.ExpectedError, err)
			assert.Equal(test.ExpectedResult, cfg)
		})
	}
}

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
					Name: config.DefaultClusterName,
					ManagerPool: config.ClusterNodePool{
						Name:  "manager-pool",
						Count: 1,
					},
					WorkerPools: []config.ClusterNodePool{},
				},
				Provider: config.Provider{
					Config: map[string]any{},
				},
			},
		},
		{
			Name: "cluster_name",
			Env: map[string]string{
				"K3M_CLUSTER_NAME":               "some-name",
				"K3M_CLUSTER_MANAGER_POOL_NAME":  "new-manager-name",
				"K3M_CLUSTER_MANAGER_POOL_COUNT": "3",
			},
			Target: &config.Config{
				APIVersion: config.APIVersion,
				Cluster: config.Cluster{
					Name: "some-name",
					ManagerPool: config.ClusterNodePool{
						Name:  "new-manager-name",
						Count: 3,
					},
					WorkerPools: []config.ClusterNodePool{},
				},
				Provider: config.Provider{
					Config: map[string]any{},
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
