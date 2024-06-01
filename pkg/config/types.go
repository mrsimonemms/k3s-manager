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
	"github.com/go-playground/validator/v10"
	"github.com/mrsimonemms/k3s-manager/pkg/common"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

type Config struct {
	APIVersion string `json:"apiVersion" validate:"required"`

	Cluster    `json:"cluster" envPrefix:"CLUSTER_"`
	K3s        `json:"k3s" envPrefix:"K3S_"`
	Networking `json:"networking" envPrefix:"NETWORKING_"`

	Provider `json:"provider" envPrefix:"PROVIDER_"`
}

type Cluster struct {
	Name string `json:"name,omitempty" env:"NAME" validate:"required"`

	ManagerPool ClusterNodePool `json:"managerPool" envPrefix:"MANAGER_POOL_" validate:"required"`
	// @todo(sje): envPrefix not yet supported for slices
	// @link https://github.com/caarlos0/env/issues/298
	WorkerPools []ClusterNodePool `json:"workerPools" validate:"dive,required"`
}

type ClusterNodePool struct {
	Name   string      `json:"name" env:"NAME" validate:"required"`
	Count  int         `json:"count" env:"COUNT" validate:"required,gt=0"`
	Labels []NodeLabel `json:"labels,omitempty" validate:"dive,required"`
	Taints []NodeTaint `json:"taints,omitempty" validate:"dive,required"`

	// All of these values are provider-specific
	Type     string  `json:"type" env:"TYPE" validate:"required"`
	Location string  `json:"location" env:"LOCATION" validate:"required"`
	Image    *string `json:"image,omitempty" env:"IMAGE"` // If not specified, this will use the default as-specified by the provider
	Arch     *string `json:"arch,omitempty" env:"ARCH"`   // If not specified, this will use the default as-specified by the provider
}

type NodeLabel struct {
	Key   string `json:"key" env:"KEY" validate:"required"`
	Value string `json:"value" env:"VALUE" validate:"required"`
}

type NodeTaint struct {
	Key    string             `json:"key" env:"KEY" validate:"required"`
	Value  string             `json:"value" env:"VALUE" validate:"required"`
	Effect corev1.TaintEffect `json:"effect,omitempty" env:"EFFECT" validate:"taintEffect"`
}

type K3s struct {
	Datastore K3sDatastore `json:"datastore" envPrefix:"K3S_DATASTORE_" validate:"required"`
	Version   string       `json:"version,omitempty" env:"VERSION"` // If empty, uses the latest
}

type K3sDatastore struct {
	Type     K3sDatastoreType `json:"type" env:"TYPE" validate:"required"`
	Endpoint string           `json:"endpoint,omitempty" env:"ENDPOINT" validate:"required_if=Type external"`
}

type K3sDatastoreType string

const (
	K3S_DATASTORE_TYPE_ETCD     K3sDatastoreType = "etcd"
	K3S_DATASTORE_TYPE_EXTERNAL K3sDatastoreType = "external"
)

type Networking struct {
	NetworkingAllowed `json:"allowed" envPrefix:"ALLOWED_"`
	Location          string `json:"location" env:"LOCATION" validate:"required"`
	SSHPort           int    `json:"sshPort" env:"SSH_PORT" validate:"required,numeric"`
	Subnet            string `json:"subnet" env:"SUBNET" validate:"required,cidr"`
}

type NetworkingAllowed struct {
	API string `json:"api" env:"API" validate:"required,cidr"`
	SSH string `json:"ssh" env:"SSH" validate:"required,cidr"`
}

type Provider struct {
	ID     string         `json:"id" env:"ID"`
	Config map[string]any `json:"config" env:"CONFIG"` // Dependent upon the provider used
}

func (c *Config) ToYAML() ([]byte, error) {
	return yaml.Marshal(c)
}

func (c *Config) Validate() error {
	if err := ValidateAPIVersion(c.APIVersion); err != nil {
		return err
	}

	validate := validator.New(validator.WithRequiredStructEnabled())
	if err := validate.RegisterValidation("taintEffect", ValidateTaintEffect); err != nil {
		return err
	}

	return validate.Struct(c)
}

func Load(data []byte) (*Config, error) {
	cfg := &Config{}

	// Load the file
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	// API version is always validated
	if err := ValidateAPIVersion(cfg.APIVersion); err != nil {
		return nil, err
	}

	return cfg, nil
}

func New() (*Config, error) {
	// Default values
	cfg := &Config{
		APIVersion: APIVersion,
		Cluster: Cluster{
			Name: DefaultClusterName,
			ManagerPool: ClusterNodePool{
				Name:  "manager-pool",
				Count: 1,
			},
			WorkerPools: []ClusterNodePool{},
		},
		K3s: K3s{
			Datastore: K3sDatastore{
				Type: K3S_DATASTORE_TYPE_ETCD,
			},
		},
		Networking: Networking{
			NetworkingAllowed: NetworkingAllowed{
				API: GlobalCIDR,
				SSH: GlobalCIDR,
			},
			SSHPort: DefaultSSHPort,
			Subnet:  DefaultNetworkCIDR,
		},
		Provider: Provider{
			Config: map[string]any{},
		},
	}

	if err := env.ParseWithOptions(cfg, env.Options{
		Prefix: fmt.Sprintf("%s_", common.EnvPrefix),
	}); err != nil {
		return nil, err
	}

	return cfg, nil
}

// Ensure the API version is valid - this doesn't really do anything at the moment, but exists for future-proofing
func ValidateAPIVersion(version string) error {
	if version != APIVersion {
		return ErrInvalidAPIVersion
	}
	return nil
}

func ValidateTaintEffect(fl validator.FieldLevel) bool {
	vals := []corev1.TaintEffect{
		corev1.TaintEffectNoExecute,
		corev1.TaintEffectNoSchedule,
		corev1.TaintEffectPreferNoSchedule,
	}

	val := fl.Field().String()
	if val == "" {
		// Not set
		return true
	}

	for i := 0; i < len(vals); i++ {
		if string(vals[i]) == val {
			return true
		}
	}

	return false
}
