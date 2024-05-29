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

package cmd

import (
	"fmt"
	"os"

	"github.com/go-playground/validator/v10"
	"github.com/mrsimonemms/golang-helpers/logger"
	"github.com/mrsimonemms/k3s-manager/pkg/config"
	"github.com/mrsimonemms/k3s-manager/pkg/provider"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var clusterOpts struct {
	Validate bool
}

// clusterCmd represents the cluster command
var clusterCmd = &cobra.Command{
	Use:   "cluster",
	Short: "Cluster management commands",
}

func loadConfigFile() (*config.Config, provider.Provider, error) {
	l := logger.Log().WithFields(logrus.Fields{
		"configFile": rootOpts.ConfigFile,
	})

	data, err := os.ReadFile(rootOpts.ConfigFile)
	if err != nil {
		l.WithError(err).Error("Failed to read config file")
		return nil, nil, err
	}

	cfg, err := config.Load(data)
	if err != nil {
		l.WithError(err).Error("Failed to load config")
		return nil, nil, err
	}

	if clusterOpts.Validate {
		if err := cfg.Validate(); err != nil {
			if validationErrors, ok := err.(validator.ValidationErrors); ok {
				for _, vErr := range validationErrors {
					l = l.WithField(vErr.StructNamespace(), vErr.ActualTag())
				}
				l.Error("Config is invalid")

				return nil, nil, fmt.Errorf("invalid config")
			} else {
				l.WithError(err).Error("Config is invalid")
			}
			return nil, nil, err
		}
	}

	l.Debug("Config is valid - executing the provider factory")

	factory, err := provider.Get(cfg.Provider.ID)
	if err != nil {
		l.WithError(err).Error("Unknown provider")
		return nil, nil, err
	}

	p, err := factory(cfg)
	if err != nil {
		l.WithError(err).Error("Error loading providing config")
		return nil, nil, err
	}

	return cfg, p, nil
}

func init() {
	rootCmd.AddCommand(clusterCmd)

	bindEnv("validate", true)
	clusterCmd.PersistentFlags().BoolVarP(&clusterOpts.Validate, "validate", "v", viper.GetBool("validate"), "Validate the config before using")
}
