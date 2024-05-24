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
	"errors"
	"fmt"
	"os"

	"github.com/mrsimonemms/k3s-manager/pkg/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var configInitOpts struct {
	Force  bool
	Output string
}

// configInitCmd represents the init command
var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Create a new config file",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.New()
		if err != nil {
			return err
		}

		yaml, err := cfg.ToYAML()
		if err != nil {
			return err
		}

		_, err = os.Stat(configInitOpts.Output)
		if !errors.Is(err, os.ErrNotExist) && !configInitOpts.Force {
			return fmt.Errorf("cannot overwrite file: %s", configInitOpts.Output)
		}

		return os.WriteFile(configInitOpts.Output, yaml, 0o644)
	},
}

func init() {
	configCmd.AddCommand(configInitCmd)

	bindEnv("force", false)
	configInitCmd.Flags().BoolVarP(&configInitOpts.Force, "force", "f", viper.GetBool("force"), "Overwrite config file")

	bindEnv("output", defaultConfigFile)
	configInitCmd.Flags().StringVarP(&configInitOpts.Output, "output", "o", viper.GetString("output"), "Name of config file to create")
}
