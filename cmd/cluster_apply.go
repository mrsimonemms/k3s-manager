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
	"context"

	"github.com/mrsimonemms/golang-helpers/logger"
	"github.com/spf13/cobra"
)

// clusterApplyCmd represents the create command
var clusterApplyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Apply configuration to a cluster",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, p, err := loadConfigFile()
		if err != nil {
			return err
		}

		ctx := context.Background()

		// Prepare the cloud provider. This is provider-specific, so will
		// be different for each, but likely be a case of ensuring a network,
		// firewall and initial server.
		logger.Log().Debug("Preparing cloud provider")
		prepare, err := p.Prepare(ctx)
		if err != nil {
			logger.Log().WithError(err).Error("Error preparing cloud")
			return err
		}

		if err := prepare.EnsureK3sManager(ctx, cfg); err != nil {
			logger.Log().WithError(err).Error("Error ensuring K3s manager")
			return err
		}

		return nil
	},
}

func init() {
	clusterCmd.AddCommand(clusterApplyCmd)
}
