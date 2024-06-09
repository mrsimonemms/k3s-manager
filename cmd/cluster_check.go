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

	"github.com/mrsimonemms/k3s-manager/pkg/k3smanager"
	"github.com/spf13/cobra"
)

// clusterCheckCmd represents the check command
var clusterCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Check the cluster status and apply any changes",
	Long: `Check the cluster status and apply any changes. This may
be run from either inside or outside the cluster, but it
will not watch for changes over time.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, p, err := loadConfigFile()
		if err != nil {
			return err
		}

		ctx := context.Background()

		return k3smanager.Check(ctx, cfg, p)
	},
}

func init() {
	clusterCmd.AddCommand(clusterCheckCmd)
}
