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

	"github.com/spf13/cobra"
)

// clusterDeleteCmd represents the destroy command
var clusterDeleteCmd = &cobra.Command{
	Use:     "delete",
	Short:   "Delete a cluster",
	Aliases: []string{"destroy"},
	RunE: func(cmd *cobra.Command, args []string) error {
		_, p, err := loadConfigFile()
		if err != nil {
			return err
		}

		ctx := context.Background()

		// We don't need to carefully delete things - just destroy everything
		return p.DeleteAllResources(ctx)
	},
}

func init() {
	clusterCmd.AddCommand(clusterDeleteCmd)
}
