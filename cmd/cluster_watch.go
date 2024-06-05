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
	"github.com/mrsimonemms/k3s-manager/pkg/k3smanager"
	"github.com/spf13/cobra"
)

// clusterWatchCmd represents the run command
var clusterWatchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Watch for required changes over time",
	Long: `A long-running command to watch for cluster changes. This
will typically run in the Kubernetes cluster and watch for
changes required over time.`,
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return k3smanager.Watch()
	},
}

func init() {
	clusterCmd.AddCommand(clusterWatchCmd)
}
