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
	"fmt"
	"os"
	"path/filepath"

	"github.com/mrsimonemms/golang-helpers/logger"
	"github.com/mrsimonemms/k3s-manager/pkg/common"
	"github.com/mrsimonemms/k3s-manager/pkg/provider"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var clusterKubeconfigOpts struct {
	Output string
}

// clusterKubeconfigCmd represents the kubeconfig command
var clusterKubeconfigCmd = &cobra.Command{
	Use:   "kubeconfig",
	Short: "Get the cluster's kubeconfig",
	RunE: func(cmd *cobra.Command, args []string) error {
		_, p, err := loadConfigFile()
		if err != nil {
			return err
		}

		ctx := context.Background()

		nodes, err := p.NodeList(ctx, &provider.NodeListRequest{Type: common.NodeTypeManager})
		if err != nil {
			return err
		}
		if nodes == nil || len(nodes.Machines) == 0 {
			return provider.ErrNotConfigured
		}

		manager, err := p.ManagerAddress(ctx)
		if err != nil {
			return err
		}

		var kubeconfig []byte
		for _, n := range nodes.Machines {
			// Try connecting to every node before giving up
			kubeconfig, err = n.GetKubeconfig(manager.Address)
			if err != nil {
				logger.Log().WithError(err).Warn("Unable to get kubeconfig from node")
			}
			if kubeconfig != nil {
				break
			}
		}
		if kubeconfig == nil {
			logger.Log().Error("Failed to retrieve kubeconfig from managers")
			return fmt.Errorf("could not get kubeconfig")
		}

		output := clusterKubeconfigOpts.Output
		logger.Log().WithField("output", output).Debug("Output path")
		if output == "-" {
			fmt.Println(string(kubeconfig))
			return nil
		}

		dir := filepath.Dir(output)

		logger.Log().WithField("directory", dir).Debug("Ensuring directory exists")
		err = os.Mkdir(dir, 0o755)
		if err != nil && !os.IsExist(err) {
			return err
		}

		logger.Log().Debug("Writing file")
		return os.WriteFile(output, kubeconfig, 0o600)
	},
}

func init() {
	clusterCmd.AddCommand(clusterKubeconfigCmd)

	bindEnv("output", "-")
	clusterKubeconfigCmd.Flags().StringVarP(&clusterKubeconfigOpts.Output, "output", "o", viper.GetString("output"), `Location to output the kubeconfig. To sent to stdout, set to "-" `)
}
