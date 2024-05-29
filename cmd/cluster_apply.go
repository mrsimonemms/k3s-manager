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

		fmt.Printf("CFG\n%+v\n", cfg)
		fmt.Printf("Provider\n%+v\n", p)

		return nil
	},
}

func init() {
	clusterCmd.AddCommand(clusterApplyCmd)
}
