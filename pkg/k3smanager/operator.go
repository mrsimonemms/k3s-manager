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

package k3smanager

import (
	"context"
	"errors"
	"fmt"

	"github.com/mrsimonemms/golang-helpers/logger"
	"github.com/mrsimonemms/k3s-manager/pkg/config"
	"github.com/mrsimonemms/k3s-manager/pkg/provider"
)

func Check(ctx context.Context, cfg *config.Config, p provider.Provider) error {
	logger.Log().Info("List nodes")
	nodeList, err := p.NodeList(ctx, &provider.NodeListRequest{})
	if err != nil {
		logger.Log().WithError(err).Error("Error listing nodes")
		return err
	}

	// @todo(sje): check manager nodes
	fmt.Printf("%+v\n", nodeList)
	for _, n := range cfg.WorkerPools {
		fmt.Printf("%+v\n", n.Count)
	}

	return nil
}

func Watch() error {
	return errors.New("command not yet implemented")
}
