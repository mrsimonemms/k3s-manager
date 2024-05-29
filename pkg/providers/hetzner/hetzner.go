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

package hetzner

import (
	"context"
	"errors"

	"github.com/mrsimonemms/k3s-manager/pkg/provider"
)

type Hetzner struct{}

var errNotImplemented = errors.New("command not yet implemented")

func (h *Hetzner) ApplyCSI(context.Context) (*provider.ApplyCSIResponse, error) {
	return nil, errNotImplemented
}

func (h *Hetzner) DatastoreCreate(context.Context) (*provider.DatastoreCreateResponse, error) {
	return nil, errNotImplemented
}

func (h *Hetzner) DatastoreDelete(context.Context) (*provider.DatastoreDeleteResponse, error) {
	return nil, errNotImplemented
}

func (h *Hetzner) LoadBalancerCreate(context.Context) (*provider.LoadBalancerCreateResponse, error) {
	return nil, errNotImplemented
}

func (h *Hetzner) LoadBalancerDelete(context.Context) (*provider.LoadBalancerDeleteResponse, error) {
	return nil, errNotImplemented
}

func (h *Hetzner) NodeCreate(context.Context) (*provider.NodeCreateResponse, error) {
	return nil, errNotImplemented
}

func (h *Hetzner) NodeDelete(context.Context) (*provider.NodeDeleteResponse, error) {
	return nil, errNotImplemented
}

func (h *Hetzner) Prepare(context.Context) (*provider.PrepareResponse, error) {
	return nil, errNotImplemented
}
