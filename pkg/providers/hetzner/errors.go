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
	"errors"
	"fmt"
)

var (
	ErrBadSSHKey               = errors.New("bad ssh key")
	ErrBadLoadBalancerConfig   = errors.New("load balancer config must have location or networkZone set")
	ErrSSHKeyNotPresent        = errors.New("ssh key not present")
	ErrUnknownImage            = errors.New("unknown server image")
	ErrUnknownLocation         = errors.New("unknown server location")
	ErrUnknownLoadBalancer     = errors.New("unknown load balancer")
	ErrUnknownLoadBalancerType = errors.New("unknown load balancer type")
	ErrUnknownServerType       = errors.New("unknown server type")
)

var errNotImplemented = errors.New("command not yet implemented")

func ensureOnlyOneResource[T any](list []*T, name string) (*T, error) {
	if len(list) == 1 {
		return list[0], nil
	}

	return nil, fmt.Errorf("resource %s not configured correctly", name)
}
