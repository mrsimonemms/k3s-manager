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
	"fmt"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
)

const (
	Name         = "hetzner"
	DefaultImage = "ubuntu-24.04"
	DefaultArch  = string(hcloud.ArchitectureX86)
)

type LabelKey string

const (
	LabelKeyCluster LabelKey = "cluster"
	LabelKeyType    LabelKey = "type"
	LabelKeyPool    LabelKey = "pool"
	LabelKeyCount   LabelKey = "count"
)

var ErrMultipleCandidates = func(resource string) error {
	return fmt.Errorf("multiple %s resources exist", resource)
}
