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
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"github.com/mrsimonemms/k3s-manager/pkg/common"
)

type labelSelector map[string]string

func (l labelSelector) Validate() error {
	m := make(map[string]any, 0)

	for k, v := range l {
		m[k] = v
	}

	_, err := hcloud.ValidateResourceLabels(m)

	return err
}

func (l labelSelector) String() string {
	labels := make([]string, 0)

	for k, v := range escapeLabels(l) {
		labels = append(labels, fmt.Sprintf("%s=%s", k, v))
	}

	return strings.Join(labels, ",")
}

func escapeLabels(labels map[string]string) map[string]string {
	escaped := make(map[string]string, len(labels))

	for k, v := range labels {
		escaped[k] = v
	}

	return escaped
}

func generateLabelKey(key LabelKey) string {
	return fmt.Sprintf("%s/%s", common.Namespace, key)
}

func generateSSHKeyFingerprint(publicKey string) (fingerprint string, err error) {
	parts := strings.Fields(publicKey)
	if len(parts) < 2 {
		err = ErrBadSSHKey
		return
	}

	k, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return
	}

	fp := md5.Sum([]byte(k))
	for i, b := range fp {
		fingerprint += fmt.Sprintf("%02x", b)
		if i < len(fp)-1 {
			fingerprint += ":"
		}
	}

	return
}
