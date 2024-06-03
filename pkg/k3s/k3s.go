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

package k3s

import (
	"fmt"
	"strings"

	"github.com/mrsimonemms/k3s-manager/pkg/config"
	"github.com/mrsimonemms/k3s-manager/pkg/ssh"
	v1 "k8s.io/api/core/v1"
)

const (
	K3S_DOWNLOAD_URL = "https://get.k3s.io"
)

type K3s struct {
	// Common
	DownloadURL *string // Allow for getting K3s from a different source

	// K3s Install Exec command
	IsAgent    bool    // Can either be a server (manager) or agent (worker).
	JoinToken  *string // All servers (except the initial) need a join token
	NodeLabels []config.NodeLabel
	NodeTaints []config.NodeTaint
	TLSSANs    []string

	K3sVersion string
}

func (k *K3s) installExec() string {
	c := make([]string, 0)

	if k.IsAgent {
		// Agent-specific commands
		c = append(c, "agent")
	} else {
		// Server-specific commands
		c = append(c, "server")
	}

	for _, n := range k.NodeLabels {
		c = append(c, fmt.Sprintf("--node-label=%s=%s", n.Key, n.Value))
	}

	for _, n := range k.NodeTaints {
		if n.Effect == "" {
			n.Effect = v1.TaintEffectNoSchedule
		}
		c = append(c, fmt.Sprintf("--node-taint=%s=%s:%s", n.Key, n.Value, n.Effect))
	}

	for _, t := range k.TLSSANs {
		c = append(c, fmt.Sprintf("--tls-san=%s", t))
	}

	c = append(c, "--write-kubeconfig-mode=0644")

	c = append(c, "--disable servicelb")
	c = append(c, "--disable traefik")

	c = append(c, fmt.Sprintf("--node-name=%s", "$(hostname -f)"))
	c = append(c, fmt.Sprintf("--node-external-ip=%s", "$(hostname -I | awk '{print $1}')"))
	c = append(c, fmt.Sprintf("--node-ip=%s", "$(hostname -I | awk '{print $2}')"))
	c = append(c, fmt.Sprintf("--advertise-address=%s", "$(hostname -I | awk '{print $2}')"))

	return strings.Join(c, " ")
}

func (k *K3s) installOpts() string {
	c := make(map[string]string, 0)

	c["INSTALL_K3S_VERSION"] = k.K3sVersion

	if k.JoinToken != nil {
		c["K3S_TOKEN"] = *k.JoinToken
	}

	var s string
	for k, v := range c {
		if s != "" {
			s += " "
		}

		s += fmt.Sprintf(`%s="%s"`, k, v)
	}

	return s
}

func (k *K3s) GenerateInstallCommand() string {
	downloadUrl := K3S_DOWNLOAD_URL
	if k.DownloadURL != nil {
		downloadUrl = *k.DownloadURL
	}

	return fmt.Sprintf(`curl -sfL %s | INSTALL_K3S_EXEC="%s" %s sh -`, downloadUrl, k.installExec(), k.installOpts())
}

func GetKubeconfig(s ssh.SSH, publicAddress string) ([]byte, error) {
	stdout, _, _, err := s.Run("sudo cat /etc/rancher/k3s/k3s.yaml")
	if err != nil {
		return nil, err
	}

	kubeconfig := strings.NewReplacer(
		"127.0.0.1", publicAddress,
		"localhost", publicAddress,
	)

	return []byte(kubeconfig.Replace(stdout)), nil
}

func GetJoinToken(s ssh.SSH) ([]byte, error) {
	stdout, _, _, err := s.Run("sudo cat /var/lib/rancher/k3s/server/token")
	if err != nil {
		return nil, err
	}

	return []byte(stdout), nil
}
