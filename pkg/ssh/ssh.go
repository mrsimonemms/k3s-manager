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

package ssh

import (
	"context"
	"time"

	"github.com/appleboy/easyssh-proxy"
	"github.com/mrsimonemms/golang-helpers/logger"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type ReadyCheck func() (bool, error)

type SSH struct {
	ssh easyssh.MakeConfig
}

type CloudInitResponse struct {
	Status         string    `json:"status"`
	BootStatusCode string    `json:"boot_status_code"`
	LastUpdate     time.Time `json:"last_update"`
	Detail         string    `json:"detail"`
	Errors         []string  `json:"errors,omitempty"`
	DataSource     string    `json:"datasource"`
}

func (s *SSH) Run(command string, timeout ...time.Duration) (outStr string, errStr string, isTimeout bool, err error) {
	outStr, errStr, isTimeout, err = s.ssh.Run(command, timeout...)
	return
}

func (s *SSH) WaitUntilCloudInitReady(ctx context.Context, timeout ...time.Duration) error {
	logger.Log().Debug("Waiting for cloud-init server to become ready")

	return s.WaitUntilReady(ctx, func() (bool, error) {
		stdout, stderr, _, err := s.ssh.Run("cloud-init status -l --format yaml", time.Second)
		if err != nil {
			// Server not yet accepting SSH connections
			logger.Log().WithError(err).Debug("Cannot connect to server")
			return false, nil
		}

		logger.Log().Debug("Server connected successfully")
		logger.Log().WithFields(logrus.Fields{
			"stdout": stdout,
			"stderr": stderr,
		}).Trace("Data received")

		var status CloudInitResponse
		res := stdout
		if stdout == "" {
			res = stderr
		}
		if err := yaml.Unmarshal([]byte(res), &status); err != nil {
			// Server isn't ready
			logger.Log().WithError(err).Debug("Cloud-init has yet to finish")
			return false, nil
		}

		logger.Log().WithField("status", status).Debug("Status received from cloud-init on server")

		if status.Status == "done" {
			// The server is ready
			logger.Log().Debug("Server is ready")
			return true, nil
		}
		if status.Status == "error" {
			// The server has errored - we now need human intervention
			logger.Log().WithError(err).Debug("Cloud-init has failed")
			return false, ErrCloudInit
		}

		return false, nil
	}, timeout...)
}

func (s *SSH) WaitUntilReady(ctx context.Context, readinessCheck ReadyCheck, timeout ...time.Duration) error {
	if len(timeout) == 0 {
		timeout = []time.Duration{
			10 * time.Minute,
		}
	}

	startTime := time.Now()
	timeoutTime := startTime.Add(timeout[0])
	count := 0

	var waitErr error
	for {
		if count > 0 {
			time.Sleep(time.Second)
		}
		count += 1
		now := time.Now()

		if now.After(timeoutTime) {
			return ErrTimeout
		}

		isReady, err := readinessCheck()
		if err != nil {
			waitErr = err
			break
		}
		if isReady {
			break
		}
	}

	return waitErr
}

func New(ssh easyssh.MakeConfig) SSH {
	return SSH{
		ssh: ssh,
	}
}
