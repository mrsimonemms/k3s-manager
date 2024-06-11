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

package common

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
)

var ErrTimeout = errors.New("ssh timeout")

type ReadyCheck func() (bool, error)

func AppendRandomString(str string, length float64) string {
	return fmt.Sprintf("%s-%s", str, RandomString(length))
}

func Ptr[T any](p T) *T {
	return &p
}

func RandomString(length float64) string {
	// UUIDs are 32 characters long - work out how many we need to generate
	gens := math.Ceil(length / 32)

	var rand string
	for i := 0; i < int(gens); i++ {
		rand += strings.Replace(uuid.New().String(), "-", "", -1)
	}

	return rand[0:int(length)]
}

func WaitUntilReady(ctx context.Context, readinessCheck ReadyCheck, timeout ...time.Duration) error {
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
