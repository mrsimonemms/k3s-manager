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

const (
	EnvPrefix   = "K3M" // When using environment variables, this is the prefix
	MachineUser = "k3smanager"
	Namespace   = "k3smanager.dev"
)

type NodeType string

const (
	NodeTypeManager NodeType = "manager"
	NodeTypeWorker  NodeType = "worker"
)
