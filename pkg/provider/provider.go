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

package provider

var providers map[string]Provider = map[string]Provider{}

func Get(name string) (Provider, error) {
	if provider, ok := providers[name]; ok {
		return provider, nil
	}

	return nil, ErrUnknownProvider(name)
}

func List() map[string]Provider {
	return providers
}

func Register(name string, provider Provider) error {
	if _, err := Get(name); err != nil && err != ErrUnknownProvider(name) {
		providers[name] = provider

		return nil
	}

	return ErrProviderExists(name)
}