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

	"github.com/sirupsen/logrus"
)

type (
	upsertCreateFn[T any] func(context.Context) (*T, error)
	upsertListFn[T any]   func(context.Context) ([]*T, error)
	upsertUpdateFn[T any] func(context.Context, *T) (*T, error)
)

type upsert[T any] struct {
	resourceType string
	logger       *logrus.Entry
	getId        func(*T) any

	// Searches for a matching resource - errors if not 1 returned
	list upsertListFn[T]
	// Creates a new resource
	create upsertCreateFn[T]
	// Ensures that the created/updated come out with the same configuration
	update upsertUpdateFn[T]
}

func (u upsert[T]) exec(ctx context.Context) (*T, error) {
	var resource *T

	l := u.logger.WithField("resource", u.resourceType)

	l.Info("Ensuring resource exists")
	resources, err := u.list(ctx)
	if err != nil {
		l.WithError(err).Error("Error listing resource")
		return nil, err
	}

	foundResources := len(resources)
	l.WithField("count", foundResources).Debug("Number of resources returned")
	if foundResources > 1 {
		// Found multiple matching resources - error to avoid a collision
		return nil, ErrMultipleCandidates(u.resourceType)
	}
	if foundResources == 0 {
		// Nothing found - create a resource
		l.Debug("Creating new resource")
		resource, err = u.create(ctx)
		if err != nil {
			// Error creating resource
			l.WithError(err).Error("Error creating resource")
			return nil, err
		}
	} else {
		resource = resources[0]
	}

	if u.getId != nil {
		l = l.WithField("id", u.getId(resource))
	}

	l.Debug("Updating resource with current config")

	// Now update the resource so it reflects the config provided
	resource, err = u.update(ctx, resource)
	if err != nil {
		l.WithError(err).Error("Error updating qresource")
		return nil, err
	}

	l.Info("Resource exists and is ready to use")

	return resource, nil
}
