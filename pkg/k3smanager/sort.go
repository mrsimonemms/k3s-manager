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

package k3smanager

import (
	"regexp"
	"sort"
	"strings"

	"helm.sh/helm/v3/pkg/releaseutil"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

type SortableObject struct {
	metav1.TypeMeta `json:",inline"`
	Metadata        metav1.ObjectMeta `json:"metadata"`
	Content         string            `json:"-"`
}

// Based on the Helm install sort order, order the objects
func SortByKind(objects []SortableObject) ([]SortableObject, error) {
	sortMap := map[string]int{}
	for k, v := range releaseutil.InstallOrder {
		sortMap[v] = k
	}

	sort.SliceStable(objects, func(i, j int) bool {
		scoreI := sortMap[objects[i].Kind]
		scoreJ := sortMap[objects[j].Kind]

		if scoreI == scoreJ {
			return objects[i].Metadata.Name < objects[j].Metadata.Name
		}

		return scoreI < scoreJ
	})

	return objects, nil
}

// Converts the YAML into sortable objects
func YAMLToSortableObjects(templates []string) ([]SortableObject, error) {
	sortedObjects := make([]SortableObject, 0)

	for _, o := range templates {
		// Assume multi-document YAML
		re := regexp.MustCompile("(^|\n)---")
		items := re.Split(o, -1)

		for _, p := range items {
			var v SortableObject
			err := yaml.Unmarshal([]byte(p), &v)
			if err != nil {
				return nil, err
			}

			// remove any empty charts
			ctnt := strings.Trim(p, "\n")
			if len(strings.TrimSpace(ctnt)) == 0 {
				continue
			}

			v.Content = ctnt
			sortedObjects = append(sortedObjects, v)
		}
	}

	return sortedObjects, nil
}
