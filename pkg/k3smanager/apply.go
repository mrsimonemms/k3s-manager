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
	"bytes"
	"context"
	"embed"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/Masterminds/sprig/v3"
	"github.com/mrsimonemms/golang-helpers/logger"
	"github.com/mrsimonemms/k3s-manager/pkg/common"
	"github.com/mrsimonemms/k3s-manager/pkg/config"
	"github.com/mrsimonemms/k3s-manager/pkg/provider"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/yaml"
	yamlutil "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/clientcmd"
)

//go:embed templates/*.yaml
var templates embed.FS

type Kubeclient struct {
	Config        *rest.Config
	Clientset     *kubernetes.Clientset
	DynamicClient *dynamic.DynamicClient
}

type TemplateData struct {
	Config          *config.Config
	JoinToken       string
	ProviderSecrets map[string]string
}

func login(kubeconfig []byte) (*Kubeclient, error) {
	var l *logrus.Entry
	var err error
	var config *rest.Config

	if kubeconfig == nil {
		// Login with in-cluster workflow
		l = logger.Log().WithField("method", "in-cluster")
		l.Debug("Logging into cluster")

		config, err = rest.InClusterConfig()
		if err != nil {
			l.WithError(err).Error("Failed to login")
			return nil, err
		}
	} else {
		// Kubeconfig provided - login with out-of-cluster workflow
		l = logger.Log().WithField("method", "out-of-cluster")
		l.Debug("Logging into cluster")

		file, err := os.CreateTemp("", "kubeconfig")
		if err != nil {
			l.WithError(err).Error("Failed to create temp file")
			return nil, err
		}

		l = l.WithField("file", file.Name())

		if _, err := file.Write(kubeconfig); err != nil {
			l.WithError(err).Error("Failed to write kubeconfig")
			return nil, err
		}

		defer func() {
			l.WithField("filename", file.Name()).Debug("Deleting kubeconfig tempfile")
			err = os.Remove(file.Name())
		}()

		l.Debug("Logging into cluster")
		config, err = clientcmd.BuildConfigFromFlags("", file.Name())
		if err != nil {
			return nil, err
		}
	}

	l.Debug("Getting kubernetes client")
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	dd, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &Kubeclient{
		Config:        config,
		Clientset:     clientset,
		DynamicClient: dd,
	}, err
}

func ParseTemplates(data TemplateData) (*string, error) {
	tpl, err := template.New("k8s").
		Funcs(sprig.FuncMap()).
		Funcs(helmFuncs).
		ParseFS(templates, "templates/*.yaml")
	if err != nil {
		return nil, err
	}

	files := make([]string, 0)
	if err := fs.WalkDir(templates, ".", func(path string, d fs.DirEntry, err error) error {
		if d.IsDir() {
			return nil
		}

		file, _ := strings.CutPrefix(path, "templates/")

		var output bytes.Buffer
		if err := tpl.ExecuteTemplate(&output, file, data); err != nil {
			return err
		}

		c := fmt.Sprintf("# %s\n", file)
		c += output.String()
		files = append(files, c)

		return nil
	}); err != nil {
		return nil, err
	}

	// Convert all the YAML into sortable RuntimeObjects
	o, err := YAMLToSortableObjects(files)
	if err != nil {
		return nil, err
	}

	// Sort the objects
	s, err := SortByKind(o)
	if err != nil {
		return nil, err
	}

	// Now put it back together in the correct order
	var output string
	for _, i := range s {
		output += "---\n"
		output += i.Content
		output += "\n"
	}

	return common.Ptr(output), nil
}

// Apply will only be run from outside the cluster
func Apply(ctx context.Context, cfg *config.Config, secrets *provider.K3sAccessSecrets, providerSecrets map[string]string) error {
	logger.Log().Info("Applying k3smanager resources to the cluster")
	kubeconfig, err := login(secrets.Kubeconfig)
	if err != nil {
		return err
	}

	if providerSecrets == nil {
		providerSecrets = make(map[string]string)
	}

	templates, err := ParseTemplates(TemplateData{
		Config:          cfg,
		JoinToken:       string(secrets.JoinToken),
		ProviderSecrets: providerSecrets,
	})
	if err != nil {
		return err
	}

	decoder := yamlutil.NewYAMLOrJSONDecoder(strings.NewReader(*templates), 100)
	var rawObj runtime.RawExtension
	if err = decoder.Decode(&rawObj); err != nil {
		return err
	}

	obj, gvk, err := yaml.NewDecodingSerializer(unstructured.UnstructuredJSONScheme).Decode(rawObj.Raw, nil, nil)
	if err != nil {
		return err
	}

	unstructuredMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return err
	}

	unstructuredObj := &unstructured.Unstructured{Object: unstructuredMap}

	gr, err := restmapper.GetAPIGroupResources(kubeconfig.Clientset.Discovery())
	if err != nil {
		return err
	}

	mapper := restmapper.NewDiscoveryRESTMapper(gr)
	mapping, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		return err
	}

	dri := kubeconfig.DynamicClient.Resource(mapping.Resource).Namespace("kube-system")

	_, err = dri.Apply(ctx, "k3s-manager", unstructuredObj, metav1.ApplyOptions{
		FieldManager: "k3s-manager",
	})

	return err
}

// Retries the login workflow until successful or timeout
func ConnectToCluster(ctx context.Context, secrets *provider.K3sAccessSecrets, timeout time.Duration) error {
	l := logger.Log().WithField("timeout", timeout)
	l.Info("Attempting to connect to Kubernetes cluster")

	count := 0
	return common.WaitUntilReady(ctx, func() (bool, error) {
		defer func() {
			count++
		}()

		l = logger.Log().WithField("attempt", count)
		l.Debug("New connection attempt")

		kubeconfig, err := login(secrets.Kubeconfig)
		if err != nil {
			l.WithError(err).Debug("Unable to login")
			return false, nil
		}
		l.Debug("Successfully connected to cluster - get list of nodes")

		nodes, err := kubeconfig.Clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
		if err != nil {
			l.WithError(err).Debug("Error getting node list")
			return false, nil
		}

		l.WithField("nodes", nodes).Trace("Nodes currently attached to cluster")

		l.Debug("Connection successful")

		return true, nil
	}, timeout)
}
