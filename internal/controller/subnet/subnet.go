/*
Copyright 2025 The Crossplane Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package subnet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/crossplane/crossplane-runtime/pkg/feature"
	"github.com/crossplane/crossplane-runtime/pkg/meta"

	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/crossplane/crossplane-runtime/pkg/connection"
	"github.com/crossplane/crossplane-runtime/pkg/controller"
	"github.com/crossplane/crossplane-runtime/pkg/event"
	"github.com/crossplane/crossplane-runtime/pkg/ratelimiter"
	"github.com/crossplane/crossplane-runtime/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/pkg/resource"
	"github.com/crossplane/crossplane-runtime/pkg/statemetrics"

	"github.com/crossplane/provider-vkcloud/apis/networking/v1alpha1"
	apisv1alpha1 "github.com/crossplane/provider-vkcloud/apis/v1alpha1"
	"github.com/crossplane/provider-vkcloud/internal/features"
)

const (
	errNotSubnet    = "managed resource is not a Subnet custom resource"
	errTrackPCUsage = "cannot track ProviderConfig usage"
	errGetPC        = "cannot get ProviderConfig"
	errGetCreds     = "cannot get credentials"

	errNewClient = "cannot create new Service"
)

type VkCloudService struct {
	Token   string
	BaseURL string
	Client  *http.Client
}

type Credentials struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	Domain     string `json:"domain"`
	ProjectID  string `json:"projectId"`
	AuthURL    string `json:"authUrl"`
	NeutronURL string `json:"neutronUrl"`
}

func getKeystoneToken(c Credentials) (string, error) {
	requestBodyJson := map[string]interface{}{
		"auth": map[string]interface{}{
			"identity": map[string]interface{}{
				"methods": []string{"password"},
				"password": map[string]interface{}{
					"user": map[string]interface{}{
						"name":     c.Username,
						"domain":   map[string]string{"name": c.Domain},
						"password": c.Password,
					},
				},
			},
			"scope": map[string]interface{}{
				"project": map[string]interface{}{
					"id": c.ProjectID,
				},
			},
		},
	}

	requestBody, _ := json.Marshal(requestBodyJson)
	request, err := http.NewRequest(
		"POST",
		c.AuthURL+"/v3/auth/tokens",
		bytes.NewReader(requestBody),
	)
	if err != nil {
		return "", err
	}

	request.Header.Set("Content-Type", "application/json")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return "", err
	}

	return response.Header.Get("X-Subject-Token"), nil
}

var (
	newVkCloudService = func(creds []byte) (*VkCloudService, error) {
		var c Credentials
		if err := json.Unmarshal(creds, &c); err != nil {
			return nil, err
		}

		token, err := getKeystoneToken(c)
		if err != nil {
			return nil, err
		}

		return &VkCloudService{
			Token:   token,
			BaseURL: c.NeutronURL,
			Client:  &http.Client{Timeout: 10 * time.Second},
		}, nil
	}
)

// Setup adds a controller that reconciles Subnet managed resources.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1alpha1.SubnetGroupKind)

	cps := []managed.ConnectionPublisher{managed.NewAPISecretPublisher(mgr.GetClient(), mgr.GetScheme())}
	if o.Features.Enabled(features.EnableAlphaExternalSecretStores) {
		cps = append(cps, connection.NewDetailsManager(mgr.GetClient(), apisv1alpha1.StoreConfigGroupVersionKind))
	}

	opts := []managed.ReconcilerOption{
		managed.WithExternalConnecter(&connector{
			kube:         mgr.GetClient(),
			usage:        resource.NewProviderConfigUsageTracker(mgr.GetClient(), &apisv1alpha1.ProviderConfigUsage{}),
			newServiceFn: newVkCloudService}),
		managed.WithLogger(o.Logger.WithValues("controller", name)),
		managed.WithPollInterval(o.PollInterval),
		managed.WithRecorder(event.NewAPIRecorder(mgr.GetEventRecorderFor(name))),
		managed.WithConnectionPublishers(cps...),
		managed.WithManagementPolicies(),
	}

	if o.Features.Enabled(feature.EnableAlphaChangeLogs) {
		opts = append(opts, managed.WithChangeLogger(o.ChangeLogOptions.ChangeLogger))
	}

	if o.MetricOptions != nil {
		opts = append(opts, managed.WithMetricRecorder(o.MetricOptions.MRMetrics))
	}

	if o.MetricOptions != nil && o.MetricOptions.MRStateMetrics != nil {
		stateMetricsRecorder := statemetrics.NewMRStateRecorder(
			mgr.GetClient(), o.Logger, o.MetricOptions.MRStateMetrics, &v1alpha1.SubnetList{}, o.MetricOptions.PollStateMetricInterval,
		)
		if err := mgr.Add(stateMetricsRecorder); err != nil {
			return errors.Wrap(err, "cannot register MR state metrics recorder for kind v1alpha1.SubnetList")
		}
	}

	r := managed.NewReconciler(mgr, resource.ManagedKind(v1alpha1.SubnetGroupVersionKind), opts...)

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&v1alpha1.Subnet{}).
		Complete(ratelimiter.NewReconciler(name, r, o.GlobalRateLimiter))
}

// A connector is expected to produce an ExternalClient when its Connect method
// is called.
type connector struct {
	kube         client.Client
	usage        resource.Tracker
	newServiceFn func(creds []byte) (*VkCloudService, error)
}

// Connect typically produces an ExternalClient by:
// 1. Tracking that the managed resource is using a ProviderConfig.
// 2. Getting the managed resource's ProviderConfig.
// 3. Getting the credentials specified by the ProviderConfig.
// 4. Using the credentials to form a client.
func (c *connector) Connect(ctx context.Context, mg resource.Managed) (managed.ExternalClient, error) {
	cr, ok := mg.(*v1alpha1.Subnet)
	if !ok {
		return nil, errors.New(errNotSubnet)
	}

	if err := c.usage.Track(ctx, mg); err != nil {
		return nil, errors.Wrap(err, errTrackPCUsage)
	}

	pc := &apisv1alpha1.ProviderConfig{}
	if err := c.kube.Get(ctx, types.NamespacedName{Name: cr.GetProviderConfigReference().Name}, pc); err != nil {
		return nil, errors.Wrap(err, errGetPC)
	}

	cd := pc.Spec.Credentials
	data, err := resource.CommonCredentialExtractor(ctx, cd.Source, c.kube, cd.CommonCredentialSelectors)
	if err != nil {
		return nil, errors.Wrap(err, errGetCreds)
	}

	svc, err := c.newServiceFn(data)
	if err != nil {
		return nil, errors.Wrap(err, errNewClient)
	}

	return &external{service: svc}, nil
}

// An ExternalClient observes, then either creates, updates, or deletes an
// external resource to ensure it reflects the managed resource's desired state.
type external struct {
	// A 'client' used to connect to the external resource API. In practice this
	// would be something like an AWS SDK client.
	service *VkCloudService
}

func (c *external) Observe(ctx context.Context, mg resource.Managed) (managed.ExternalObservation, error) {
	cr, ok := mg.(*v1alpha1.Subnet)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotSubnet)
	}

	subnetID := meta.GetExternalName(cr)
	if subnetID == "" {
		return managed.ExternalObservation{ResourceExists: false}, nil
	}

	request, err := http.NewRequestWithContext(
		ctx,
		"GET",
		c.service.BaseURL+"/v2.0/subnets/"+subnetID,
		nil,
	)
	if err != nil {
		return managed.ExternalObservation{}, err
	}

	request.Header.Set("X-Auth-Token", c.service.Token)

	response, err := c.service.Client.Do(request)
	if err != nil {
		return managed.ExternalObservation{}, err
	}

	if response.StatusCode == 404 {
		return managed.ExternalObservation{ResourceExists: false}, nil
	}

	return managed.ExternalObservation{
		ResourceExists:          true,
		ResourceUpToDate:        true,
		ResourceLateInitialized: false,
	}, nil
}

func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1alpha1.Subnet)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotSubnet)
	}

	requestBodyJson := map[string]interface{}{
		"subnet": map[string]interface{}{
			"name":       cr.Spec.ForProvider.Name,
			"network_id": cr.Spec.ForProvider.NetworkId,
			"cidr":       cr.Spec.ForProvider.Cidr,
			"ip_version": 4,
		},
	}

	requestBody, _ := json.Marshal(requestBodyJson)
	request, err := http.NewRequestWithContext(
		ctx,
		"POST",
		c.service.BaseURL+"/v2.0/subnets",
		bytes.NewReader(requestBody),
	)
	if err != nil {
		return managed.ExternalCreation{}, err
	}

	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Auth-Token", c.service.Token)

	response, err := c.service.Client.Do(request)
	if err != nil {
		return managed.ExternalCreation{}, err
	}

	defer response.Body.Close()

	var result struct {
		Subnet struct {
			ID string `json:"id"`
		} `json:"subnet"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return managed.ExternalCreation{}, err
	}

	meta.SetExternalName(cr, result.Subnet.ID)
	return managed.ExternalCreation{}, nil
}

func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1alpha1.Subnet)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotSubnet)
	}

	fmt.Printf("Updating: %+v", cr)

	return managed.ExternalUpdate{
		// Optionally return any details that may be required to connect to the
		// external resource. These will be stored as the connection secret.
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Delete(ctx context.Context, mg resource.Managed) (managed.ExternalDelete, error) {
	cr, ok := mg.(*v1alpha1.Subnet)
	if !ok {
		return managed.ExternalDelete{}, errors.New(errNotSubnet)
	}

	networkID := meta.GetExternalName(cr)
	if networkID == "" {
		return managed.ExternalDelete{}, nil
	}

	request, err := http.NewRequestWithContext(
		ctx,
		"DELETE",
		c.service.BaseURL+"/v2.0/subnets/"+networkID,
		nil,
	)
	if err != nil {
		return managed.ExternalDelete{}, err
	}

	request.Header.Set("X-Auth-Token", c.service.Token)

	c.service.Client.Do(request)
	return managed.ExternalDelete{}, nil
}

func (c *external) Disconnect(ctx context.Context) error {
	return nil
}
