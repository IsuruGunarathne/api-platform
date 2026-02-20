/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	api "github.com/wso2/api-platform/gateway/gateway-controller/pkg/api/generated"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/config"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/models"
	policyv1alpha "github.com/wso2/api-platform/sdk/gateway/policy/v1alpha"
)

// ─── Fixture helpers ─────────────────────────────────────────────────────────

// ptrStr returns a pointer to s.
func ptrStr(s string) *string { return &s }

// makeRestAPIStoredConfig builds a minimal RestApi StoredConfig with a populated Spec.
func makeRestAPIStoredConfig(id, handle, displayName, version, context string, ops []api.Operation, apiPolicies []api.Policy) *models.StoredConfig {
	var policies *[]api.Policy
	if apiPolicies != nil {
		policies = &apiPolicies
	}

	apiData := api.APIConfigData{
		DisplayName: displayName,
		Version:     version,
		Context:     context,
		Operations:  ops,
		Policies:    policies,
		Upstream: struct {
			Main    api.Upstream  `json:"main" yaml:"main"`
			Sandbox *api.Upstream `json:"sandbox,omitempty" yaml:"sandbox,omitempty"`
		}{
			Main: api.Upstream{Url: ptrStr("http://backend:8080")},
		},
	}
	spec := api.APIConfiguration_Spec{}
	_ = spec.FromAPIConfigData(apiData)

	return &models.StoredConfig{
		ID:   id,
		Kind: string(api.RestApi),
		Configuration: api.APIConfiguration{
			Kind:     api.RestApi,
			Metadata: api.Metadata{Name: handle},
			Spec:     spec,
		},
	}
}

// makeWebSubStoredConfig builds a minimal WebSubApi StoredConfig with a populated Spec.
func makeWebSubStoredConfig(id, handle, displayName, version, context string, channels []api.Channel) *models.StoredConfig {
	apiData := api.WebhookAPIData{
		DisplayName: displayName,
		Version:     version,
		Context:     context,
		Channels:    channels,
	}
	spec := api.APIConfiguration_Spec{}
	_ = spec.FromWebhookAPIData(apiData)

	return &models.StoredConfig{
		ID:   id,
		Kind: string(api.WebSubApi),
		Configuration: api.APIConfiguration{
			Kind:     api.WebSubApi,
			Metadata: api.Metadata{Name: handle},
			Spec:     spec,
		},
	}
}

// makeRouterConfig returns a minimal RouterConfig with the given vhosts.
func makeRouterConfig(mainVHost, sandboxVHost string) *config.RouterConfig {
	return &config.RouterConfig{
		GatewayHost: "localhost",
		VHosts: config.VHostsConfig{
			Main:    config.VHostEntry{Default: mainVHost},
			Sandbox: config.VHostEntry{Default: sandboxVHost},
		},
	}
}

// makePolicyDefinitions returns a definitions map keyed by "name|version" so that
// ResolvePolicyVersion (which iterates values) can find matching definitions.
// Pairs must be: name1, fullVersion1, name2, fullVersion2, …
func makePolicyDefinitions(pairs ...string) map[string]api.PolicyDefinition {
	defs := make(map[string]api.PolicyDefinition, len(pairs)/2)
	for i := 0; i+1 < len(pairs); i += 2 {
		name, ver := pairs[i], pairs[i+1]
		defs[name+"|"+ver] = api.PolicyDefinition{Name: name, Version: ver}
	}
	return defs
}

// ─── ConvertAPIPolicyToModel ──────────────────────────────────────────────────

func TestConvertAPIPolicyToModel_WithParams(t *testing.T) {
	params := map[string]interface{}{"key1": "val1", "key2": 42}
	p := api.Policy{Name: "my-policy", Version: "v1.0.0", Params: &params}

	result := ConvertAPIPolicyToModel(p, policyv1alpha.LevelAPI, "v1.0.0")

	assert.Equal(t, "my-policy", result.Name)
	assert.Equal(t, "v1.0.0", result.Version)
	assert.True(t, result.Enabled)
	assert.Equal(t, "val1", result.Parameters["key1"])
	assert.Equal(t, 42, result.Parameters["key2"])
	assert.Equal(t, string(policyv1alpha.LevelAPI), result.Parameters["attachedTo"])
}

func TestConvertAPIPolicyToModel_NilParams(t *testing.T) {
	p := api.Policy{Name: "my-policy", Version: "v1", Params: nil}

	result := ConvertAPIPolicyToModel(p, policyv1alpha.LevelRoute, "v1.0.0")

	assert.Equal(t, "my-policy", result.Name)
	assert.Equal(t, string(policyv1alpha.LevelRoute), result.Parameters["attachedTo"])
	assert.Len(t, result.Parameters, 1, "only attachedTo should be set when Params is nil")
}

func TestConvertAPIPolicyToModel_EmptyLevel(t *testing.T) {
	params := map[string]interface{}{"foo": "bar"}
	p := api.Policy{Name: "my-policy", Version: "v1", Params: &params}

	result := ConvertAPIPolicyToModel(p, "", "v1")

	_, hasAttachedTo := result.Parameters["attachedTo"]
	assert.False(t, hasAttachedTo, "attachedTo should not be set when level is empty")
	assert.Equal(t, "bar", result.Parameters["foo"])
}

// ─── DerivePolicyFromAPIConfig – RestApi ─────────────────────────────────────

func TestDerivePolicy_RestAPI_BasicWithPolicies(t *testing.T) {
	defs := makePolicyDefinitions("rate-limit", "v1.0.0", "auth", "v2.0.0")
	routerCfg := makeRouterConfig("localhost", "sandbox.localhost")
	sysCfg := &config.Config{Analytics: config.AnalyticsConfig{Enabled: false}}

	apiPolicies := []api.Policy{{Name: "rate-limit", Version: "v1"}}
	opPolicies := []api.Policy{{Name: "auth", Version: "v2"}}
	ops := []api.Operation{{Method: "GET", Path: "/users", Policies: &opPolicies}}
	cfg := makeRestAPIStoredConfig("api-1", "my-api", "My API", "v1", "/myapi", ops, apiPolicies)

	result := DerivePolicyFromAPIConfig(cfg, routerCfg, sysCfg, defs)

	require.NotNil(t, result)
	assert.Equal(t, "api-1-policies", result.ID)
	require.Len(t, result.Configuration.Routes, 1)
	// API-level rate-limit first, then operation-level auth
	assert.Len(t, result.Configuration.Routes[0].Policies, 2)
	assert.Equal(t, "rate-limit", result.Configuration.Routes[0].Policies[0].Name)
	assert.Equal(t, "auth", result.Configuration.Routes[0].Policies[1].Name)
}

func TestDerivePolicy_RestAPI_NoPoliciesReturnsNil(t *testing.T) {
	defs := makePolicyDefinitions()
	routerCfg := makeRouterConfig("localhost", "sandbox.localhost")
	sysCfg := &config.Config{Analytics: config.AnalyticsConfig{Enabled: false}}

	ops := []api.Operation{{Method: "GET", Path: "/users"}}
	cfg := makeRestAPIStoredConfig("api-1", "my-api", "My API", "v1", "/myapi", ops, nil)

	result := DerivePolicyFromAPIConfig(cfg, routerCfg, sysCfg, defs)

	assert.Nil(t, result, "should return nil when no policies exist at any level")
}

func TestDerivePolicy_RestAPI_InvalidAPILevelVersionSkipped(t *testing.T) {
	defs := makePolicyDefinitions("auth", "v1.0.0") // only "auth" is defined
	routerCfg := makeRouterConfig("localhost", "sandbox.localhost")
	sysCfg := &config.Config{Analytics: config.AnalyticsConfig{Enabled: false}}

	// "bad-policy" has no matching definition → skipped; "auth" is found → kept
	apiPolicies := []api.Policy{
		{Name: "bad-policy", Version: "v1"},
		{Name: "auth", Version: "v1"},
	}
	ops := []api.Operation{{Method: "GET", Path: "/users"}}
	cfg := makeRestAPIStoredConfig("api-1", "my-api", "My API", "v1", "/myapi", ops, apiPolicies)

	result := DerivePolicyFromAPIConfig(cfg, routerCfg, sysCfg, defs)

	require.NotNil(t, result)
	require.Len(t, result.Configuration.Routes, 1)
	assert.Len(t, result.Configuration.Routes[0].Policies, 1)
	assert.Equal(t, "auth", result.Configuration.Routes[0].Policies[0].Name)
}

func TestDerivePolicy_RestAPI_InvalidOpLevelVersionSkipped(t *testing.T) {
	defs := makePolicyDefinitions("auth", "v1.0.0")
	routerCfg := makeRouterConfig("localhost", "sandbox.localhost")
	sysCfg := &config.Config{Analytics: config.AnalyticsConfig{Enabled: false}}

	badOpPolicies := []api.Policy{{Name: "nonexistent", Version: "v99"}}
	validOpPolicies := []api.Policy{{Name: "auth", Version: "v1"}}
	ops := []api.Operation{
		{Method: "GET", Path: "/users", Policies: &badOpPolicies},
		{Method: "POST", Path: "/users", Policies: &validOpPolicies},
	}
	cfg := makeRestAPIStoredConfig("api-1", "my-api", "My API", "v1", "/myapi", ops, nil)

	result := DerivePolicyFromAPIConfig(cfg, routerCfg, sysCfg, defs)

	require.NotNil(t, result)
	require.Len(t, result.Configuration.Routes, 2)
	// GET /users: invalid policy skipped → 0 policies
	assert.Len(t, result.Configuration.Routes[0].Policies, 0)
	// POST /users: auth policy included → 1 policy
	assert.Len(t, result.Configuration.Routes[1].Policies, 1)
	assert.Equal(t, "auth", result.Configuration.Routes[1].Policies[0].Name)
}

func TestDerivePolicy_RestAPI_SandboxUpstream(t *testing.T) {
	defs := makePolicyDefinitions("auth", "v1.0.0")
	routerCfg := makeRouterConfig("localhost", "sandbox.localhost")
	sysCfg := &config.Config{Analytics: config.AnalyticsConfig{Enabled: false}}

	opPolicies := []api.Policy{{Name: "auth", Version: "v1"}}
	ops := []api.Operation{{Method: "GET", Path: "/items", Policies: &opPolicies}}
	cfg := makeRestAPIStoredConfig("api-1", "my-api", "My API", "v1", "/myapi", ops, nil)

	// Inject sandbox upstream into the spec
	sandboxURL := "http://sandbox-backend:8080"
	apiData, err := cfg.Configuration.Spec.AsAPIConfigData()
	require.NoError(t, err)
	apiData.Upstream.Sandbox = &api.Upstream{Url: &sandboxURL}
	require.NoError(t, cfg.Configuration.Spec.FromAPIConfigData(apiData))

	result := DerivePolicyFromAPIConfig(cfg, routerCfg, sysCfg, defs)

	require.NotNil(t, result)
	// One route for main vhost + one for sandbox vhost
	assert.Len(t, result.Configuration.Routes, 2)
}

func TestDerivePolicy_RestAPI_CustomVhosts(t *testing.T) {
	defs := makePolicyDefinitions("auth", "v1.0.0")
	routerCfg := makeRouterConfig("default.localhost", "default.sandbox.localhost")
	sysCfg := &config.Config{Analytics: config.AnalyticsConfig{Enabled: false}}

	opPolicies := []api.Policy{{Name: "auth", Version: "v1"}}
	ops := []api.Operation{{Method: "GET", Path: "/data", Policies: &opPolicies}}
	cfg := makeRestAPIStoredConfig("api-1", "my-api", "My API", "v1", "/custom", ops, nil)

	// Override vhosts in the spec
	customSandbox := "custom.sandbox.com"
	apiData, err := cfg.Configuration.Spec.AsAPIConfigData()
	require.NoError(t, err)
	apiData.Vhosts = &struct {
		Main    string  `json:"main" yaml:"main"`
		Sandbox *string `json:"sandbox,omitempty" yaml:"sandbox,omitempty"`
	}{
		Main:    "custom.main.com",
		Sandbox: &customSandbox,
	}
	require.NoError(t, cfg.Configuration.Spec.FromAPIConfigData(apiData))

	result := DerivePolicyFromAPIConfig(cfg, routerCfg, sysCfg, defs)

	require.NotNil(t, result)
	routeKey := result.Configuration.Routes[0].RouteKey
	// Route key format: "METHOD|/context/path|vhost"
	assert.Contains(t, routeKey, "custom.main.com")
}

func TestDerivePolicy_RestAPI_InvalidSpec(t *testing.T) {
	defs := makePolicyDefinitions()
	routerCfg := makeRouterConfig("localhost", "sandbox.localhost")
	sysCfg := &config.Config{}

	// RestApi kind but zero Spec (union is nil → AsAPIConfigData fails)
	cfg := &models.StoredConfig{
		ID:   "api-bad",
		Kind: string(api.RestApi),
		Configuration: api.APIConfiguration{
			Kind:     api.RestApi,
			Metadata: api.Metadata{Name: "bad-api"},
		},
	}

	result := DerivePolicyFromAPIConfig(cfg, routerCfg, sysCfg, defs)

	assert.Nil(t, result, "should return nil for invalid RestApi spec")
}

func TestDerivePolicy_RestAPI_WithAnalytics(t *testing.T) {
	defs := makePolicyDefinitions()
	routerCfg := makeRouterConfig("localhost", "sandbox.localhost")
	// Enable analytics so the system policy is injected even with no user policies
	sysCfg := &config.Config{Analytics: config.AnalyticsConfig{Enabled: true}}

	ops := []api.Operation{{Method: "GET", Path: "/data"}}
	cfg := makeRestAPIStoredConfig("api-1", "my-api", "My API", "v1", "/myapi", ops, nil)

	result := DerivePolicyFromAPIConfig(cfg, routerCfg, sysCfg, defs)

	require.NotNil(t, result, "analytics system policy should make policyCount > 0")
	require.Len(t, result.Configuration.Routes, 1)
	assert.GreaterOrEqual(t, len(result.Configuration.Routes[0].Policies), 1)
	// The analytics system policy is prepended first
	firstPolicy := result.Configuration.Routes[0].Policies[0]
	assert.Contains(t, firstPolicy.Name, "analytics")
}

func TestDerivePolicy_RestAPI_MetadataPopulated(t *testing.T) {
	defs := makePolicyDefinitions("auth", "v1.0.0")
	routerCfg := makeRouterConfig("localhost", "sandbox.localhost")
	sysCfg := &config.Config{}

	opPolicies := []api.Policy{{Name: "auth", Version: "v1"}}
	ops := []api.Operation{{Method: "GET", Path: "/data", Policies: &opPolicies}}
	cfg := makeRestAPIStoredConfig("api-123", "my-api-handle", "My API Name", "v1.2", "/api-ctx", ops, nil)

	result := DerivePolicyFromAPIConfig(cfg, routerCfg, sysCfg, defs)

	require.NotNil(t, result)
	assert.Equal(t, "api-123-policies", result.ID)
	assert.Equal(t, "My API Name", result.Configuration.Metadata.APIName)
	assert.Equal(t, "v1.2", result.Configuration.Metadata.Version)
	assert.Equal(t, "/api-ctx", result.Configuration.Metadata.Context)
}

// ─── DerivePolicyFromAPIConfig – WebSubApi ───────────────────────────────────

func TestDerivePolicy_WebSub_WithChannels(t *testing.T) {
	defs := makePolicyDefinitions("channel-auth", "v1.0.0")
	routerCfg := makeRouterConfig("localhost", "sandbox.localhost")
	sysCfg := &config.Config{Analytics: config.AnalyticsConfig{Enabled: false}}

	chPolicies := []api.Policy{{Name: "channel-auth", Version: "v1"}}
	channels := []api.Channel{
		{Name: "/topic1", Method: "POST", Policies: &chPolicies},
		{Name: "/topic2", Method: "POST"}, // no channel-level policy
	}
	cfg := makeWebSubStoredConfig("websub-1", "my-websub", "My WebSub", "v1", "/events", channels)

	result := DerivePolicyFromAPIConfig(cfg, routerCfg, sysCfg, defs)

	require.NotNil(t, result)
	require.Len(t, result.Configuration.Routes, 2)
	// /topic1 gets the policy; /topic2 gets none
	assert.Len(t, result.Configuration.Routes[0].Policies, 1)
	assert.Equal(t, "channel-auth", result.Configuration.Routes[0].Policies[0].Name)
	assert.Len(t, result.Configuration.Routes[1].Policies, 0)
}

func TestDerivePolicy_WebSub_ChannelPoliciesOnly(t *testing.T) {
	defs := makePolicyDefinitions("transform", "v1.0.0")
	routerCfg := makeRouterConfig("localhost", "sandbox.localhost")
	sysCfg := &config.Config{}

	chPolicies := []api.Policy{{Name: "transform", Version: "v1"}}
	channels := []api.Channel{
		{Name: "/events", Method: "POST", Policies: &chPolicies},
	}
	cfg := makeWebSubStoredConfig("ws-1", "ws-api", "WS API", "v1", "/ws", channels)

	result := DerivePolicyFromAPIConfig(cfg, routerCfg, sysCfg, defs)

	require.NotNil(t, result)
	require.Len(t, result.Configuration.Routes, 1)
	assert.Len(t, result.Configuration.Routes[0].Policies, 1)
	assert.Equal(t, "transform", result.Configuration.Routes[0].Policies[0].Name)
}

func TestDerivePolicy_WebSub_InvalidSpec(t *testing.T) {
	defs := makePolicyDefinitions()
	routerCfg := makeRouterConfig("localhost", "sandbox.localhost")
	sysCfg := &config.Config{}

	// WebSubApi kind but zero Spec (union is nil → AsWebhookAPIData fails)
	cfg := &models.StoredConfig{
		ID:   "ws-bad",
		Kind: string(api.WebSubApi),
		Configuration: api.APIConfiguration{
			Kind:     api.WebSubApi,
			Metadata: api.Metadata{Name: "ws-bad"},
		},
	}

	result := DerivePolicyFromAPIConfig(cfg, routerCfg, sysCfg, defs)

	assert.Nil(t, result, "should return nil for invalid WebSubApi spec")
}

func TestDerivePolicy_WebSub_InvalidChannelPolicyVersion(t *testing.T) {
	defs := makePolicyDefinitions("valid-policy", "v1.0.0")
	routerCfg := makeRouterConfig("localhost", "sandbox.localhost")
	sysCfg := &config.Config{Analytics: config.AnalyticsConfig{Enabled: false}}

	badPolicies := []api.Policy{{Name: "nonexistent", Version: "v99"}}
	validPolicies := []api.Policy{{Name: "valid-policy", Version: "v1"}}
	channels := []api.Channel{
		{Name: "/bad", Method: "POST", Policies: &badPolicies},
		{Name: "/good", Method: "POST", Policies: &validPolicies},
	}
	cfg := makeWebSubStoredConfig("ws-1", "ws-api", "WS API", "v1", "/ws", channels)

	result := DerivePolicyFromAPIConfig(cfg, routerCfg, sysCfg, defs)

	require.NotNil(t, result)
	require.Len(t, result.Configuration.Routes, 2)
	assert.Len(t, result.Configuration.Routes[0].Policies, 0, "/bad channel: invalid policy skipped")
	assert.Len(t, result.Configuration.Routes[1].Policies, 1, "/good channel: valid policy kept")
}

func TestDerivePolicy_WebSub_NoPoliciesReturnsNil(t *testing.T) {
	defs := makePolicyDefinitions()
	routerCfg := makeRouterConfig("localhost", "sandbox.localhost")
	sysCfg := &config.Config{Analytics: config.AnalyticsConfig{Enabled: false}}

	channels := []api.Channel{
		{Name: "/topic1", Method: "POST"},
		{Name: "/topic2", Method: "POST"},
	}
	cfg := makeWebSubStoredConfig("ws-1", "ws-api", "WS API", "v1", "/ws", channels)

	result := DerivePolicyFromAPIConfig(cfg, routerCfg, sysCfg, defs)

	assert.Nil(t, result, "should return nil when no policies exist at any channel level")
}
