/*
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
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

package storage

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	api "github.com/wso2/api-platform/gateway/gateway-controller/pkg/api/generated"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/models"
)

func TestNewConfigStore(t *testing.T) {
	cs := NewConfigStore()

	assert.NotNil(t, cs)
	assert.NotNil(t, cs.configs)
	assert.NotNil(t, cs.nameVersion)
	assert.NotNil(t, cs.handle)
	assert.NotNil(t, cs.templates)
	assert.NotNil(t, cs.templateIdByHandle)
	assert.NotNil(t, cs.apiKeysByAPI)
	assert.NotNil(t, cs.labelsByAPI)
	assert.NotNil(t, cs.TopicManager)
	assert.Equal(t, int64(0), cs.GetSnapshotVersion())
}

func TestConfigStore_SnapshotVersion(t *testing.T) {
	cs := NewConfigStore()

	// Initial version should be 0
	assert.Equal(t, int64(0), cs.GetSnapshotVersion())

	// Increment version
	v1 := cs.IncrementSnapshotVersion()
	assert.Equal(t, int64(1), v1)
	assert.Equal(t, int64(1), cs.GetSnapshotVersion())

	// Increment again
	v2 := cs.IncrementSnapshotVersion()
	assert.Equal(t, int64(2), v2)
	assert.Equal(t, int64(2), cs.GetSnapshotVersion())

	// Set version directly
	cs.SetSnapshotVersion(100)
	assert.Equal(t, int64(100), cs.GetSnapshotVersion())
}

func TestConfigStore_TemplateOperations(t *testing.T) {
	cs := NewConfigStore()

	template := &models.StoredLLMProviderTemplate{
		ID: "template-1",
		Configuration: api.LLMProviderTemplate{
			Metadata: api.Metadata{
				Name: "openai-template",
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Add template
	err := cs.AddTemplate(template)
	require.NoError(t, err)

	// Get by ID
	retrieved, err := cs.GetTemplate("template-1")
	require.NoError(t, err)
	assert.Equal(t, "openai-template", retrieved.GetHandle())

	// Get by handle
	retrieved, err = cs.GetTemplateByHandle("openai-template")
	require.NoError(t, err)
	assert.Equal(t, "template-1", retrieved.ID)

	// Get all templates
	all := cs.GetAllTemplates()
	assert.Len(t, all, 1)

	// Update template - create a new struct to avoid pointer issues
	updatedTemplate := &models.StoredLLMProviderTemplate{
		ID: "template-1",
		Configuration: api.LLMProviderTemplate{
			Metadata: api.Metadata{
				Name: "updated-template",
			},
		},
		CreatedAt: template.CreatedAt,
		UpdatedAt: time.Now(),
	}
	err = cs.UpdateTemplate(updatedTemplate)
	require.NoError(t, err)

	// Verify update
	retrieved, err = cs.GetTemplateByHandle("updated-template")
	require.NoError(t, err)
	assert.Equal(t, "template-1", retrieved.ID)

	// Old handle should not work
	_, err = cs.GetTemplateByHandle("openai-template")
	assert.Error(t, err)

	// Delete template
	err = cs.DeleteTemplate("template-1")
	require.NoError(t, err)

	// Verify deletion
	_, err = cs.GetTemplate("template-1")
	assert.Error(t, err)
}

func TestConfigStore_TemplateErrors(t *testing.T) {
	cs := NewConfigStore()

	// Add template with empty ID
	err := cs.AddTemplate(&models.StoredLLMProviderTemplate{
		ID: "",
		Configuration: api.LLMProviderTemplate{
			Metadata: api.Metadata{
				Name: "test",
			},
		},
	})
	assert.Error(t, err)

	// Add template with empty handle
	err = cs.AddTemplate(&models.StoredLLMProviderTemplate{
		ID: "id-1",
		Configuration: api.LLMProviderTemplate{
			Metadata: api.Metadata{
				Name: "",
			},
		},
	})
	assert.Error(t, err)

	// Add duplicate ID
	template := &models.StoredLLMProviderTemplate{
		ID: "dup-id",
		Configuration: api.LLMProviderTemplate{
			Metadata: api.Metadata{
				Name: "handle-1",
			},
		},
	}
	err = cs.AddTemplate(template)
	require.NoError(t, err)

	err = cs.AddTemplate(&models.StoredLLMProviderTemplate{
		ID: "dup-id",
		Configuration: api.LLMProviderTemplate{
			Metadata: api.Metadata{
				Name: "handle-2",
			},
		},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")

	// Add duplicate handle
	err = cs.AddTemplate(&models.StoredLLMProviderTemplate{
		ID: "different-id",
		Configuration: api.LLMProviderTemplate{
			Metadata: api.Metadata{
				Name: "handle-1",
			},
		},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")

	// Update non-existent template
	err = cs.UpdateTemplate(&models.StoredLLMProviderTemplate{
		ID: "non-existent",
		Configuration: api.LLMProviderTemplate{
			Metadata: api.Metadata{
				Name: "test",
			},
		},
	})
	assert.Error(t, err)

	// Delete non-existent template
	err = cs.DeleteTemplate("non-existent")
	assert.Error(t, err)

	// Get non-existent template
	_, err = cs.GetTemplate("non-existent")
	assert.Error(t, err)

	_, err = cs.GetTemplateByHandle("non-existent")
	assert.Error(t, err)
}

func TestConfigStore_APIKeyOperations(t *testing.T) {
	cs := NewConfigStore()

	apiKey := &models.APIKey{
		ID:        "key-1",
		Name:      "test-key",
		APIKey:    "hashed-key-value",
		APIId:     "api-1",
		Status:    models.APIKeyStatusActive,
		CreatedBy: "user-1",
		CreatedAt: time.Now(),
	}

	// Store API key
	err := cs.StoreAPIKey(apiKey)
	require.NoError(t, err)

	// Get by ID
	retrieved, err := cs.GetAPIKeyByID("api-1", "key-1")
	require.NoError(t, err)
	assert.Equal(t, "test-key", retrieved.Name)

	// Get by name
	retrieved, err = cs.GetAPIKeyByName("api-1", "test-key")
	require.NoError(t, err)
	assert.Equal(t, "key-1", retrieved.ID)

	// Get all keys for API
	keys, err := cs.GetAPIKeysByAPI("api-1")
	require.NoError(t, err)
	assert.Len(t, keys, 1)

	// Count active keys
	count, err := cs.CountActiveAPIKeysByUserAndAPI("api-1", "user-1")
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Remove API key
	err = cs.RemoveAPIKeyByID("api-1", "key-1")
	require.NoError(t, err)

	// Verify removal
	_, err = cs.GetAPIKeyByID("api-1", "key-1")
	assert.Error(t, err)
}

func TestConfigStore_APIKeyErrors(t *testing.T) {
	cs := NewConfigStore()

	// Store nil key
	err := cs.StoreAPIKey(nil)
	assert.Error(t, err)

	// Store key with empty name
	err = cs.StoreAPIKey(&models.APIKey{
		ID:     "key-1",
		Name:   "",
		APIKey: "value",
		APIId:  "api-1",
	})
	assert.Error(t, err)

	// Store key with empty value
	err = cs.StoreAPIKey(&models.APIKey{
		ID:     "key-1",
		Name:   "test",
		APIKey: "",
		APIId:  "api-1",
	})
	assert.Error(t, err)

	// Store key with empty API ID
	err = cs.StoreAPIKey(&models.APIKey{
		ID:     "key-1",
		Name:   "test",
		APIKey: "value",
		APIId:  "",
	})
	assert.Error(t, err)

	// Get non-existent key
	_, err = cs.GetAPIKeyByID("non-existent", "key-1")
	assert.Error(t, err)

	_, err = cs.GetAPIKeyByName("non-existent", "test")
	assert.Error(t, err)

	// Remove non-existent key
	err = cs.RemoveAPIKeyByID("non-existent", "key-1")
	assert.Error(t, err)
}

func TestConfigStore_RemoveAPIKeysByAPI(t *testing.T) {
	cs := NewConfigStore()

	// Add multiple keys for an API
	for i := 1; i <= 3; i++ {
		err := cs.StoreAPIKey(&models.APIKey{
			ID:        "key-" + string(rune('0'+i)),
			Name:      "test-key-" + string(rune('0'+i)),
			APIKey:    "value-" + string(rune('0'+i)),
			APIId:     "api-1",
			Status:    models.APIKeyStatusActive,
			CreatedBy: "user-1",
		})
		require.NoError(t, err)
	}

	// Verify all keys exist
	keys, err := cs.GetAPIKeysByAPI("api-1")
	require.NoError(t, err)
	assert.Len(t, keys, 3)

	// Remove all keys for API
	err = cs.RemoveAPIKeysByAPI("api-1")
	require.NoError(t, err)

	// Verify all removed
	keys, err = cs.GetAPIKeysByAPI("api-1")
	require.NoError(t, err)
	assert.Len(t, keys, 0)

	// Remove from non-existent API should not error
	err = cs.RemoveAPIKeysByAPI("non-existent")
	assert.NoError(t, err)
}

func TestConfigStore_GetAPIKeysByAPI_EmptyResult(t *testing.T) {
	cs := NewConfigStore()

	// Get keys for non-existent API should return empty slice, not error
	keys, err := cs.GetAPIKeysByAPI("non-existent")
	require.NoError(t, err)
	assert.NotNil(t, keys)
	assert.Len(t, keys, 0)
}

func TestConfigStore_CountActiveAPIKeysByUserAndAPI(t *testing.T) {
	cs := NewConfigStore()

	// Add active key
	err := cs.StoreAPIKey(&models.APIKey{
		ID:        "key-1",
		Name:      "active-key",
		APIKey:    "value-1",
		APIId:     "api-1",
		Status:    models.APIKeyStatusActive,
		CreatedBy: "user-1",
	})
	require.NoError(t, err)

	// Add revoked key
	err = cs.StoreAPIKey(&models.APIKey{
		ID:        "key-2",
		Name:      "revoked-key",
		APIKey:    "value-2",
		APIId:     "api-1",
		Status:    models.APIKeyStatusRevoked,
		CreatedBy: "user-1",
	})
	require.NoError(t, err)

	// Add key for different user
	err = cs.StoreAPIKey(&models.APIKey{
		ID:        "key-3",
		Name:      "other-user-key",
		APIKey:    "value-3",
		APIId:     "api-1",
		Status:    models.APIKeyStatusActive,
		CreatedBy: "user-2",
	})
	require.NoError(t, err)

	// Count for user-1 should be 1 (only active key)
	count, err := cs.CountActiveAPIKeysByUserAndAPI("api-1", "user-1")
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Count for user-2 should be 1
	count, err = cs.CountActiveAPIKeysByUserAndAPI("api-1", "user-2")
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Count for non-existent API should be 0
	count, err = cs.CountActiveAPIKeysByUserAndAPI("non-existent", "user-1")
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

// ─── ConfigStore API config CRUD ─────────────────────────────────────────────

// makeStoredConfig builds a minimal valid RestApi StoredConfig for CRUD testing.
func makeStoredConfig(id, handle, displayName, version string) *models.StoredConfig {
	mainURL := "http://backend:8080"
	apiData := api.APIConfigData{
		DisplayName: displayName,
		Version:     version,
		Context:     "/" + displayName,
		Operations:  []api.Operation{{Method: "GET", Path: "/data"}},
		Upstream: struct {
			Main    api.Upstream  `json:"main" yaml:"main"`
			Sandbox *api.Upstream `json:"sandbox,omitempty" yaml:"sandbox,omitempty"`
		}{
			Main: api.Upstream{Url: &mainURL},
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
		Status:    models.StatusDeployed,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func TestConfigStore_Add_Get_BasicRestAPI(t *testing.T) {
	cs := NewConfigStore()
	cfg := makeStoredConfig("id-1", "my-api", "My API", "v1")

	err := cs.Add(cfg)
	require.NoError(t, err)

	got, err := cs.Get("id-1")
	require.NoError(t, err)
	assert.Equal(t, "id-1", got.ID)
	assert.Equal(t, "my-api", got.GetHandle())
}

func TestConfigStore_Add_DuplicateHandle_Conflict(t *testing.T) {
	cs := NewConfigStore()
	cfg1 := makeStoredConfig("id-1", "same-handle", "API One", "v1")
	cfg2 := makeStoredConfig("id-2", "same-handle", "API Two", "v2")

	require.NoError(t, cs.Add(cfg1))
	err := cs.Add(cfg2)
	assert.ErrorIs(t, err, ErrConflict)
}

func TestConfigStore_Add_DuplicateNameVersion_Conflict(t *testing.T) {
	cs := NewConfigStore()
	// Same displayName:version but different handles
	cfg1 := makeStoredConfig("id-1", "handle-a", "Duplicate API", "v1")
	cfg2 := makeStoredConfig("id-2", "handle-b", "Duplicate API", "v1")

	require.NoError(t, cs.Add(cfg1))
	err := cs.Add(cfg2)
	assert.ErrorIs(t, err, ErrConflict)
}

func TestConfigStore_GetByHandle(t *testing.T) {
	cs := NewConfigStore()
	cfg := makeStoredConfig("id-1", "my-api", "My API", "v1")
	require.NoError(t, cs.Add(cfg))

	got, err := cs.GetByHandle("my-api")
	require.NoError(t, err)
	assert.Equal(t, "id-1", got.ID)
}

func TestConfigStore_GetByHandle_NotFound(t *testing.T) {
	cs := NewConfigStore()
	_, err := cs.GetByHandle("nonexistent")
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestConfigStore_GetByNameVersion(t *testing.T) {
	cs := NewConfigStore()
	cfg := makeStoredConfig("id-1", "my-api", "My API", "v1")
	require.NoError(t, cs.Add(cfg))

	got, err := cs.GetByNameVersion("My API", "v1")
	require.NoError(t, err)
	assert.Equal(t, "id-1", got.ID)
}

func TestConfigStore_GetByNameVersion_NotFound(t *testing.T) {
	cs := NewConfigStore()
	_, err := cs.GetByNameVersion("Unknown", "v99")
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestConfigStore_Update(t *testing.T) {
	cs := NewConfigStore()
	cfg := makeStoredConfig("id-1", "my-api", "My API", "v1")
	require.NoError(t, cs.Add(cfg))

	// Build updated config (same ID, same handle, but version v2)
	updated := makeStoredConfig("id-1", "my-api", "My API", "v2")
	require.NoError(t, cs.Update(updated))

	got, err := cs.Get("id-1")
	require.NoError(t, err)
	assert.Equal(t, "v2", got.GetVersion())
}

func TestConfigStore_Update_NotFound(t *testing.T) {
	cs := NewConfigStore()
	cfg := makeStoredConfig("nonexistent-id", "my-api", "My API", "v1")
	err := cs.Update(cfg)
	assert.Error(t, err, "updating non-existent ID should error")
}

func TestConfigStore_Delete(t *testing.T) {
	cs := NewConfigStore()
	cfg := makeStoredConfig("id-1", "my-api", "My API", "v1")
	require.NoError(t, cs.Add(cfg))

	require.NoError(t, cs.Delete("id-1"))

	_, err := cs.Get("id-1")
	assert.ErrorIs(t, err, ErrNotFound)
	// Handle index should also be cleared
	_, err = cs.GetByHandle("my-api")
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestConfigStore_Delete_NotFound(t *testing.T) {
	cs := NewConfigStore()
	err := cs.Delete("nonexistent-id")
	assert.Error(t, err)
}

func TestConfigStore_GetAll(t *testing.T) {
	cs := NewConfigStore()
	require.NoError(t, cs.Add(makeStoredConfig("id-1", "api-a", "API A", "v1")))
	require.NoError(t, cs.Add(makeStoredConfig("id-2", "api-b", "API B", "v1")))
	require.NoError(t, cs.Add(makeStoredConfig("id-3", "api-c", "API C", "v1")))

	all := cs.GetAll()
	assert.Len(t, all, 3)
}

func TestConfigStore_GetAllByKind(t *testing.T) {
	cs := NewConfigStore()
	require.NoError(t, cs.Add(makeStoredConfig("id-1", "api-a", "API A", "v1")))
	require.NoError(t, cs.Add(makeStoredConfig("id-2", "api-b", "API B", "v1")))

	restAPIs := cs.GetAllByKind(string(api.RestApi))
	assert.Len(t, restAPIs, 2)

	websubAPIs := cs.GetAllByKind(string(api.WebSubApi))
	assert.Len(t, websubAPIs, 0)
}

func TestConfigStore_Labels_SaveAndGet(t *testing.T) {
	cs := NewConfigStore()
	labels := map[string]string{"env": "prod", "project-id": "proj-123"}
	cfg := makeStoredConfig("id-1", "labeled-api", "Labeled API", "v1")
	cfg.Configuration.Metadata.Labels = &labels
	require.NoError(t, cs.Add(cfg))

	got, err := cs.GetLabelsMap("labeled-api")
	require.NoError(t, err)
	assert.Equal(t, "prod", got["env"])
	assert.Equal(t, "proj-123", got["project-id"])
}

func TestConfigStore_Labels_NotFound(t *testing.T) {
	cs := NewConfigStore()
	_, err := cs.GetLabelsMap("unknown-handle")
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestConfigStore_ConcurrentAdd(t *testing.T) {
	cs := NewConfigStore()
	const n = 50

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			id := fmt.Sprintf("id-%d", idx)
			handle := fmt.Sprintf("api-%d", idx)
			name := fmt.Sprintf("API %d", idx)
			_ = cs.Add(makeStoredConfig(id, handle, name, "v1"))
		}(i)
	}
	wg.Wait()

	all := cs.GetAll()
	assert.Len(t, all, n)
}

// makeWebSubConfig builds a minimal valid WebSubApi StoredConfig for CRUD testing.
func makeWebSubConfig(id, handle, displayName, version string, channels []api.Channel) *models.StoredConfig {
	apiData := api.WebhookAPIData{
		DisplayName: displayName,
		Version:     version,
		Context:     "/" + displayName,
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
		Status:    models.StatusDeployed,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func TestConfigStore_Add_WebSubApi(t *testing.T) {
	cs := NewConfigStore()
	channels := []api.Channel{{Name: "/topic1", Method: "POST"}, {Name: "/topic2", Method: "POST"}}
	cfg := makeWebSubConfig("ws-1", "my-websub", "My WebSub", "v1", channels)

	err := cs.Add(cfg)
	require.NoError(t, err)

	got, err := cs.Get("ws-1")
	require.NoError(t, err)
	assert.Equal(t, string(api.WebSubApi), got.Kind)
	// Verify topic manager registered the topics
	topics := cs.TopicManager.GetAllByConfig("ws-1")
	assert.Len(t, topics, 2)
}

func TestConfigStore_Update_HandleChange(t *testing.T) {
	cs := NewConfigStore()
	cfg := makeStoredConfig("id-1", "old-handle", "My API", "v1")
	require.NoError(t, cs.Add(cfg))

	// Update with a new handle
	updated := makeStoredConfig("id-1", "new-handle", "My API", "v1")
	require.NoError(t, cs.Update(updated))

	// Old handle should no longer be findable
	_, err := cs.GetByHandle("old-handle")
	assert.ErrorIs(t, err, ErrNotFound)

	// New handle should work
	got, err := cs.GetByHandle("new-handle")
	require.NoError(t, err)
	assert.Equal(t, "id-1", got.ID)
}

func TestConfigStore_Update_HandleConflict(t *testing.T) {
	cs := NewConfigStore()
	require.NoError(t, cs.Add(makeStoredConfig("id-1", "handle-a", "API A", "v1")))
	require.NoError(t, cs.Add(makeStoredConfig("id-2", "handle-b", "API B", "v1")))

	// Try to update id-1's handle to one already used by id-2
	conflicting := makeStoredConfig("id-1", "handle-b", "API A", "v1")
	err := cs.Update(conflicting)
	assert.ErrorIs(t, err, ErrConflict)
}

func TestConfigStore_Update_WebSubApi(t *testing.T) {
	cs := NewConfigStore()
	channels := []api.Channel{{Name: "/old-topic", Method: "POST"}}
	cfg := makeWebSubConfig("ws-1", "ws-api", "WS API", "v1", channels)
	require.NoError(t, cs.Add(cfg))

	// Update with different channels
	newChannels := []api.Channel{{Name: "/new-topic", Method: "POST"}}
	updated := makeWebSubConfig("ws-1", "ws-api", "WS API", "v1", newChannels)
	require.NoError(t, cs.Update(updated))

	// The old topic should be gone, new topic present
	topics := cs.TopicManager.GetAllByConfig("ws-1")
	assert.Len(t, topics, 1)
	assert.Contains(t, topics[0], "new-topic")
}

func TestConfigStore_GetByKindNameAndVersion(t *testing.T) {
	cs := NewConfigStore()
	require.NoError(t, cs.Add(makeStoredConfig("id-1", "api-a", "My API", "v1")))
	require.NoError(t, cs.Add(makeStoredConfig("id-2", "api-b", "My API", "v2")))

	got := cs.GetByKindNameAndVersion(string(api.RestApi), "My API", "v1")
	require.NotNil(t, got)
	assert.Equal(t, "id-1", got.ID)

	// Different kind returns nil
	notFound := cs.GetByKindNameAndVersion(string(api.WebSubApi), "My API", "v1")
	assert.Nil(t, notFound)
}

func TestConfigStore_GetByKindAndHandle(t *testing.T) {
	cs := NewConfigStore()
	require.NoError(t, cs.Add(makeStoredConfig("id-1", "my-api", "My API", "v1")))

	got := cs.GetByKindAndHandle(string(api.RestApi), "my-api")
	require.NotNil(t, got)
	assert.Equal(t, "id-1", got.ID)

	// Wrong kind returns nil
	notFound := cs.GetByKindAndHandle(string(api.WebSubApi), "my-api")
	assert.Nil(t, notFound)
}
