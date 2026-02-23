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

package certstore

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/models"
)

// Test certificate in PEM format (self-signed test cert)
const validCertPEM = `-----BEGIN CERTIFICATE-----
MIIB+jCCAWOgAwIBAgIUCNyE284LxvMJTE+42kjmK5e1vW4wDQYJKoZIhvcNAQEL
BQAwDzENMAsGA1UEAwwEdGVzdDAeFw0yNjAxMzAwOTQ2MTJaFw0yNjAxMzEwOTQ2
MTJaMA8xDTALBgNVBAMMBHRlc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGB
ANBI4kYFzQus5qPjuzJEzTQIi6C+hNHFn42toed+2tq/jvBpveaCtSfdLgbwDhZ0
uO5jArhCh++/zfsCqLptTy9nXfvvpJ564y+2Hzp5oFrBBY9Zkohl3ubutIpOG4bO
bo/uB2RvBYZRsUIjKG/NyD9F6I55Yw3vXlcFZkMZVGqrAgMBAAGjUzBRMB0GA1Ud
DgQWBBRNy/QwZlrUz7Jr5d86yYpsoRBoCDAfBgNVHSMEGDAWgBRNy/QwZlrUz7Jr
5d86yYpsoRBoCDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4GBAIOA
aLH5I4KNIlLP5QTK5inG3bihRVbgyFhuS8/wG7k5ONl7bPjvO+VqcXcXQ4uvOY9f
NWeEEe+FnIqCMN4nbrt/Fmimn91F/+3ZBns/Z/L9HJYLlekVPtJXGaDVF6zcj/QP
+oz8QbmWNLWZz2J+vcZG9tikpw0r9EJ2t8tKgWYx
-----END CERTIFICATE-----`

const invalidPEM = `not a valid certificate`

const nonCertPEM = `-----BEGIN PRIVATE KEY-----
MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAuXRVVe4HRD0Ud8Dt
yy+GSZdrdyqZdCWFi+CFcN8C1uswS9xei9itB2xAI/3+p3zUJd2y1rX76kbz76Ss
6R235QIDAQABAkA9QEJWp6Q9XF8ZXvDPMPNLzCn1Gxu8FqPLbJ7L8KvC5fPvHvJa
-----END PRIVATE KEY-----`

func TestNewCertStore(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	cs := NewCertStore(logger, nil, "/test/certs", "/etc/ssl/certs/ca-certificates.crt")

	assert.NotNil(t, cs)
	assert.Equal(t, "/test/certs", cs.GetCertsDir())
	assert.Nil(t, cs.GetCombinedCertificates()) // Not loaded yet
}

func TestCertStore_GetCertsDir(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	tests := []struct {
		name     string
		certsDir string
		expected string
	}{
		{
			name:     "Standard path",
			certsDir: "/etc/gateway/certs",
			expected: "/etc/gateway/certs",
		},
		{
			name:     "Empty path",
			certsDir: "",
			expected: "",
		},
		{
			name:     "Relative path",
			certsDir: "./certs",
			expected: "./certs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := NewCertStore(logger, nil, tt.certsDir, "")
			assert.Equal(t, tt.expected, cs.GetCertsDir())
		})
	}
}

func TestCertStore_GetCombinedCertificates_BeforeLoad(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cs := NewCertStore(logger, nil, "", "")

	// Should return nil before LoadCertificates is called
	assert.Nil(t, cs.GetCombinedCertificates())
}

func TestCertStore_ValidateCertificateData(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cs := NewCertStore(logger, nil, "", "")

	tests := []struct {
		name        string
		certData    []byte
		wantCount   int
		wantErr     bool
		errContains string
	}{
		{
			name:      "Valid single certificate",
			certData:  []byte(validCertPEM),
			wantCount: 1,
			wantErr:   false,
		},
		{
			name:        "Invalid PEM data",
			certData:    []byte(invalidPEM),
			wantCount:   0,
			wantErr:     true,
			errContains: "no valid certificates",
		},
		{
			name:        "Non-certificate PEM (private key)",
			certData:    []byte(nonCertPEM),
			wantCount:   0,
			wantErr:     true,
			errContains: "no valid certificates",
		},
		{
			name:        "Empty data",
			certData:    []byte{},
			wantCount:   0,
			wantErr:     true,
			errContains: "no valid certificates",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count, err := cs.validateCertificateData("test-cert", tt.certData)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantCount, count)
			}
		})
	}
}

func TestCertStore_ValidateAndExtractCertificates(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cs := NewCertStore(logger, nil, "", "")

	tests := []struct {
		name        string
		filename    string
		certData    []byte
		wantCount   int
		wantErr     bool
		errContains string
	}{
		{
			name:      "Valid certificate file",
			filename:  "test.pem",
			certData:  []byte(validCertPEM),
			wantCount: 1,
			wantErr:   false,
		},
		{
			name:        "Invalid file content",
			filename:    "invalid.pem",
			certData:    []byte("not valid pem"),
			wantCount:   0,
			wantErr:     true,
			errContains: "no valid certificates",
		},
		{
			name:        "Empty file",
			filename:    "empty.pem",
			certData:    []byte{},
			wantCount:   0,
			wantErr:     true,
			errContains: "no valid certificates",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count, err := cs.validateAndExtractCertificates(tt.filename, tt.certData)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantCount, count)
			}
		})
	}
}

func TestGenerateCertificateID(t *testing.T) {
	// Generate multiple IDs and ensure they're unique
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id := generateCertificateID()
		assert.NotEmpty(t, id)
		assert.False(t, ids[id], "Generated duplicate ID: %s", id)
		ids[id] = true
	}
}

func TestCertStore_MultipleCertificatesInChain(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cs := NewCertStore(logger, nil, "", "")

	// Create a chain with two certificates
	certChain := validCertPEM + "\n" + validCertPEM

	count, err := cs.validateCertificateData("chain.pem", []byte(certChain))
	assert.NoError(t, err)
	assert.Equal(t, 2, count)
}

func TestCertStore_LoadCustomCertificates_DirNotExist(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cs := NewCertStore(logger, nil, "/nonexistent/path/to/certs", "")

	// loadCustomCertificates is private, so we test via LoadCertificates
	// When directory doesn't exist, it should not fail
	data, count, err := cs.loadCustomCertificates()
	assert.NoError(t, err)
	assert.Nil(t, data)
	assert.Equal(t, 0, count)
}

func TestCertStore_LoadCustomCertificates_WithValidCerts(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Create temp directory for test certs
	tempDir, err := os.MkdirTemp("", "certstore_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a valid certificate file
	certPath := filepath.Join(tempDir, "test.pem")
	err = os.WriteFile(certPath, []byte(validCertPEM), 0644)
	assert.NoError(t, err)

	cs := NewCertStore(logger, nil, tempDir, "")
	data, count, err := cs.loadCustomCertificates()
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
	assert.Contains(t, string(data), "BEGIN CERTIFICATE")
}

func TestCertStore_LoadCustomCertificates_MultipleCertFiles(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Create temp directory for test certs
	tempDir, err := os.MkdirTemp("", "certstore_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create multiple certificate files with different extensions
	extensions := []string{".pem", ".crt", ".cer", ".cert"}
	for i, ext := range extensions {
		certPath := filepath.Join(tempDir, fmt.Sprintf("test%d%s", i, ext))
		err = os.WriteFile(certPath, []byte(validCertPEM), 0644)
		assert.NoError(t, err)
	}

	cs := NewCertStore(logger, nil, tempDir, "")
	data, count, err := cs.loadCustomCertificates()
	assert.NoError(t, err)
	assert.Equal(t, 4, count) // 4 valid certificate files
	assert.NotEmpty(t, data)
}

func TestCertStore_LoadCustomCertificates_SkipNonCertFiles(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Create temp directory for test certs
	tempDir, err := os.MkdirTemp("", "certstore_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a valid certificate file
	certPath := filepath.Join(tempDir, "valid.pem")
	err = os.WriteFile(certPath, []byte(validCertPEM), 0644)
	assert.NoError(t, err)

	// Create non-certificate files that should be skipped
	txtPath := filepath.Join(tempDir, "readme.txt")
	err = os.WriteFile(txtPath, []byte("readme content"), 0644)
	assert.NoError(t, err)

	jsonPath := filepath.Join(tempDir, "config.json")
	err = os.WriteFile(jsonPath, []byte(`{"key": "value"}`), 0644)
	assert.NoError(t, err)

	cs := NewCertStore(logger, nil, tempDir, "")
	data, count, err := cs.loadCustomCertificates()
	assert.NoError(t, err)
	assert.Equal(t, 1, count) // Only the .pem file should be counted
	assert.Contains(t, string(data), "BEGIN CERTIFICATE")
}

func TestCertStore_LoadCustomCertificates_InvalidCertContent(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Create temp directory for test certs
	tempDir, err := os.MkdirTemp("", "certstore_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a .pem file with invalid content
	invalidPath := filepath.Join(tempDir, "invalid.pem")
	err = os.WriteFile(invalidPath, []byte("not a valid certificate"), 0644)
	assert.NoError(t, err)

	// Also create a valid certificate
	validPath := filepath.Join(tempDir, "valid.pem")
	err = os.WriteFile(validPath, []byte(validCertPEM), 0644)
	assert.NoError(t, err)

	cs := NewCertStore(logger, nil, tempDir, "")
	data, count, err := cs.loadCustomCertificates()
	// Should continue processing other files even if one is invalid
	assert.NoError(t, err)
	assert.Equal(t, 1, count) // Only the valid certificate
	assert.Contains(t, string(data), "BEGIN CERTIFICATE")
}

func TestCertStore_LoadCustomCertificates_SubDirectories(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Create temp directory for test certs
	tempDir, err := os.MkdirTemp("", "certstore_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a subdirectory
	subDir := filepath.Join(tempDir, "subdir")
	err = os.Mkdir(subDir, 0755)
	assert.NoError(t, err)

	// Create certificate files in both directories
	certPath1 := filepath.Join(tempDir, "root.pem")
	err = os.WriteFile(certPath1, []byte(validCertPEM), 0644)
	assert.NoError(t, err)

	certPath2 := filepath.Join(subDir, "nested.pem")
	err = os.WriteFile(certPath2, []byte(validCertPEM), 0644)
	assert.NoError(t, err)

	cs := NewCertStore(logger, nil, tempDir, "")
	data, count, err := cs.loadCustomCertificates()
	assert.NoError(t, err)
	// Should load certs from both root and subdirectory
	assert.Equal(t, 2, count)
	assert.NotEmpty(t, data)
}

func TestCertStore_LoadCustomCertificates_CertWithoutNewline(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Create temp directory for test certs
	tempDir, err := os.MkdirTemp("", "certstore_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create cert without trailing newline
	certNoNewline := strings.TrimSuffix(validCertPEM, "\n")
	certPath := filepath.Join(tempDir, "nonewline.pem")
	err = os.WriteFile(certPath, []byte(certNoNewline), 0644)
	assert.NoError(t, err)

	cs := NewCertStore(logger, nil, tempDir, "")
	data, count, err := cs.loadCustomCertificates()
	assert.NoError(t, err)
	assert.Equal(t, 1, count)
	// Should have trailing newline added
	assert.True(t, bytes.HasSuffix(data, []byte("\n")))
}

func TestCertStore_LoadCustomCertificates_PrivateKeySkipped(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Create temp directory for test certs
	tempDir, err := os.MkdirTemp("", "certstore_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a private key file (should be skipped)
	keyPath := filepath.Join(tempDir, "key.pem")
	err = os.WriteFile(keyPath, []byte(nonCertPEM), 0644)
	assert.NoError(t, err)

	// Create a valid certificate
	certPath := filepath.Join(tempDir, "cert.pem")
	err = os.WriteFile(certPath, []byte(validCertPEM), 0644)
	assert.NoError(t, err)

	cs := NewCertStore(logger, nil, tempDir, "")
	data, count, err := cs.loadCustomCertificates()
	assert.NoError(t, err)
	// Private key file should be processed but no certs extracted
	assert.Equal(t, 1, count) // Only the actual certificate
	assert.Contains(t, string(data), "BEGIN CERTIFICATE")
	assert.NotContains(t, string(data), "PRIVATE KEY")
}

func TestCertStore_LoadCustomCertificates_EmptyDirectory(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Create temp directory with no files
	tempDir, err := os.MkdirTemp("", "certstore_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	cs := NewCertStore(logger, nil, tempDir, "")
	data, count, err := cs.loadCustomCertificates()
	assert.NoError(t, err)
	assert.Equal(t, 0, count)
	assert.Empty(t, data)
}

func TestCertStore_LoadCustomCertificates_CertChainInFile(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Create temp directory
	tempDir, err := os.MkdirTemp("", "certstore_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create a certificate chain (2 certs in one file)
	certChain := validCertPEM + "\n" + validCertPEM
	chainPath := filepath.Join(tempDir, "chain.pem")
	err = os.WriteFile(chainPath, []byte(certChain), 0644)
	assert.NoError(t, err)

	cs := NewCertStore(logger, nil, tempDir, "")
	data, count, err := cs.loadCustomCertificates()
	assert.NoError(t, err)
	assert.Equal(t, 2, count) // Two certificates in the chain
	assert.NotEmpty(t, data)
}

// ============================================================
// mockCertStorage — implements storage.Storage for certstore tests
// ============================================================

type mockCertStorage struct {
	certs        []*models.StoredCertificate // shared state; SaveCertificate appends here
	savedCerts   []*models.StoredCertificate // only certs added during the test run
	getByNameErr error
	saveErr      error
	listErr      error
}

// --- real logic: the three methods certstore actually calls ---

func (m *mockCertStorage) GetCertificateByName(name string) (*models.StoredCertificate, error) {
	if m.getByNameErr != nil {
		return nil, m.getByNameErr
	}
	for _, c := range m.certs {
		if c.Name == name {
			return c, nil
		}
	}
	return nil, nil // not found; no error
}

func (m *mockCertStorage) SaveCertificate(cert *models.StoredCertificate) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.certs = append(m.certs, cert)
	m.savedCerts = append(m.savedCerts, cert)
	return nil
}

func (m *mockCertStorage) ListCertificates() ([]*models.StoredCertificate, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.certs, nil
}

// --- stubs for the remaining interface methods ---

func (m *mockCertStorage) GetCertificate(id string) (*models.StoredCertificate, error) {
	return nil, nil
}
func (m *mockCertStorage) DeleteCertificate(id string) error { return nil }

func (m *mockCertStorage) SaveConfig(cfg *models.StoredConfig) error         { return nil }
func (m *mockCertStorage) UpdateConfig(cfg *models.StoredConfig) error       { return nil }
func (m *mockCertStorage) DeleteConfig(id string) error                      { return nil }
func (m *mockCertStorage) GetConfig(id string) (*models.StoredConfig, error) { return nil, nil }
func (m *mockCertStorage) GetConfigByNameVersion(name, version string) (*models.StoredConfig, error) {
	return nil, nil
}
func (m *mockCertStorage) GetConfigByHandle(handle string) (*models.StoredConfig, error) {
	return nil, nil
}
func (m *mockCertStorage) GetAllConfigs() ([]*models.StoredConfig, error) { return nil, nil }
func (m *mockCertStorage) GetAllConfigsByKind(kind string) ([]*models.StoredConfig, error) {
	return nil, nil
}

func (m *mockCertStorage) SaveLLMProviderTemplate(t *models.StoredLLMProviderTemplate) error {
	return nil
}
func (m *mockCertStorage) UpdateLLMProviderTemplate(t *models.StoredLLMProviderTemplate) error {
	return nil
}
func (m *mockCertStorage) DeleteLLMProviderTemplate(id string) error { return nil }
func (m *mockCertStorage) GetLLMProviderTemplate(id string) (*models.StoredLLMProviderTemplate, error) {
	return nil, nil
}
func (m *mockCertStorage) GetAllLLMProviderTemplates() ([]*models.StoredLLMProviderTemplate, error) {
	return nil, nil
}

func (m *mockCertStorage) SaveAPIKey(apiKey *models.APIKey) error                { return nil }
func (m *mockCertStorage) GetAPIKeyByID(id string) (*models.APIKey, error)       { return nil, nil }
func (m *mockCertStorage) GetAPIKeyByKey(key string) (*models.APIKey, error)     { return nil, nil }
func (m *mockCertStorage) GetAPIKeysByAPI(apiId string) ([]*models.APIKey, error) { return nil, nil }
func (m *mockCertStorage) GetAllAPIKeys() ([]*models.APIKey, error)              { return nil, nil }
func (m *mockCertStorage) GetAPIKeysByAPIAndName(apiId, name string) (*models.APIKey, error) {
	return nil, nil
}
func (m *mockCertStorage) UpdateAPIKey(apiKey *models.APIKey) error        { return nil }
func (m *mockCertStorage) DeleteAPIKey(key string) error                   { return nil }
func (m *mockCertStorage) RemoveAPIKeysAPI(apiId string) error             { return nil }
func (m *mockCertStorage) RemoveAPIKeyAPIAndName(apiId, name string) error { return nil }
func (m *mockCertStorage) CountActiveAPIKeysByUserAndAPI(apiId, userID string) (int, error) {
	return 0, nil
}

func (m *mockCertStorage) Close() error { return nil }

// ============================================================
// Tests for LoadCertificates()
// ============================================================

func TestCertStore_LoadCertificates_NoDB_NoSystemPath(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cs := NewCertStore(logger, nil, "", "")

	result, err := cs.LoadCertificates()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no certificates loaded")
	assert.Nil(t, result)
}

func TestCertStore_LoadCertificates_WithDBCerts(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	mock := &mockCertStorage{
		certs: []*models.StoredCertificate{
			{ID: "1", Name: "test.pem", Certificate: []byte(validCertPEM)},
		},
	}
	cs := NewCertStore(logger, mock, "", "")

	result, err := cs.LoadCertificates()
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Contains(t, string(result), "BEGIN CERTIFICATE")
}

func TestCertStore_LoadCertificates_DBListError_NoFallback(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	mock := &mockCertStorage{
		listErr: errors.New("db connection error"),
	}
	cs := NewCertStore(logger, mock, "", "")

	result, err := cs.LoadCertificates()
	assert.Error(t, err)
	assert.Nil(t, result)
}

func TestCertStore_LoadCertificates_DBListError_SystemCertSaves(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	mock := &mockCertStorage{
		listErr: errors.New("db connection error"),
	}

	tmpFile, err := os.CreateTemp("", "system-certs-*.pem")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	_, err = tmpFile.WriteString(validCertPEM)
	assert.NoError(t, err)
	tmpFile.Close()

	cs := NewCertStore(logger, mock, "", tmpFile.Name())

	result, err := cs.LoadCertificates()
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Contains(t, string(result), "BEGIN CERTIFICATE")
}

func TestCertStore_LoadCertificates_SystemCertOnly(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	tmpFile, err := os.CreateTemp("", "system-certs-*.pem")
	assert.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	_, err = tmpFile.WriteString(validCertPEM)
	assert.NoError(t, err)
	tmpFile.Close()

	cs := NewCertStore(logger, nil, "", tmpFile.Name())

	result, err := cs.LoadCertificates()
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Contains(t, string(result), "BEGIN CERTIFICATE")
}

func TestCertStore_LoadCertificates_InvalidSystemPath(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	mock := &mockCertStorage{}
	cs := NewCertStore(logger, mock, "", "/nonexistent/path/to/certs.pem")

	result, err := cs.LoadCertificates()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load both custom and system certificates")
	assert.Nil(t, result)
}

func TestCertStore_LoadCertificates_DBCerts_SystemFail(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	mock := &mockCertStorage{
		certs: []*models.StoredCertificate{
			{ID: "1", Name: "test.pem", Certificate: []byte(validCertPEM)},
		},
	}
	cs := NewCertStore(logger, mock, "", "/nonexistent/system/certs.pem")

	result, err := cs.LoadCertificates()
	// loadedCount > 0 from DB, so system cert failure is non-fatal
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

func TestCertStore_LoadCertificates_SetsGetCombinedCerts(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	mock := &mockCertStorage{
		certs: []*models.StoredCertificate{
			{ID: "1", Name: "test.pem", Certificate: []byte(validCertPEM)},
		},
	}
	cs := NewCertStore(logger, mock, "", "")

	result, err := cs.LoadCertificates()
	assert.NoError(t, err)
	assert.NotNil(t, result)

	combined := cs.GetCombinedCertificates()
	assert.Equal(t, result, combined)
}

func TestCertStore_LoadCertificates_InvalidCertInDB(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	mock := &mockCertStorage{
		certs: []*models.StoredCertificate{
			{ID: "1", Name: "bad.pem", Certificate: []byte(invalidPEM)},
		},
	}
	cs := NewCertStore(logger, mock, "", "")

	result, err := cs.LoadCertificates()
	assert.Error(t, err)
	assert.Nil(t, result)
}

// ============================================================
// Tests for Reload()
// ============================================================

func TestCertStore_Reload_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	mock := &mockCertStorage{
		certs: []*models.StoredCertificate{
			{ID: "1", Name: "test.pem", Certificate: []byte(validCertPEM)},
		},
	}
	cs := NewCertStore(logger, mock, "", "")

	err := cs.Reload()
	assert.NoError(t, err)
}

func TestCertStore_Reload_Error(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cs := NewCertStore(logger, nil, "", "")

	err := cs.Reload()
	assert.Error(t, err)
}

// ============================================================
// Tests for bootstrapCertificatesFromFilesystem()
// ============================================================

func TestCertStore_Bootstrap_DirNotExist(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	mock := &mockCertStorage{}
	cs := NewCertStore(logger, mock, "/nonexistent/certs/dir", "")

	err := cs.bootstrapCertificatesFromFilesystem()
	assert.NoError(t, err)
	assert.Empty(t, mock.savedCerts)
}

func TestCertStore_Bootstrap_NewCert_SavedToDB(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	mock := &mockCertStorage{}
	tempDir := t.TempDir()

	certPath := filepath.Join(tempDir, "cert.pem")
	err := os.WriteFile(certPath, []byte(validCertPEM), 0644)
	assert.NoError(t, err)

	cs := NewCertStore(logger, mock, tempDir, "")
	err = cs.bootstrapCertificatesFromFilesystem()
	assert.NoError(t, err)
	assert.Len(t, mock.savedCerts, 1)
	assert.Equal(t, "cert.pem", mock.savedCerts[0].Name)
}

func TestCertStore_Bootstrap_CertAlreadyInDB_Skipped(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	mock := &mockCertStorage{
		certs: []*models.StoredCertificate{
			{ID: "existing", Name: "cert.pem", Certificate: []byte(validCertPEM)},
		},
	}
	tempDir := t.TempDir()

	certPath := filepath.Join(tempDir, "cert.pem")
	err := os.WriteFile(certPath, []byte(validCertPEM), 0644)
	assert.NoError(t, err)

	cs := NewCertStore(logger, mock, tempDir, "")
	err = cs.bootstrapCertificatesFromFilesystem()
	assert.NoError(t, err)
	assert.Empty(t, mock.savedCerts)
}

func TestCertStore_Bootstrap_GetByNameError_Continues(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	mock := &mockCertStorage{
		getByNameErr: errors.New("db lookup error"),
	}
	tempDir := t.TempDir()

	certPath := filepath.Join(tempDir, "cert.pem")
	err := os.WriteFile(certPath, []byte(validCertPEM), 0644)
	assert.NoError(t, err)

	cs := NewCertStore(logger, mock, tempDir, "")
	err = cs.bootstrapCertificatesFromFilesystem()
	assert.NoError(t, err)
	assert.Empty(t, mock.savedCerts)
}

func TestCertStore_Bootstrap_SaveError_Continues(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	mock := &mockCertStorage{
		saveErr: errors.New("db save error"),
	}
	tempDir := t.TempDir()

	certPath := filepath.Join(tempDir, "cert.pem")
	err := os.WriteFile(certPath, []byte(validCertPEM), 0644)
	assert.NoError(t, err)

	cs := NewCertStore(logger, mock, tempDir, "")
	err = cs.bootstrapCertificatesFromFilesystem()
	assert.NoError(t, err)
	assert.Empty(t, mock.savedCerts)
}

func TestCertStore_Bootstrap_InvalidCertFile_Skipped(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	mock := &mockCertStorage{}
	tempDir := t.TempDir()

	badPath := filepath.Join(tempDir, "bad.pem")
	err := os.WriteFile(badPath, []byte(invalidPEM), 0644)
	assert.NoError(t, err)

	cs := NewCertStore(logger, mock, tempDir, "")
	err = cs.bootstrapCertificatesFromFilesystem()
	assert.NoError(t, err)
	assert.Empty(t, mock.savedCerts)
}

func TestCertStore_Bootstrap_MultipleCerts_OneNew_OneExisting(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	mock := &mockCertStorage{
		certs: []*models.StoredCertificate{
			{ID: "existing", Name: "existing.pem", Certificate: []byte(validCertPEM)},
		},
	}
	tempDir := t.TempDir()

	err := os.WriteFile(filepath.Join(tempDir, "existing.pem"), []byte(validCertPEM), 0644)
	assert.NoError(t, err)
	err = os.WriteFile(filepath.Join(tempDir, "new.pem"), []byte(validCertPEM), 0644)
	assert.NoError(t, err)

	cs := NewCertStore(logger, mock, tempDir, "")
	err = cs.bootstrapCertificatesFromFilesystem()
	assert.NoError(t, err)
	assert.Len(t, mock.savedCerts, 1)
	assert.Equal(t, "new.pem", mock.savedCerts[0].Name)
}

// ============================================================
// Tests for certificateExistsByName()
// ============================================================

func TestCertStore_CertificateExistsByName_Exists(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	mock := &mockCertStorage{
		certs: []*models.StoredCertificate{
			{ID: "1", Name: "test.pem", Certificate: []byte(validCertPEM)},
		},
	}
	cs := NewCertStore(logger, mock, "", "")

	exists, err := cs.certificateExistsByName("test.pem")
	assert.NoError(t, err)
	assert.True(t, exists)
}

func TestCertStore_CertificateExistsByName_NotExists(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	mock := &mockCertStorage{}
	cs := NewCertStore(logger, mock, "", "")

	exists, err := cs.certificateExistsByName("test.pem")
	assert.NoError(t, err)
	assert.False(t, exists)
}

func TestCertStore_CertificateExistsByName_DBError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	mock := &mockCertStorage{
		getByNameErr: errors.New("db error"),
	}
	cs := NewCertStore(logger, mock, "", "")

	exists, err := cs.certificateExistsByName("test.pem")
	assert.Error(t, err)
	assert.False(t, exists)
}
