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

package utils

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/wso2/api-platform/gateway/gateway-controller/pkg/config"
)

// --- ValidateAPIKeyValue ---

func TestValidateAPIKeyValue_Empty(t *testing.T) {
	svc := &APIKeyService{}
	err := svc.ValidateAPIKeyValue("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be empty")
}

func TestValidateAPIKeyValue_TooShort(t *testing.T) {
	svc := &APIKeyService{}
	// DefaultMinAPIKeyLength is 36; 35 chars is too short
	err := svc.ValidateAPIKeyValue(strings.Repeat("a", 35))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestValidateAPIKeyValue_AtMinLength(t *testing.T) {
	svc := &APIKeyService{}
	// DefaultMinAPIKeyLength is 36; exactly 36 chars should pass
	err := svc.ValidateAPIKeyValue(strings.Repeat("a", 36))
	assert.NoError(t, err)
}

func TestValidateAPIKeyValue_AtMaxLength(t *testing.T) {
	svc := &APIKeyService{}
	// DefaultMaxAPIKeyLength is 128; exactly 128 chars should pass
	err := svc.ValidateAPIKeyValue(strings.Repeat("a", 128))
	assert.NoError(t, err)
}

func TestValidateAPIKeyValue_TooLong(t *testing.T) {
	svc := &APIKeyService{}
	// DefaultMaxAPIKeyLength is 128; 129 chars is too long
	err := svc.ValidateAPIKeyValue(strings.Repeat("a", 129))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too long")
}

func TestValidateAPIKeyValue_CustomConfig_TooShort(t *testing.T) {
	svc := &APIKeyService{
		apiKeyConfig: &config.APIKeyConfig{MinKeyLength: 10, MaxKeyLength: 50},
	}
	err := svc.ValidateAPIKeyValue(strings.Repeat("a", 9))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestValidateAPIKeyValue_CustomConfig_Valid(t *testing.T) {
	svc := &APIKeyService{
		apiKeyConfig: &config.APIKeyConfig{MinKeyLength: 10, MaxKeyLength: 50},
	}
	err := svc.ValidateAPIKeyValue(strings.Repeat("a", 10))
	assert.NoError(t, err)
}

func TestValidateAPIKeyValue_CustomConfig_TooLong(t *testing.T) {
	svc := &APIKeyService{
		apiKeyConfig: &config.APIKeyConfig{MinKeyLength: 10, MaxKeyLength: 50},
	}
	err := svc.ValidateAPIKeyValue(strings.Repeat("a", 51))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too long")
}

// --- ValidateDisplayName ---

func TestValidateDisplayName_Empty(t *testing.T) {
	err := ValidateDisplayName("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be empty")
}

func TestValidateDisplayName_WhitespaceOnly(t *testing.T) {
	err := ValidateDisplayName("   ")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be empty")
}

func TestValidateDisplayName_Valid(t *testing.T) {
	err := ValidateDisplayName("My API Key")
	assert.NoError(t, err)
}

func TestValidateDisplayName_ExactlyMaxRunes(t *testing.T) {
	// DisplayNameMaxLength is 100; exactly 100 ASCII chars = 100 runes
	err := ValidateDisplayName(strings.Repeat("a", 100))
	assert.NoError(t, err)
}

func TestValidateDisplayName_TooManyRunes(t *testing.T) {
	// 101 ASCII chars = 101 runes > 100
	err := ValidateDisplayName(strings.Repeat("a", 101))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too long")
}

func TestValidateDisplayName_UnicodeRunes(t *testing.T) {
	// "é" is 2 bytes but 1 rune; 50 × "é" = 100 bytes but 50 runes ≤ 100
	err := ValidateDisplayName(strings.Repeat("é", 50))
	assert.NoError(t, err)
}

// --- ValidateAPIKeyName ---

func TestValidateAPIKeyName_Empty(t *testing.T) {
	err := ValidateAPIKeyName("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be empty")
}

func TestValidateAPIKeyName_TooShort(t *testing.T) {
	// APIKeyNameMinLength is 3; "ab" has length 2
	err := ValidateAPIKeyName("ab")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too short")
}

func TestValidateAPIKeyName_AtMinLength(t *testing.T) {
	// Exactly 3 chars, valid pattern
	err := ValidateAPIKeyName("abc")
	assert.NoError(t, err)
}

func TestValidateAPIKeyName_TooLong(t *testing.T) {
	// APIKeyNameMaxLength is 63; 64 chars is too long
	err := ValidateAPIKeyName(strings.Repeat("a", 64))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "too long")
}

func TestValidateAPIKeyName_Uppercase(t *testing.T) {
	// Regex requires lowercase only
	err := ValidateAPIKeyName("MyAPI")
	assert.Error(t, err)
}

func TestValidateAPIKeyName_ConsecutiveHyphens(t *testing.T) {
	// Consecutive separators are not allowed
	err := ValidateAPIKeyName("my--api")
	assert.Error(t, err)
}

func TestValidateAPIKeyName_LeadingHyphen(t *testing.T) {
	// Cannot start with a separator
	err := ValidateAPIKeyName("-myapi")
	assert.Error(t, err)
}

func TestValidateAPIKeyName_TrailingUnderscore(t *testing.T) {
	// Cannot end with a separator
	err := ValidateAPIKeyName("myapi_")
	assert.Error(t, err)
}

func TestValidateAPIKeyName_ValidWithHyphen(t *testing.T) {
	err := ValidateAPIKeyName("my-api")
	assert.NoError(t, err)
}

func TestValidateAPIKeyName_ValidWithUnderscore(t *testing.T) {
	err := ValidateAPIKeyName("my_api")
	assert.NoError(t, err)
}

func TestValidateAPIKeyName_Alphanumeric(t *testing.T) {
	err := ValidateAPIKeyName("myapi123")
	assert.NoError(t, err)
}

// --- GenerateAPIKeyName ---

func TestGenerateAPIKeyName_NormalName(t *testing.T) {
	result, err := GenerateAPIKeyName("My REST API")
	assert.NoError(t, err)
	assert.Equal(t, "my-rest-api", result)
}

func TestGenerateAPIKeyName_AllUppercase(t *testing.T) {
	result, err := GenerateAPIKeyName("MYAPI")
	assert.NoError(t, err)
	assert.Equal(t, "myapi", result)
}

func TestGenerateAPIKeyName_WithUnderscores(t *testing.T) {
	result, err := GenerateAPIKeyName("my_api_v1")
	assert.NoError(t, err)
	assert.Equal(t, "my-api-v1", result)
}

func TestGenerateAPIKeyName_ConsecutiveSpaces(t *testing.T) {
	result, err := GenerateAPIKeyName("my  api")
	assert.NoError(t, err)
	assert.Equal(t, "my-api", result)
}

func TestGenerateAPIKeyName_VeryLong(t *testing.T) {
	// 80-char input; result must be ≤ 63 chars and pass ValidateAPIKeyName
	result, err := GenerateAPIKeyName(strings.Repeat("a", 80))
	assert.NoError(t, err)
	assert.LessOrEqual(t, len(result), 63)
	assert.NoError(t, ValidateAPIKeyName(result))
}

func TestGenerateAPIKeyName_SpecialCharsOnly(t *testing.T) {
	// All chars removed → padded with random hex → ≥ 3 chars, valid name
	result, err := GenerateAPIKeyName("@#$%")
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(result), 3)
	assert.NoError(t, ValidateAPIKeyName(result))
}

func TestGenerateAPIKeyName_LeadingTrailingHyphens(t *testing.T) {
	result, err := GenerateAPIKeyName("-my-api-")
	assert.NoError(t, err)
	assert.Equal(t, "my-api", result)
}

func TestGenerateAPIKeyName_EmptyAfterSanitize(t *testing.T) {
	// "---" → collapsed to "-" → trimmed to "" → padded with random hex
	result, err := GenerateAPIKeyName("---")
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, len(result), 3)
	assert.NoError(t, ValidateAPIKeyName(result))
}
