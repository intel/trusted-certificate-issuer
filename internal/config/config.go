/*
Copyright 2021 Intel(R).

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

package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/creasty/defaults"
)

const (
	KeyWrapAesGCM        = "aes_gcm"
	KeyWrapAesKeyWrapPad = "aes_key_wrap_pad"
)

type Config struct {
	MetricsAddress     string
	HealthProbeAddress string
	LeaderElection     bool
	CertManagerIssuer  bool
	CSRFullCertChain   bool
	RandomNonce        bool

	HSMConfigPath    string
	HSMConfig        HSMConfig
	KeyWrapMechanism string
}

type HSMConfig struct {
	TokenLabel string `json:"tokenLabel" default:"SgxOperator"`
	UserPin    string `json:"userPin"`
	SoPin      string `json:"soPin"`
}

func (cfg *Config) Validate() error {
	if cfg.HSMConfigPath != "" {
		if err := cfg.parseHSMConfig(); err != nil {
			return fmt.Errorf("failed to parse hsm config: %v", err)
		}
	}
	if cfg.HSMConfig.SoPin == "" || cfg.HSMConfig.UserPin == "" {
		return fmt.Errorf("invalid HSM config: missing user/so pin")
	}

	if cfg.KeyWrapMechanism != KeyWrapAesGCM &&
		cfg.KeyWrapMechanism != KeyWrapAesKeyWrapPad {
		return fmt.Errorf("invalid key wrap mechanism '%s'", cfg.KeyWrapMechanism)
	}

	return nil
}

func (cfg *Config) parseHSMConfig() error {
	if cfg.HSMConfigPath == "" {
		return nil
	}
	defaults.Set(&cfg.HSMConfig)

	data, err := ioutil.ReadFile(cfg.HSMConfigPath)
	if err != nil {
		return err
	}

	return json.Unmarshal(data, &cfg.HSMConfig)
}
