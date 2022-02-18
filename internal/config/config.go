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
	"fmt"
)

type Config struct {
	MetricsAddress     string
	HealthProbeAddress string
	LeaderElection     bool
	CertManagerIssuer  bool
	CSRFullCertChain   bool

	HSMTokenLabel string
	HSMUserPin    string
	HSMSoPin      string
	HSMConfigPath string
}

func (cfg Config) Validate() error {
	if cfg.HSMSoPin == "" || cfg.HSMUserPin == "" {
		return fmt.Errorf("invalid HSM config: missing user/so pin")
	}

	return nil
}
