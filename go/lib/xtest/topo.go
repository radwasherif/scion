// Copyright 2019 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package xtest

import (
	"testing"

	"github.com/scionproto/scion/go/lib/topology"
)

// TestTopoProvider is a provider for a specific topology object.
type TestTopoProvider struct {
	*topology.Topo
}

// TopoProviderFromFile creates a topo provider from a topology file.
// It fails the test if loading the file fails.
func TopoProviderFromFile(t *testing.T, fName string) *TestTopoProvider {
	t.Helper()
	topo, err := topology.LoadFromFile(fName)
	FailOnErr(t, err)
	return &TestTopoProvider{Topo: topo}
}

// Get returns the stored topology.
func (t *TestTopoProvider) Get() *topology.Topo {
	return t.Topo
}