// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package substrate

import (
	"reflect"
	"testing"
)

func TestWorkerSelectorFromEnv(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want map[string]string
	}{
		{"", nil},
		{"sbx-pool=ax", map[string]string{"sbx-pool": "ax"}},
		{" a=1 , b=2 ", map[string]string{"a": "1", "b": "2"}},
		{"novalue,=x", nil},
	} {
		t.Setenv("AX_WORKER_SELECTOR", tc.raw)
		got := workerSelectorFromEnv().GetMatchLabels()
		if len(tc.want) == 0 && len(got) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("AX_WORKER_SELECTOR=%q: got %v, want %v", tc.raw, got, tc.want)
		}
	}
	t.Setenv("AX_WORKER_SELECTOR", "sbx-pool=ax")
	tmpl := BuildActorTemplate("ax-lab", "t", "img", nil, nil, "gs://b/", nil)
	if got := tmpl.GetWorkerSelector().GetMatchLabels()["sbx-pool"]; got != "ax" {
		t.Errorf("template worker selector = %q, want ax", got)
	}
}
