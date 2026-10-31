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

func TestSecurityContextFromEnv(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want []string
	}{
		{"", nil},
		{"SETUID,SETGID,CHOWN", []string{"CHOWN", "SETGID", "SETUID"}},
		{" FOWNER , DAC_OVERRIDE ,FOWNER", []string{"DAC_OVERRIDE", "FOWNER"}},
		{"ALL", nil},
		{"CHOWN,ALL", nil},
		{"CAP_CHOWN", []string{"CAP_CHOWN"}}, // a well-formed name; Substrate decides whether it exists
		{"chown", nil},
		{"CHOWN,", nil},
	} {
		t.Setenv("AX_TASK_CAPABILITIES_ADD", tc.raw)
		got := securityContextFromEnv().GetCapabilities().GetAdd()
		if len(tc.want) == 0 && len(got) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("AX_TASK_CAPABILITIES_ADD=%q: got %v, want %v", tc.raw, got, tc.want)
		}
	}
}

func TestTemplateCarriesTaskCapabilities(t *testing.T) {
	t.Setenv("AX_TASK_CAPABILITIES_ADD", "SETUID,SETGID,CHOWN,DAC_OVERRIDE,FOWNER,FSETID")
	tmpl := BuildActorTemplate("ax-lab", "t", "img@sha256:abc", nil, nil, "gs://b/", nil)
	got := tmpl.GetContainers()[0].GetSecurityContext().GetCapabilities()
	want := []string{"CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "SETGID", "SETUID"}
	if !reflect.DeepEqual(got.GetAdd(), want) || len(got.GetDrop()) != 0 {
		t.Fatalf("template capabilities add=%v drop=%v, want add=%v", got.GetAdd(), got.GetDrop(), want)
	}

	t.Setenv("AX_TASK_CAPABILITIES_ADD", "")
	tmpl = BuildActorTemplate("ax-lab", "t", "img@sha256:abc", nil, nil, "gs://b/", nil)
	if sc := tmpl.GetContainers()[0].GetSecurityContext(); sc != nil {
		t.Fatalf("unset AX_TASK_CAPABILITIES_ADD must leave the default set, got %v", sc)
	}
}
