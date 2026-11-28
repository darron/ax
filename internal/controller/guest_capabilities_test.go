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

package controller_test

import (
	"strings"
	"testing"

	"github.com/google/ax/internal/controller"
	"github.com/google/ax/pkg/apis/v1alpha1"
	ateapipb "go.ate.dev/substrate/api/ateapi/v1"
)

const guestCapabilityImage = "us-docker.pkg.dev/example/agents/sandboxd@sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestParseGuestCapabilitiesPolicy(t *testing.T) {
	t.Run("unset keeps defaults", func(t *testing.T) {
		policy, err := controller.ParseGuestCapabilitiesPolicy("", "")
		if err != nil || policy.Image != "" || len(policy.Add) != 0 {
			t.Fatalf("ParseGuestCapabilitiesPolicy(empty) = %+v, %v; want empty policy", policy, err)
		}
	})

	for _, tc := range []struct {
		name, image, capabilities string
	}{
		{name: "missing capabilities", image: guestCapabilityImage},
		{name: "missing image", capabilities: "CHOWN"},
		{name: "unpinned image", image: "example/sandboxd:latest", capabilities: "CHOWN"},
		{name: "empty capability", image: guestCapabilityImage, capabilities: "CHOWN,,FOWNER"},
		{name: "invalid capability spelling", image: guestCapabilityImage, capabilities: "chown"},
		{name: "all capabilities alias", image: guestCapabilityImage, capabilities: "ALL"},
		{name: "kernel capability prefix", image: guestCapabilityImage, capabilities: "CAP_CHOWN"},
		{name: "duplicate capability", image: guestCapabilityImage, capabilities: "CHOWN,CHOWN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := controller.ParseGuestCapabilitiesPolicy(tc.image, tc.capabilities); err == nil {
				t.Fatal("ParseGuestCapabilitiesPolicy() succeeded; want error")
			}
		})
	}

	policy, err := controller.ParseGuestCapabilitiesPolicy(guestCapabilityImage, " FOWNER,CHOWN ")
	if err != nil {
		t.Fatalf("ParseGuestCapabilitiesPolicy(valid pair): %v", err)
	}
	if got, want := strings.Join(policy.Add, ","), "CHOWN,FOWNER"; got != want {
		t.Errorf("capabilities = %q, want canonical order %q", got, want)
	}
}

func TestResolveProfileTemplate_GuestCapabilitiesAreImageScoped(t *testing.T) {
	profileFor := func(image string) *v1alpha1.Profile {
		return &v1alpha1.Profile{
			Image:     image,
			Resources: &v1alpha1.ResourcesSpec{Limits: &v1alpha1.ResourceList{Cpu: "2", Memory: "2Gi"}},
		}
	}
	policy, err := controller.ParseGuestCapabilitiesPolicy(guestCapabilityImage, "CHOWN,DAC_OVERRIDE,FOWNER,FSETID,SETGID,SETUID")
	if err != nil {
		t.Fatal(err)
	}

	_, defaultName, defaultTemplate, err := controller.ResolveProfileTemplate("default", profileFor(guestCapabilityImage), "", "")
	if err != nil {
		t.Fatal(err)
	}
	if defaultTemplate.GetContainers()[0].GetSecurityContext() != nil {
		t.Fatalf("default template has guest security context %v", defaultTemplate.GetContainers()[0].GetSecurityContext())
	}

	_, matchedName, matchedTemplate, err := controller.ResolveProfileTemplate("default", profileFor(guestCapabilityImage), "", "", policy)
	if err != nil {
		t.Fatal(err)
	}
	if matchedName == defaultName {
		t.Errorf("matching capability policy kept template name %q", matchedName)
	}
	if got, want := matchedTemplate.GetContainers()[0].GetSecurityContext().GetCapabilities().GetAdd(), policy.Add; len(got) != len(want) {
		t.Fatalf("guest capabilities = %v, want %v", got, want)
	} else {
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("guest capabilities = %v, want %v", got, want)
			}
		}
	}
	wantResources := &ateapipb.ResourceRequirements{Limits: &ateapipb.Resources{CpuMillicores: 2000, MemoryBytes: 2 << 30}}
	if got := matchedTemplate.GetResources(); got.GetLimits().GetCpuMillicores() != wantResources.GetLimits().GetCpuMillicores() || got.GetLimits().GetMemoryBytes() != wantResources.GetLimits().GetMemoryBytes() {
		t.Errorf("capability policy changed template resources: got %v, want %v", got, wantResources)
	}

	otherImage := strings.TrimSuffix(guestCapabilityImage, strings.Repeat("a", 64)) + strings.Repeat("b", 64)
	_, otherDefaultName, otherDefaultTemplate, err := controller.ResolveProfileTemplate("default", profileFor(otherImage), "", "")
	if err != nil {
		t.Fatal(err)
	}
	_, otherPolicyName, otherPolicyTemplate, err := controller.ResolveProfileTemplate("default", profileFor(otherImage), "", "", policy)
	if err != nil {
		t.Fatal(err)
	}
	if otherPolicyName != otherDefaultName {
		t.Errorf("nonmatching image changed template name from %q to %q", otherDefaultName, otherPolicyName)
	}
	if otherPolicyTemplate.GetContainers()[0].GetSecurityContext() != nil {
		t.Errorf("nonmatching image received guest capabilities: %v", otherPolicyTemplate.GetContainers()[0].GetSecurityContext())
	}
	if otherDefaultTemplate.GetContainers()[0].GetSecurityContext() != nil {
		t.Errorf("default nonmatching template has guest security context %v", otherDefaultTemplate.GetContainers()[0].GetSecurityContext())
	}
}
