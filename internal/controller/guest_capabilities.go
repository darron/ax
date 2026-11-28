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

package controller

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
)

var capabilityName = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// GuestCapabilitiesPolicy scopes an added capability set to one exact,
// digest-pinned guest image.
type GuestCapabilitiesPolicy struct {
	Image string
	Add   []string
}

// ParseGuestCapabilitiesPolicy reads the optional image/capability pair used
// by AX server deployments. Empty inputs leave guest templates unchanged.
func ParseGuestCapabilitiesPolicy(image, capabilities string) (GuestCapabilitiesPolicy, error) {
	image = strings.TrimSpace(image)
	capabilities = strings.TrimSpace(capabilities)
	if image == "" && capabilities == "" {
		return GuestCapabilitiesPolicy{}, nil
	}
	if image == "" || capabilities == "" {
		return GuestCapabilitiesPolicy{}, fmt.Errorf("AX_GUEST_CAPABILITIES_IMAGE and AX_GUEST_CAPABILITIES must both be set")
	}
	if _, err := name.NewDigest(image); err != nil {
		return GuestCapabilitiesPolicy{}, fmt.Errorf("AX_GUEST_CAPABILITIES_IMAGE must be pinned by digest: %w", err)
	}

	parts := strings.Split(capabilities, ",")
	add := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		capability := strings.TrimSpace(part)
		if !capabilityName.MatchString(capability) || capability == "ALL" || strings.HasPrefix(capability, "CAP_") {
			return GuestCapabilitiesPolicy{}, fmt.Errorf("AX_GUEST_CAPABILITIES contains invalid capability %q", capability)
		}
		if _, ok := seen[capability]; ok {
			return GuestCapabilitiesPolicy{}, fmt.Errorf("AX_GUEST_CAPABILITIES repeats capability %q", capability)
		}
		seen[capability] = struct{}{}
		add = append(add, capability)
	}
	sort.Strings(add)
	return GuestCapabilitiesPolicy{Image: image, Add: add}, nil
}

// ForImage returns the configured capabilities only for an exact image match.
func (p GuestCapabilitiesPolicy) ForImage(image string) []string {
	if p.Image == "" || p.Image != image {
		return nil
	}
	return slices.Clone(p.Add)
}
