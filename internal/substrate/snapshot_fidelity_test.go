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
	"testing"

	ateapipb "go.ate.dev/substrate/api/ateapi/v1"
)

func TestParseSnapshotFidelity(t *testing.T) {
	for _, tc := range []struct {
		raw     string
		want    ateapipb.SnapshotFidelity
		wantErr bool
	}{
		{"", ateapipb.SnapshotFidelity_SNAPSHOT_FIDELITY_VOLUMES, false},
		{"volumes", ateapipb.SnapshotFidelity_SNAPSHOT_FIDELITY_VOLUMES, false},
		{"ROOTFS", ateapipb.SnapshotFidelity_SNAPSHOT_FIDELITY_ROOTFS, false},
		{" rootfs ", ateapipb.SnapshotFidelity_SNAPSHOT_FIDELITY_ROOTFS, false},
		{"memory", ateapipb.SnapshotFidelity_SNAPSHOT_FIDELITY_MEMORY, false},
		{"everything", ateapipb.SnapshotFidelity_SNAPSHOT_FIDELITY_UNSPECIFIED, true},
		{"SNAPSHOT_FIDELITY_ROOTFS", ateapipb.SnapshotFidelity_SNAPSHOT_FIDELITY_UNSPECIFIED, true},
	} {
		got, err := ParseSnapshotFidelity(tc.raw)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("ParseSnapshotFidelity(%q) = %v, %v; want %v, err=%v", tc.raw, got, err, tc.want, tc.wantErr)
		}
	}
}

func TestValidateSnapshotFidelityEnv(t *testing.T) {
	t.Setenv("AX_SNAPSHOT_FIDELITY", "rootfs")
	if err := ValidateSnapshotFidelityEnv(); err != nil {
		t.Fatalf("rootfs rejected: %v", err)
	}
	t.Setenv("AX_SNAPSHOT_FIDELITY", "disk")
	if err := ValidateSnapshotFidelityEnv(); err == nil {
		t.Fatal("unknown value accepted")
	}
}

func TestBuildActorTemplateUsesSnapshotFidelity(t *testing.T) {
	t.Setenv("AX_SNAPSHOTS_BUCKET", "gs://bucket/ax/")
	t.Setenv("AX_SNAPSHOT_FIDELITY", "")
	tmpl := BuildActorTemplate("space", "name", "img@sha256:"+zeros64, nil, nil, "", nil)
	if got := tmpl.GetSnapshotConfig().GetPreferredFidelity(); got != ateapipb.SnapshotFidelity_SNAPSHOT_FIDELITY_VOLUMES {
		t.Fatalf("default fidelity = %v, want VOLUMES", got)
	}
	t.Setenv("AX_SNAPSHOT_FIDELITY", "rootfs")
	tmpl = BuildActorTemplate("space", "name", "img@sha256:"+zeros64, nil, nil, "", nil)
	if got := tmpl.GetSnapshotConfig().GetPreferredFidelity(); got != ateapipb.SnapshotFidelity_SNAPSHOT_FIDELITY_ROOTFS {
		t.Fatalf("rootfs fidelity = %v, want ROOTFS", got)
	}
}

const zeros64 = "0000000000000000000000000000000000000000000000000000000000000000"
