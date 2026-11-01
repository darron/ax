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

package substrate_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/google/ax/internal/substrate"
	"github.com/google/ax/internal/substrate/substratetest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func TestNewClientWithOptionsSendsPreviewMetadata(t *testing.T) {
	received := make(chan metadata.MD, 1)
	server := substratetest.NewServer(t, grpc.UnaryInterceptor(func(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		received <- md.Copy()
		return next(ctx, req)
	}))
	client, err := substrate.NewClientWithOptions(substrate.ClientOptions{Target: server.Endpoint(), Plaintext: true})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "x-correlation", "preserved")
	if err := client.EnsureAtespace(ctx, "preview-test"); err != nil {
		t.Fatal(err)
	}
	md := <-received
	if !reflect.DeepEqual(md.Get("ate-preview-allowed"), []string{"true"}) || !reflect.DeepEqual(md.Get("x-correlation"), []string{"preserved"}) {
		t.Fatalf("server received metadata %v", md)
	}
}
