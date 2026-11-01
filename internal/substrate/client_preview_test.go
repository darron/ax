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
	"context"
	"google.golang.org/protobuf/types/known/emptypb"
	"net"
	"reflect"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func TestPreviewInterceptorsPreserveOutgoingMetadata(t *testing.T) {
	ctx := metadata.NewOutgoingContext(t.Context(), metadata.Pairs("x-trace", "existing"))
	check := func(t *testing.T, ctx context.Context) {
		t.Helper()
		md, _ := metadata.FromOutgoingContext(ctx)
		if !reflect.DeepEqual(md.Get("ate-preview-allowed"), []string{"true"}) || !reflect.DeepEqual(md.Get("x-trace"), []string{"existing"}) {
			t.Fatalf("metadata = %v", md)
		}
	}
	t.Run("unary", func(t *testing.T) {
		called := false
		err := previewUnaryClientInterceptor(ctx, "/test/Unary", nil, nil, nil, func(ctx context.Context, _ string, _ any, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
			called = true
			check(t, ctx)
			return nil
		})
		if err != nil || !called {
			t.Fatal(err, called)
		}
	})
	t.Run("stream", func(t *testing.T) {
		called := false
		_, err := previewStreamClientInterceptor(ctx, &grpc.StreamDesc{}, nil, "/test/Stream", func(ctx context.Context, _ *grpc.StreamDesc, _ *grpc.ClientConn, _ string, _ ...grpc.CallOption) (grpc.ClientStream, error) {
			called = true
			check(t, ctx)
			return nil, nil
		})
		if err != nil || !called {
			t.Fatal(err, called)
		}
	})
	md, _ := metadata.FromOutgoingContext(ctx)
	if len(md.Get("ate-preview-allowed")) != 0 {
		t.Fatal("caller context mutated")
	}
}

// Exercise the installed streaming interceptor over gRPC, not just its callback.
func TestNewClientWithOptionsSendsStreamingPreviewMetadata(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan metadata.MD, 1)
	server := grpc.NewServer(grpc.UnknownServiceHandler(func(_ any, stream grpc.ServerStream) error {
		md, _ := metadata.FromIncomingContext(stream.Context())
		received <- md.Copy()
		if err := stream.RecvMsg(new(emptypb.Empty)); err != nil {
			return err
		}
		return stream.SendMsg(new(emptypb.Empty))
	}))
	go server.Serve(listener)
	defer server.Stop()
	client, err := NewClientWithOptions(ClientOptions{Target: listener.Addr().String(), Plaintext: true})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "x-correlation", "stream-preserved")
	stream, err := client.conn.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, "/test.Preview/Stream")
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.SendMsg(new(emptypb.Empty)); err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatal(err)
	}
	if err := stream.RecvMsg(new(emptypb.Empty)); err != nil {
		t.Fatal(err)
	}
	md := <-received
	if !reflect.DeepEqual(md.Get("ate-preview-allowed"), []string{"true"}) || !reflect.DeepEqual(md.Get("x-correlation"), []string{"stream-preserved"}) {
		t.Fatalf("server metadata = %v", md)
	}
}
