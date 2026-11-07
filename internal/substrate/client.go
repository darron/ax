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
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/google/ax/pkg/apis/v1alpha1"
	ateapipb "go.ate.dev/substrate/api/ateapi/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// ClientOptions configures connection to the Substrate Control API server.
type ClientOptions struct {
	Target      string
	Authority   string
	TokenFile   string
	CAFile      string
	InsecureTLS bool
	Plaintext   bool
}

type tokenAuth struct {
	tokenFile string
}

func (t tokenAuth) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	if t.tokenFile == "" {
		return nil, nil
	}
	b, err := os.ReadFile(t.tokenFile)
	if err != nil {
		return nil, fmt.Errorf("reading token file %q: %w", t.tokenFile, err)
	}
	return map[string]string{
		"authorization": "Bearer " + strings.TrimSpace(string(b)),
	}, nil
}

func (t tokenAuth) RequireTransportSecurity() bool {
	return false
}

// Client wraps the Substrate Control API client.
type Client struct {
	conn    *grpc.ClientConn
	control ateapipb.ControlClient
}

// NewClientWithOptions connects to Substrate with full TLS and auth configuration.
func NewClientWithOptions(opts ClientOptions, extraDialOpts ...grpc.DialOption) (*Client, error) {
	if opts.Target == "" {
		opts.Target = "api.ate-system.svc.cluster.local:443"
	}

	// Auto-detect token file if not specified
	if opts.TokenFile == "" {
		if envToken := os.Getenv("SUBSTRATE_TOKEN_FILE"); envToken != "" {
			opts.TokenFile = envToken
		} else if _, err := os.Stat("/var/run/secrets/ateapi/token"); err == nil {
			opts.TokenFile = "/var/run/secrets/ateapi/token"
		}
	}

	// Auto-detect CA file if not specified
	if opts.CAFile == "" {
		if envCA := os.Getenv("SUBSTRATE_CA_FILE"); envCA != "" {
			opts.CAFile = envCA
		} else if _, err := os.Stat("/run/servicedns-ca/trust-bundle.pem"); err == nil {
			opts.CAFile = "/run/servicedns-ca/trust-bundle.pem"
		} else if _, err := os.Stat("/run/servicedns-ca/ca.pem"); err == nil {
			opts.CAFile = "/run/servicedns-ca/ca.pem"
		}
	}

	dialOpts := append([]grpc.DialOption{}, extraDialOpts...)
	// AX templates use a per-template snapshot storage location. Substrate RC1
	// requires explicit request opt-in in addition to its server preview gate.
	dialOpts = append(dialOpts,
		grpc.WithChainUnaryInterceptor(previewUnaryClientInterceptor),
		grpc.WithChainStreamInterceptor(previewStreamClientInterceptor),
	)

	if opts.Plaintext {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		tlsConfig := &tls.Config{}
		if opts.InsecureTLS {
			tlsConfig.InsecureSkipVerify = true
		}
		if opts.Authority != "" {
			tlsConfig.ServerName = opts.Authority
		} else if strings.Contains(opts.Target, "api.ate-system.svc") {
			tlsConfig.ServerName = "api.ate-system.svc"
		}

		if opts.CAFile != "" {
			caCert, err := os.ReadFile(opts.CAFile)
			if err != nil {
				return nil, fmt.Errorf("reading CA file %q: %w", opts.CAFile, err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caCert) {
				return nil, fmt.Errorf("failed to parse CA certificate from %q", opts.CAFile)
			}
			tlsConfig.RootCAs = pool
		}

		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	}

	authority := opts.Authority
	if authority == "" && strings.Contains(opts.Target, "api.ate-system.svc") {
		authority = "api.ate-system.svc"
	}
	if authority != "" {
		dialOpts = append(dialOpts, grpc.WithAuthority(authority))
	}

	if opts.TokenFile != "" {
		dialOpts = append(dialOpts, grpc.WithPerRPCCredentials(tokenAuth{tokenFile: opts.TokenFile}))
	}

	conn, err := grpc.NewClient(opts.Target, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Substrate control service at %s: %w", opts.Target, err)
	}
	return &Client{
		conn:    conn,
		control: ateapipb.NewControlClient(conn),
	}, nil
}

// Preview metadata is added on the control connection only. Append preserves
// authentication, tracing and caller metadata; it does not enable server gates.
func previewUnaryClientInterceptor(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	return invoker(metadata.AppendToOutgoingContext(ctx, "ate-preview-allowed", "true"), method, req, reply, cc, opts...)
}

func previewStreamClientInterceptor(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return streamer(metadata.AppendToOutgoingContext(ctx, "ate-preview-allowed", "true"), desc, cc, method, opts...)
}

// NewClient establishes a connection to the Substrate Control API server.
func NewClient(target string, opts ...grpc.DialOption) (*Client, error) {
	if len(opts) > 0 {
		if target == "" {
			target = "api.ate-system.svc.cluster.local:443"
		}
		conn, err := grpc.NewClient(target, opts...)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to Substrate control service at %s: %w", target, err)
		}
		return &Client{
			conn:    conn,
			control: ateapipb.NewControlClient(conn),
		}, nil
	}

	// Auto-configure options when no explicit dial options given
	return NewClientWithOptions(ClientOptions{Target: target})
}

// Close closes the gRPC connection.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// EnsureAtespace creates the atespace if it does not already exist.
func (c *Client) EnsureAtespace(ctx context.Context, atespace string) error {
	req := &ateapipb.CreateAtespaceRequest{
		Atespace: &ateapipb.Atespace{
			Metadata: &ateapipb.ResourceMetadata{
				Name: atespace,
			},
		},
	}
	err := retryOnCodes(ctx, func() error {
		_, err := c.control.CreateAtespace(ctx, req)
		return err
	}, codes.Unavailable)
	if err != nil && status.Code(err) == codes.PermissionDenied {
		// A server scoped to its own atespaces cannot create atespaces. Accept
		// one an operator created, which the server can still read.
		if _, getErr := c.control.GetAtespace(ctx, &ateapipb.GetAtespaceRequest{
			Atespace: &ateapipb.ObjectRef{Name: atespace},
		}); getErr == nil {
			return nil
		}
	}
	if err != nil && status.Code(err) != codes.AlreadyExists {
		return fmt.Errorf("creating atespace %q: %w", atespace, err)
	}
	return nil
}

// GetActorTemplate fetches an ActorTemplate by name.
func (c *Client) GetActorTemplate(ctx context.Context, atespace, templateName string) (*ateapipb.ActorTemplate, error) {
	req := &ateapipb.GetActorTemplateRequest{
		ActorTemplate: &ateapipb.ObjectRef{
			Atespace: atespace,
			Name:     templateName,
		},
	}
	var tmpl *ateapipb.ActorTemplate
	err := retryOnCodes(ctx, func() error {
		var err error
		tmpl, err = c.control.GetActorTemplate(ctx, req)
		return err
	}, codes.Unavailable)
	return tmpl, err
}

const (
	DefaultGuestCommand    = "/usr/local/bin/ax-task-runner"
	DefaultSnapshotsBucket = "gs://dberkov-gke-dev3/ate-env/"

	// defaultRetryAttempts is the maximum number of calls retryOnCodes makes. With
	// exponential backoff from defaultRetryInterval capped at maxRetryInterval
	// (±50% jitter), the total wait across all attempts is roughly 6s-20s.
	defaultRetryAttempts = 10

	// retryBackoffFactor is the multiplier applied to the backoff after each failed attempt.
	retryBackoffFactor = 2

	// actorDeletingWaitAttempts bounds how many times EnsureActor retries creation
	// while a previous actor with the same name is still being deleted.
	actorDeletingWaitAttempts = 20
)

var (
	// defaultRetryInterval is the initial backoff for retryOnCodes and the poll
	// interval used while waiting for actor deletion.
	defaultRetryInterval = 200 * time.Millisecond

	// maxRetryInterval caps the exponential backoff in retryOnCodes.
	maxRetryInterval = 2 * time.Second

	// actorDeletingWaitInterval is the interval between creation attempts while a
	// previous actor is still deleting (actorDeletingWaitAttempts * interval ~= 10s).
	actorDeletingWaitInterval = 500 * time.Millisecond
)

// IsTransientError reports whether err represents a transient Substrate
// control-plane unavailability or timeout rather than a permanent failure.
func IsTransientError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.Unavailable, codes.DeadlineExceeded:
			return true
		}
	}
	return false
}

// retryOnCodes calls fn until it succeeds, returns an error whose gRPC code is not in
// retryable, defaultRetryAttempts is exhausted, or ctx is done. Between attempts it
// waits with jittered exponential backoff starting at defaultRetryInterval and
// capped at maxRetryInterval.
func retryOnCodes(ctx context.Context, fn func() error, retryable ...codes.Code) error {
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = defaultRetryInterval
	b.MaxInterval = maxRetryInterval
	b.Multiplier = retryBackoffFactor

	_, err := backoff.Retry(ctx, func() (struct{}, error) {
		err := fn()
		if err != nil && !slices.Contains(retryable, status.Code(err)) {
			return struct{}{}, backoff.Permanent(err)
		}
		return struct{}{}, err
	}, backoff.WithBackOff(b), backoff.WithMaxTries(defaultRetryAttempts))

	// backoff.Retry returns the *PermanentError wrapper as-is when the attempt limit
	// is hit on the same try, so unwrap it to always surface the original error.
	var permanent *backoff.PermanentError
	if errors.As(err, &permanent) {
		return permanent.Unwrap()
	}
	return err
}

const (
	// DefaultCPUMillicores is the default CPU limit (1 core) applied to an
	// ActorTemplate when a Task omits spec.resources.limits.cpu.
	DefaultCPUMillicores int64 = 1000
	// DefaultMemoryBytes is the default memory limit (512 MiB) applied to an
	// ActorTemplate when a Task omits spec.resources.limits.memory.
	DefaultMemoryBytes int64 = 512 << 20
)

// ResourceLimits translates a Task's resource limits into the Substrate
// ActorTemplate resources block. Substrate sizes a sandbox by limits alone
// (requests are rejected by v1alpha1.ValidateResources). It returns nil when no
// limit is set so the template uses the default sandbox limits.
func ResourceLimits(reqs *v1alpha1.ResourcesSpec) *ateapipb.ResourceRequirements {
	limits := reqs.GetLimits()
	cpuStr := limits.GetCpu()
	memStr := limits.GetMemory()
	if cpuStr == "" && memStr == "" {
		return nil
	}
	out := &ateapipb.Resources{
		CpuMillicores: DefaultCPUMillicores,
		MemoryBytes:   DefaultMemoryBytes,
	}
	if cpuStr != "" {
		if cpu, err := v1alpha1.ParseCPUMillicores(cpuStr); err == nil {
			out.CpuMillicores = cpu
		}
	}
	if memStr != "" {
		if mem, err := v1alpha1.ParseMemoryBytes(memStr); err == nil {
			out.MemoryBytes = mem
		}
	}
	return &ateapipb.ResourceRequirements{Limits: out}
}

// workerSelectorFromEnv reads AX_WORKER_SELECTOR, comma-separated key=value
// labels, so task actors land only on the worker pools carrying them.
func workerSelectorFromEnv() *ateapipb.Selector {
	raw := os.Getenv("AX_WORKER_SELECTOR")
	if raw == "" {
		return nil
	}
	labels := map[string]string{}
	for _, pair := range strings.Split(raw, ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if ok && key != "" {
			labels[key] = value
		}
	}
	if len(labels) == 0 {
		return nil
	}
	return &ateapipb.Selector{MatchLabels: labels}
}

// goldenSnapshotConfigFromEnv reads AX_GOLDEN_SNAPSHOTS. "disabled" turns off
// the golden actor Substrate otherwise builds for every template, which needs
// a worker slot as large as the task's. Each task gets its own template, so
// the golden snapshot is reused only if EnsureActor deletes and recreates a
// crashed actor it could not revert; that recreated actor then boots without
// it, losing only its faster cold start. Any other value keeps Substrate's
// default.
func goldenSnapshotConfigFromEnv() *ateapipb.GoldenSnapshotConfig {
	if strings.TrimSpace(os.Getenv("AX_GOLDEN_SNAPSHOTS")) != "disabled" {
		return nil
	}
	return &ateapipb.GoldenSnapshotConfig{Mode: ateapipb.GoldenSnapshotMode_GOLDEN_SNAPSHOT_MODE_DISABLED}
}

// capabilityName is a Linux capability without its CAP_ prefix, as Substrate's
// ateapi.Capabilities expects. "ALL" is not a capability name.
var capabilityName = regexp.MustCompile(`^[A-Z][A-Z_]*[A-Z]$`)

// securityContextFromEnv reads AX_TASK_CAPABILITIES_ADD, comma-separated
// capability names (no CAP_ prefix) granted to task containers on top of
// Substrate's default AUDIT_WRITE, KILL and NET_BIND_SERVICE. Without them a
// task's root cannot chown, override file permissions or switch users, so an
// image that runs its agent as a non-root user cannot start it.
// Invalid names or ALL leave the default set unchanged.
func securityContextFromEnv() *ateapipb.SecurityContext {
	raw := os.Getenv("AX_TASK_CAPABILITIES_ADD")
	if raw == "" {
		return nil
	}
	var add []string
	seen := map[string]bool{}
	for _, name := range strings.Split(raw, ",") {
		name = strings.TrimSpace(name)
		if name == "ALL" || !capabilityName.MatchString(name) {
			slog.Warn("ignoring AX_TASK_CAPABILITIES_ADD: invalid capability name", "name", name)
			return nil
		}
		if !seen[name] {
			seen[name] = true
			add = append(add, name)
		}
	}
	slices.Sort(add)
	return &ateapipb.SecurityContext{Capabilities: &ateapipb.Capabilities{Add: add}}
}

// BuildActorTemplate constructs a Substrate ActorTemplate based on the standard ate-env specification.
// A nil resources applies DefaultCPUMillicores and DefaultMemoryBytes.
func BuildActorTemplate(atespace, name, image string, envMap map[string]string, command []string, snapshotsBucket string, resources *ateapipb.ResourceRequirements) *ateapipb.ActorTemplate {
	if atespace == "" {
		atespace = "default"
	}
	if image == "" {
		image = v1alpha1.DefaultTaskImage
	}
	if len(command) == 0 {
		command = []string{DefaultGuestCommand}
	}
	if snapshotsBucket == "" {
		if envBucket := os.Getenv("AX_SNAPSHOTS_BUCKET"); envBucket != "" {
			snapshotsBucket = envBucket
		} else {
			snapshotsBucket = DefaultSnapshotsBucket
		}
	}

	var envList []*ateapipb.EnvVar
	for k, v := range envMap {
		envList = append(envList, &ateapipb.EnvVar{
			Name:  k,
			Value: v,
		})
	}

	cpuMillicores := DefaultCPUMillicores
	memoryBytes := DefaultMemoryBytes
	if limits := resources.GetLimits(); limits != nil {
		if limits.GetCpuMillicores() > 0 {
			cpuMillicores = limits.GetCpuMillicores()
		}
		if limits.GetMemoryBytes() > 0 {
			memoryBytes = limits.GetMemoryBytes()
		}
	}

	return &ateapipb.ActorTemplate{
		Metadata: &ateapipb.ResourceMetadata{
			Name:     name,
			Atespace: atespace,
		},
		Containers: []*ateapipb.Container{{
			Name:    "guest",
			Image:   image,
			Command: command,
			Env:     envList,
			WakeupProbe: &ateapipb.WakeupProbe{
				HttpGet: &ateapipb.HttpGetAction{
					Path: "/readyz",
					Port: 80,
				},
			},
			VolumeMounts: []*ateapipb.VolumeMount{{
				Name:      "workspace",
				MountPath: "/workspace",
			}},
			SecurityContext: securityContextFromEnv(),
		}},
		Volumes: []*ateapipb.Volume{{
			Name:       "workspace",
			DurableDir: &ateapipb.DurableDirVolumeSource{},
		}},
		WorkerSelector: workerSelectorFromEnv(),
		SnapshotConfig: &ateapipb.SnapshotConfig{
			StorageLocation:      snapshotsBucket,
			PreferredFidelity:    ateapipb.SnapshotFidelity_SNAPSHOT_FIDELITY_VOLUMES,
			GoldenSnapshotConfig: goldenSnapshotConfigFromEnv(),
		},
		Resources: &ateapipb.ResourceRequirements{
			Limits: &ateapipb.Resources{
				CpuMillicores: cpuMillicores,
				MemoryBytes:   memoryBytes,
			},
		},
	}
}

// EnsureActorTemplateWithImage creates an ActorTemplate using the specified container image,
// resource limits (nil for default limits), and optional environment variables.
func (c *Client) EnsureActorTemplateWithImage(ctx context.Context, baseAtespace, baseTemplate, targetAtespace, targetTemplate, image string, resources *ateapipb.ResourceRequirements, extraEnv ...map[string]string) (*ateapipb.ActorTemplate, error) {
	existing, err := c.GetActorTemplate(ctx, targetAtespace, targetTemplate)
	if err == nil && existing != nil {
		return existing, nil
	}

	envMap := make(map[string]string)
	for _, envs := range extraEnv {
		for k, v := range envs {
			envMap[k] = v
		}
	}

	tmpl := BuildActorTemplate(targetAtespace, targetTemplate, image, envMap, nil, "", resources)
	req := &ateapipb.CreateActorTemplateRequest{
		ActorTemplate: tmpl,
	}
	var created *ateapipb.ActorTemplate
	err = retryOnCodes(ctx, func() error {
		var err error
		created, err = c.control.CreateActorTemplate(ctx, req)
		return err
	}, codes.Unavailable)
	if err != nil && status.Code(err) != codes.AlreadyExists {
		return nil, fmt.Errorf("creating actor template %s/%s: %w", targetAtespace, targetTemplate, err)
	}
	if created != nil {
		return created, nil
	}
	return c.GetActorTemplate(ctx, targetAtespace, targetTemplate)
}

// EnsureActor creates an Actor in the specified atespace deriving from an ActorTemplate.
func (c *Client) EnsureActor(ctx context.Context, atespace, actorName, templateAtespace, templateName string) (*ateapipb.Actor, error) {
	req := &ateapipb.CreateActorRequest{
		Actor: &ateapipb.Actor{
			Metadata: &ateapipb.ResourceMetadata{
				Atespace: atespace,
				Name:     actorName,
			},
			ActorTemplate: &ateapipb.ObjectRef{
				Atespace: templateAtespace,
				Name:     templateName,
			},
		},
	}
	var actor *ateapipb.Actor
	err := retryOnCodes(ctx, func() error {
		var err error
		actor, err = c.control.CreateActor(ctx, req)
		return err
	}, codes.Unavailable)
	if err != nil {
		if status.Code(err) == codes.AlreadyExists {
			existing, getErr := c.GetActor(ctx, atespace, actorName)
			if getErr == nil && existing != nil {
				state := existing.GetStatus().GetState()
				if state == ateapipb.ActorState_ACTOR_STATE_CRASHED {
					// Revert to the last snapshot so the workspace survives the crash.
					var reverted *ateapipb.RevertActorResponse
					revertErr := retryOnCodes(ctx, func() error {
						var err error
						reverted, err = c.control.RevertActor(ctx, &ateapipb.RevertActorRequest{
							Actor: &ateapipb.ObjectRef{
								Atespace: atespace,
								Name:     actorName,
							},
						})
						return err
					}, codes.Unavailable)
					if revertErr == nil {
						slog.Warn("existing actor is crashed, reverted to its last snapshot", "actor", actorName)
						return reverted.GetActor(), nil
					}
					slog.Warn("existing actor is crashed and could not be reverted, deleting and recreating", "actor", actorName, "error", revertErr)
					if err := c.DeleteActor(ctx, atespace, actorName); err != nil {
						return nil, err
					}
					err = retryOnCodes(ctx, func() error {
						var err error
						actor, err = c.control.CreateActor(ctx, req)
						return err
					}, codes.Unavailable)
					if err == nil {
						return actor, nil
					}
					return nil, fmt.Errorf("recreating actor %s/%s after crash: %w", atespace, actorName, err)
				}
				if state == ateapipb.ActorState_ACTOR_STATE_DELETING {
					// Wait briefly for previous actor deletion to finalize before recreating
					for i := 0; i < actorDeletingWaitAttempts; i++ {
						select {
						case <-ctx.Done():
							return nil, ctx.Err()
						case <-time.After(actorDeletingWaitInterval):
						}
						actor, err = c.control.CreateActor(ctx, req)
						if err == nil {
							return actor, nil
						}
						if status.Code(err) != codes.AlreadyExists {
							break
						}
					}
					return nil, fmt.Errorf("actor %s/%s is still deleting; please retry", atespace, actorName)
				}
			}
			return existing, getErr
		}
		return nil, fmt.Errorf("creating actor %s/%s: %w", atespace, actorName, err)
	}
	return actor, nil
}

// ResumeActor resumes the specified actor onto a worker and returns the worker details.
func (c *Client) ResumeActor(ctx context.Context, atespace, actorName string) (*ateapipb.Actor, string, error) {
	req := &ateapipb.ResumeActorRequest{
		Actor: &ateapipb.ObjectRef{
			Atespace: atespace,
			Name:     actorName,
		},
	}
	var resp *ateapipb.ResumeActorResponse
	err := retryOnCodes(ctx, func() error {
		var err error
		resp, err = c.control.ResumeActor(ctx, req)
		return err
	}, codes.Aborted, codes.Unavailable)
	if err != nil {
		return nil, "", fmt.Errorf("resuming actor %s/%s: %w", atespace, actorName, err)
	}
	if resp.GetActor() == nil {
		return nil, "", fmt.Errorf("nil actor returned when resuming %s/%s", atespace, actorName)
	}
	return resp.GetActor(), WorkerIP(resp.GetActor()), nil
}

// WorkerIP returns the pod IP of the worker hosting the actor, or "" when the
// actor has no worker (for example while it is suspended).
func WorkerIP(actor *ateapipb.Actor) string {
	if ips := actor.GetStatus().GetWorkerAssignment().GetWorkerPodIps(); len(ips) > 0 {
		return ips[0]
	}
	return ""
}

// SuspendActor suspends the specified actor, triggering state checkpointing.
func (c *Client) SuspendActor(ctx context.Context, atespace, actorName string) error {
	req := &ateapipb.SuspendActorRequest{
		Actor: &ateapipb.ObjectRef{
			Atespace: atespace,
			Name:     actorName,
		},
		// Checkpoint a running actor durably before acknowledging the suspend.
		// Substrate's default asynchronous upload can still be pending when
		// the actor resumes, and RevertActor discards that copy. This does not
		// promote an already-suspended actor's older node-local checkpoint.
		Options: &ateapipb.SuspendOptions{
			Mode: ateapipb.DurabilityMode_DURABILITY_MODE_SYNCHRONOUS,
		},
	}
	err := retryOnCodes(ctx, func() error {
		_, err := c.control.SuspendActor(ctx, req)
		return err
	}, codes.Aborted, codes.Unavailable)
	if err != nil {
		return fmt.Errorf("suspending actor %s/%s: %w", atespace, actorName, err)
	}
	return nil
}

// GetActor fetches an Actor by name.
func (c *Client) GetActor(ctx context.Context, atespace, actorName string) (*ateapipb.Actor, error) {
	req := &ateapipb.GetActorRequest{
		Actor: &ateapipb.ObjectRef{
			Atespace: atespace,
			Name:     actorName,
		},
	}
	var actor *ateapipb.Actor
	err := retryOnCodes(ctx, func() error {
		var err error
		actor, err = c.control.GetActor(ctx, req)
		return err
	}, codes.Unavailable)
	return actor, err
}

// ListActors returns every Actor in the given atespace, or in all atespaces
// when atespace is empty.
func (c *Client) ListActors(ctx context.Context, atespace string) ([]*ateapipb.Actor, error) {
	var actors []*ateapipb.Actor
	req := &ateapipb.ListActorsRequest{Atespace: atespace, Options: &ateapipb.ListOptions{}}
	for {
		var resp *ateapipb.ListActorsResponse
		err := retryOnCodes(ctx, func() error {
			var err error
			resp, err = c.control.ListActors(ctx, req)
			return err
		}, codes.Unavailable)
		if err != nil {
			return nil, fmt.Errorf("listing actors in %q: %w", atespace, err)
		}
		actors = append(actors, resp.GetActors()...)
		if resp.GetNextPageToken() == "" {
			return actors, nil
		}
		req.Options.PageToken = resp.GetNextPageToken()
	}
}

// DeleteActor deletes the specified actor from Substrate and blocks until the actor
// is fully deleted.
func (c *Client) DeleteActor(ctx context.Context, atespace, actorName string) error {
	req := &ateapipb.DeleteActorRequest{
		Actor: &ateapipb.ObjectRef{
			Atespace: atespace,
			Name:     actorName,
		},
	}
	err := retryOnCodes(ctx, func() error {
		_, err := c.control.DeleteActor(ctx, req)
		return err
	}, codes.Aborted, codes.Unavailable)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil
		}
		return fmt.Errorf("deleting actor %s/%s: %w", atespace, actorName, err)
	}

	getReq := &ateapipb.GetActorRequest{
		Actor: &ateapipb.ObjectRef{
			Atespace: atespace,
			Name:     actorName,
		},
	}

	// Fast path: check if the actor was deleted synchronously.
	_, err = c.control.GetActor(ctx, getReq)
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return nil
		}
		if ctx.Err() != nil {
			return fmt.Errorf("waiting for actor %s/%s deletion: %w", atespace, actorName, ctx.Err())
		}
	}

	ticker := time.NewTicker(defaultRetryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for actor %s/%s deletion: %w", atespace, actorName, ctx.Err())
		case <-ticker.C:
			_, err := c.control.GetActor(ctx, getReq)
			if err != nil {
				if status.Code(err) == codes.NotFound {
					return nil
				}
				if ctx.Err() != nil {
					return fmt.Errorf("waiting for actor %s/%s deletion: %w", atespace, actorName, ctx.Err())
				}
			}
		}
	}
}

// ListActorTemplates returns all ActorTemplates in the given atespace.
func (c *Client) ListActorTemplates(ctx context.Context, atespace string) ([]*ateapipb.ActorTemplate, error) {
	var resp *ateapipb.ListActorTemplatesResponse
	err := retryOnCodes(ctx, func() error {
		var err error
		resp, err = c.control.ListActorTemplates(ctx, &ateapipb.ListActorTemplatesRequest{Atespace: atespace})
		return err
	}, codes.Unavailable)
	if err != nil {
		return nil, fmt.Errorf("listing actor templates in %s: %w", atespace, err)
	}
	if resp.GetNextPageToken() != "" {
		slog.Warn("actor template listing was truncated", "atespace", atespace)
	}
	return resp.GetActorTemplates(), nil
}

// DeleteActorTemplate deletes the specified ActorTemplate. A missing template is not an error.
func (c *Client) DeleteActorTemplate(ctx context.Context, atespace, templateName string) error {
	req := &ateapipb.DeleteActorTemplateRequest{
		ActorTemplate: &ateapipb.ObjectRef{
			Atespace: atespace,
			Name:     templateName,
		},
	}
	err := retryOnCodes(ctx, func() error {
		_, err := c.control.DeleteActorTemplate(ctx, req)
		return err
	}, codes.Aborted, codes.Unavailable)
	if err != nil && status.Code(err) != codes.NotFound {
		return fmt.Errorf("deleting actor template %s/%s: %w", atespace, templateName, err)
	}
	return nil
}
