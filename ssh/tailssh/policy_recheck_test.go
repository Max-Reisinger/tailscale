// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd

package tailssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/user"
	"testing"
	"testing/synctest"
	"time"

	"tailscale.com/tailcfg"
	testssh "tailscale.com/tempfork/sshtest/ssh"
)

func TestPolicyRecheckRestrictions(t *testing.T) {
	lu := sessionTestUser(t)
	recorder := []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:1")}
	hold := &tailcfg.SSHAction{HoldAndDelegate: "https://unused/hold"}
	src := netip.MustParseAddrPort("1.2.3.4:1234")
	dst := netip.MustParseAddrPort("100.100.100.102:22")
	tests := []struct {
		name    string
		initial *tailcfg.SSHAction
		old     *tailcfg.SSHAction
		fresh   *tailcfg.SSHAction
		oldEnv  []string
		want    bool
	}{
		{
			name: "recording-fail-closed",
			old: &tailcfg.SSHAction{
				Accept:    true,
				Recorders: recorder,
			},
			fresh: &tailcfg.SSHAction{
				Accept:    true,
				Recorders: recorder,
				OnRecordingFailure: &tailcfg.SSHRecorderFailureAction{
					RejectSessionWithMessage:    "required",
					TerminateSessionWithMessage: "required",
				},
			},
			want: true,
		},
		{
			name:    "delegated-env-removed",
			old:     &tailcfg.SSHAction{Accept: true},
			initial: hold,
			fresh:   hold,
			oldEnv:  []string{"FOO_*"},
			want:    true,
		},
		{
			name:    "delegated-recording-added",
			old:     &tailcfg.SSHAction{Accept: true},
			initial: hold,
			fresh: &tailcfg.SSHAction{
				HoldAndDelegate: hold.HoldAndDelegate,
				Recorders:       recorder,
			},
			want: true,
		},
		{
			name: "delegated-failure-action-added",
			old:  &tailcfg.SSHAction{Accept: true},
			initial: &tailcfg.SSHAction{
				HoldAndDelegate: hold.HoldAndDelegate,
				Recorders:       recorder,
			},
			fresh: &tailcfg.SSHAction{
				HoldAndDelegate: hold.HoldAndDelegate,
				Recorders:       recorder,
				OnRecordingFailure: &tailcfg.SSHRecorderFailureAction{
					RejectSessionWithMessage: "required",
				},
			},
			want: true,
		},
		{
			name: "delegated-recorder-override",
			old: &tailcfg.SSHAction{
				Accept:    true,
				Recorders: recorder,
			},
			initial: hold,
			fresh: &tailcfg.SSHAction{
				HoldAndDelegate: hold.HoldAndDelegate,
				Recorders: []netip.AddrPort{
					netip.MustParseAddrPort("127.0.0.1:2"),
				},
			},
		},
		{
			name: "forwarding-removed",
			old: &tailcfg.SSHAction{
				Accept:                   true,
				AllowLocalPortForwarding: true,
			},
			fresh: &tailcfg.SSHAction{Accept: true},
			want:  true,
		},
		{
			name: "duration-shortened",
			old:  &tailcfg.SSHAction{Accept: true},
			fresh: &tailcfg.SSHAction{
				Accept:          true,
				SessionDuration: time.Minute,
			},
			want: true,
		},
		{
			name:  "accept-to-hold",
			old:   &tailcfg.SSHAction{Accept: true},
			fresh: hold,
			want:  true,
		},
		{
			name:  "unchanged",
			old:   &tailcfg.SSHAction{Accept: true},
			fresh: &tailcfg.SSHAction{Accept: true},
		},
	}
	for _, tt := range tests {
		for _, lookupFails := range []bool{false, true} {
			name := fmt.Sprintf("%s/lookupFails=%v", tt.name, lookupFails)
			t.Run(name, func(t *testing.T) {
				initial := tt.initial
				if initial == nil {
					initial = tt.old
				}
				p := &policyFlipper{
					localState: &localState{sshEnabled: true},
					rule:       newPolicyRule(tt.fresh, lu),
				}
				c := &conn{
					srv: &server{
						logf: t.Logf,
						lb:   p,
					},
					localUser:   lu,
					action0:     initial,
					finalAction: tt.old,
					acceptEnv:   tt.oldEnv,
					info: &sshConnInfo{
						sshUser: "alice",
						src:     src,
						dst:     dst,
					},
				}
				lookup := userLookup
				if lookupFails {
					lookup = func(string) (*userMeta, error) {
						return nil, errors.New("lookup unavailable")
					}
				}
				changed, why, _ := c.materialPolicyChangeWithUserLookup(lookup)
				if changed != tt.want {
					t.Fatalf("material=%v (%s), want %v", changed, why, tt.want)
				}
			})
		}
	}
}

func TestRecordingFailureChange(t *testing.T) {
	old := &tailcfg.SSHRecorderFailureAction{NotifyURL: "https://control/old"}
	fresh := &tailcfg.SSHRecorderFailureAction{NotifyURL: "https://control/new"}
	if !recFailureChanged(old, fresh) {
		t.Error("changed notification destination ignored")
	}
	if recFailureChanged(nil, &tailcfg.SSHRecorderFailureAction{}) {
		t.Error("nil and empty actions differ")
	}
}

func TestIsUserMissing(t *testing.T) {
	if !isUserMissing(fmt.Errorf("lookup: %w", user.UnknownUserError("gone"))) {
		t.Error("unknown user not recognized")
	}
	err := &os.PathError{
		Op:   "open",
		Path: "/etc/passwd",
		Err:  os.ErrNotExist,
	}
	if isUserMissing(err) {
		t.Error("missing database classified as missing user")
	}
}

type graceTestConn struct {
	net.Conn
	closed chan struct{}
}

func (c *graceTestConn) Close() error {
	close(c.closed)
	return nil
}

func TestLoginGraceExtensionDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		nc := &graceTestConn{closed: make(chan struct{})}
		c := &conn{srv: &server{logf: t.Logf}, netConn: nc}
		defer c.stopConnTimers()
		c.mu.Lock()
		c.armLoginGraceLocked(time.Second)
		c.mu.Unlock()
		c.extendLoginGrace(holdDelegateGrace)
		time.Sleep(2 * time.Second)
		synctest.Wait()
		select {
		case <-nc.closed:
			t.Fatal("superseded grace timer closed the connection")
		default:
		}
		time.Sleep(holdDelegateGrace)
		synctest.Wait()
		select {
		case <-nc.closed:
		default:
			t.Fatal("extended grace timer did not close the connection")
		}
	})
}

// blockedAuthSigner pauses after the server accepts an unsigned key query.
type blockedAuthSigner struct {
	testssh.Signer
	entered chan struct{}
	release chan struct{}
}

func (s *blockedAuthSigner) Sign(io.Reader, []byte) (*testssh.Signature, error) {
	close(s.entered)
	<-s.release
	return nil, errors.New("test stopped before signing")
}

func TestLoginGraceIncompleteAuthentication(t *testing.T) {
	for _, method := range []string{"unsigned-key", "partial-password"} {
		t.Run(method, func(t *testing.T) {
			lu := sessionTestUser(t)
			p := &policyFlipper{
				localState: &localState{
					sshEnabled: true,
					varRoot:    t.TempDir(),
				},
				rule: newPolicyRule(&tailcfg.SSHAction{Accept: true}, lu),
			}
			srv, sc, done := startPolicyConn(t, p)
			entered, release := make(chan struct{}), make(chan struct{})
			cfg := &testssh.ClientConfig{
				User:            "alice",
				HostKeyCallback: testssh.InsecureIgnoreHostKey(),
			}
			if method == "unsigned-key" {
				_, key, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				signer, err := testssh.NewSignerFromKey(key)
				if err != nil {
					t.Fatal(err)
				}
				cfg.SkipNoneAuth = true
				cfg.Auth = []testssh.AuthMethod{
					testssh.PublicKeys(&blockedAuthSigner{
						Signer:  signer,
						entered: entered,
						release: release,
					}),
				}
			} else {
				cfg.User += forcePasswordSuffix
				password := testssh.PasswordCallback(func() (string, error) {
					close(entered)
					<-release
					return "", errors.New("test stopped before password")
				})
				cfg.Auth = []testssh.AuthMethod{password}
			}
			clientDone := make(chan struct{})
			addr := sc.RemoteAddr().String()
			go func() {
				defer close(clientDone)
				cl, _, _, _ := testssh.NewClientConn(sc, addr, cfg)
				if cl != nil {
					cl.Close()
				}
			}()
			defer func() {
				close(release)
				sc.Close()
				<-clientDone
			}()
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
				t.Fatal("authentication did not reach continuation")
			}
			srv.mu.Lock()
			var c *conn
			for c = range srv.activeConns {
			}
			srv.mu.Unlock()
			if c == nil {
				t.Fatal("connection disappeared before grace expiry")
			}
			c.mu.Lock()
			active := c.graceTimer != nil && !c.authCompleted.Load()
			if active {
				c.graceTimer.Reset(0)
			}
			c.mu.Unlock()
			if !active {
				t.Fatal("incomplete authentication disabled login grace")
			}
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("grace expiry did not close the unfinished handshake")
			}
		})
	}
}
