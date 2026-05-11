package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/rpc/jsonrpc"
	"os"
	"strings"
	"sync"
)

const (
	rpcChoices      = "RPC.Choices"
	rpcVoterChoices = "RPC.VoterChoices"
	rpcVote         = "RPC.Vote"
	rpcVerify       = "RPC.Verify"
	rpcAuth         = "RPC.Authenticate"
	rpcAuthStatus   = "RPC.AuthenticateStatus"
	rpcGetCert      = "RPC.GetCertificate"
	rpcSign         = "RPC.Sign"
	rpcSignStatus   = "RPC.SignStatus"
)

type TLSConfig struct {
	RootCAPath string
	CertPath   string
	KeyPath    string
	ServerName string
}

type Config struct {
	ChoicesAddress      string
	VotingAddress       string
	VerificationAddress string
	MIDAddress          string
	ChoicesServerName   string
	VotingServerName    string
	VerificationSNI     string
	MIDServerName       string
	TLS                 TLSConfig
}

type Client struct {
	transport *Transport

	choicesAddr      string
	votingAddr       string
	verificationAddr string
	midAddr          string
	choicesSNI       string
	votingSNI        string
	verificationSNI  string
	midSNI           string

	mu        sync.RWMutex
	sessionID string
}

type Transport struct {
	tls  *tls.Config
	dial func(context.Context, string) (net.Conn, error)
}

func New(cfg Config) (*Client, error) {
	tr, err := NewTransport(cfg.TLS)
	if err != nil {
		return nil, err
	}
	return &Client{
		transport:        tr,
		choicesAddr:      cfg.ChoicesAddress,
		votingAddr:       cfg.VotingAddress,
		verificationAddr: cfg.VerificationAddress,
		midAddr:          cfg.MIDAddress,
		choicesSNI:       firstNonEmpty(cfg.ChoicesServerName, cfg.TLS.ServerName),
		votingSNI:        firstNonEmpty(cfg.VotingServerName, cfg.TLS.ServerName),
		verificationSNI:  firstNonEmpty(cfg.VerificationSNI, cfg.TLS.ServerName),
		midSNI:           firstNonEmpty(cfg.MIDServerName, cfg.TLS.ServerName),
	}, nil
}

func NewTransport(cfg TLSConfig) (*Transport, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: cfg.ServerName,
	}
	if cfg.RootCAPath != "" {
		rootPEM, err := os.ReadFile(cfg.RootCAPath)
		if err != nil {
			return nil, fmt.Errorf("read root CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(rootPEM) {
			return nil, errors.New("parse root CA PEM")
		}
		tlsCfg.RootCAs = pool
	}
	if cfg.CertPath != "" || cfg.KeyPath != "" {
		if cfg.CertPath == "" || cfg.KeyPath == "" {
			return nil, errors.New("both client cert and key paths are required")
		}
		pair, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{pair}
	}
	return &Transport{tls: tlsCfg}, nil
}

func PEMBytesForCertificate(cert tls.Certificate) ([]byte, error) {
	if len(cert.Certificate) == 0 {
		return nil, errors.New("certificate chain is empty")
	}
	block := &pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}
	return pem.EncodeToMemory(block), nil
}

func (c *Client) SessionID() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.sessionID
}

func (c *Client) SetSessionID(sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessionID = sessionID
}

func (c *Client) Choices(ctx context.Context, req ChoicesArgs) (*ChoicesResponse, error) {
	if c.choicesAddr == "" {
		return nil, errors.New("choices address is not configured")
	}
	req.Header = c.buildHeader(ctx, req.Header)
	var resp ChoicesResponse
	if err := c.transport.Call(ctx, c.choicesAddr, c.choicesSNI, rpcChoices, req, &resp); err != nil {
		return nil, err
	}
	c.captureSession(resp.Header.SessionID)
	return &resp, nil
}

func (c *Client) VoterChoices(ctx context.Context, req VoterArgs) (*ChoicesResponse, error) {
	if c.choicesAddr == "" {
		return nil, errors.New("choices address is not configured")
	}
	req.Header = c.buildHeader(ctx, req.Header)
	var resp ChoicesResponse
	if err := c.transport.Call(ctx, c.choicesAddr, c.choicesSNI, rpcVoterChoices, req, &resp); err != nil {
		return nil, err
	}
	c.captureSession(resp.Header.SessionID)
	return &resp, nil
}

func (c *Client) Vote(ctx context.Context, req VoteArgs) (*VoteResponse, error) {
	if c.votingAddr == "" {
		return nil, errors.New("voting address is not configured")
	}
	req.Header = c.buildHeader(ctx, req.Header)
	var resp VoteResponse
	if err := c.transport.Call(ctx, c.votingAddr, c.votingSNI, rpcVote, req, &resp); err != nil {
		return nil, err
	}
	c.captureSession(resp.Header.SessionID)
	return &resp, nil
}

func (c *Client) Verify(ctx context.Context, req VerifyArgs) (*VerifyResponse, error) {
	if c.verificationAddr == "" {
		return nil, errors.New("verification address is not configured")
	}
	req.Header = c.buildHeader(ctx, req.Header)
	var resp VerifyResponse
	if err := c.transport.Call(ctx, c.verificationAddr, c.verificationSNI, rpcVerify, req, &resp); err != nil {
		return nil, err
	}
	c.captureSession(resp.Header.SessionID)
	return &resp, nil
}

func (c *Client) MIDAuthenticate(ctx context.Context, req MIDAuthenticateArgs) (*MIDAuthenticateResponse, error) {
	if c.midAddr == "" {
		return nil, errors.New("Mobile-ID address is not configured")
	}
	req.Header = c.buildHeader(ctx, req.Header)
	var resp MIDAuthenticateResponse
	if err := c.transport.Call(ctx, c.midAddr, c.midSNI, rpcAuth, req, &resp); err != nil {
		return nil, err
	}
	c.captureSession(resp.Header.SessionID)
	return &resp, nil
}

func (c *Client) MIDAuthenticateStatus(ctx context.Context, req MIDAuthenticateStatusArgs) (*MIDAuthenticateStatusResponse, error) {
	if c.midAddr == "" {
		return nil, errors.New("Mobile-ID address is not configured")
	}
	req.Header = c.buildHeader(ctx, req.Header)
	var resp MIDAuthenticateStatusResponse
	if err := c.transport.Call(ctx, c.midAddr, c.midSNI, rpcAuthStatus, req, &resp); err != nil {
		return nil, err
	}
	c.captureSession(resp.Header.SessionID)
	return &resp, nil
}

func (c *Client) MIDGetCertificate(ctx context.Context, req MIDCertificateArgs) (*MIDCertificateResponse, error) {
	if c.midAddr == "" {
		return nil, errors.New("Mobile-ID address is not configured")
	}
	req.Header = c.buildHeader(ctx, req.Header)
	var resp MIDCertificateResponse
	if err := c.transport.Call(ctx, c.midAddr, c.midSNI, rpcGetCert, req, &resp); err != nil {
		return nil, err
	}
	c.captureSession(resp.Header.SessionID)
	return &resp, nil
}

func (c *Client) MIDSign(ctx context.Context, req MIDSignArgs) (*MIDSignResponse, error) {
	if c.midAddr == "" {
		return nil, errors.New("Mobile-ID address is not configured")
	}
	req.Header = c.buildHeader(ctx, req.Header)
	var resp MIDSignResponse
	if err := c.transport.Call(ctx, c.midAddr, c.midSNI, rpcSign, req, &resp); err != nil {
		return nil, err
	}
	c.captureSession(resp.Header.SessionID)
	return &resp, nil
}

func (c *Client) MIDSignStatus(ctx context.Context, req MIDSignStatusArgs) (*MIDSignStatusResponse, error) {
	if c.midAddr == "" {
		return nil, errors.New("Mobile-ID address is not configured")
	}
	req.Header = c.buildHeader(ctx, req.Header)
	var resp MIDSignStatusResponse
	if err := c.transport.Call(ctx, c.midAddr, c.midSNI, rpcSignStatus, req, &resp); err != nil {
		return nil, err
	}
	c.captureSession(resp.Header.SessionID)
	return &resp, nil
}

func (t *Transport) Call(ctx context.Context, address, serverName, method string, req, resp any) error {
	conn, err := t.dialContext(ctx, address, serverName)
	if err != nil {
		return fmt.Errorf("dial %s: %w", address, withDialHint(address, serverName, err))
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return fmt.Errorf("set deadline: %w", err)
		}
	}

	client := jsonrpc.NewClient(conn)
	defer client.Close()

	if err := client.Call(method, req, resp); err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}
	return nil
}

func withDialHint(address, serverName string, err error) error {
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
		return err
	}
	host, _, splitErr := net.SplitHostPort(address)
	if splitErr != nil {
		host = address
	}
	if net.ParseIP(host) != nil {
		return err
	}
	if serverName == "" {
		return fmt.Errorf("%w; hostname %q did not resolve locally", err, host)
	}
	if strings.EqualFold(host, serverName) {
		return fmt.Errorf("%w; hostname %q did not resolve locally", err, host)
	}
	return fmt.Errorf("%w; hostname %q did not resolve locally, use a reachable IP or hostname for the dial address and keep -server-name %q for TLS/SNI", err, host, serverName)
}

func (t *Transport) dialContext(ctx context.Context, address, serverName string) (net.Conn, error) {
	if t.dial != nil {
		return t.dial(ctx, address)
	}
	dialer := &tls.Dialer{
		Config:    cloneTLSConfig(t.tls, serverName),
		NetDialer: &net.Dialer{},
	}
	return dialer.DialContext(ctx, "tcp", address)
}

func (c *Client) buildHeader(ctx context.Context, header Header) Header {
	reqHeader := header
	reqHeader.Ctx = ctx
	if reqHeader.SessionID == "" {
		reqHeader.SessionID = c.SessionID()
	}
	return reqHeader
}

func (c *Client) captureSession(sessionID string) {
	if sessionID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessionID = sessionID
}

func cloneTLSConfig(cfg *tls.Config, serverName string) *tls.Config {
	if cfg == nil {
		return &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}
	}
	cloned := cfg.Clone()
	cloned.ServerName = serverName
	return cloned
}

func cloneBytes(in []byte) []byte {
	if len(in) == 0 {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
