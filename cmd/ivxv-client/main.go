package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/janwil/ivxv-codex-golang/client"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	// Pre-parse the global -config flag before dispatching to subcommands.
	// This allows: ivxv-client -config myconfig.json <subcommand> [flags...]
	pre := flag.NewFlagSet("ivxv-client", flag.ContinueOnError)
	pre.SetOutput(io.Discard)
	configPath := pre.String("config", "config.json", "path to JSON config file")
	// Ignore parse errors here; subcommand flagsets will catch real errors.
	_ = pre.Parse(args)

	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}

	subcmdArgs := pre.Args()
	if len(subcmdArgs) == 0 {
		return usageError()
	}

	switch subcmdArgs[0] {
	case "inspect-bdoc":
		return runInspectBDOC(subcmdArgs[1:], cfg)
	case "interactive-mid-vote":
		return runInteractiveMIDVote(subcmdArgs[1:], cfg)
	case "mid-auth":
		return runMIDAuthenticate(subcmdArgs[1:], cfg)
	case "mid-auth-status":
		return runMIDAuthenticateStatus(subcmdArgs[1:], cfg)
	case "validate-vote":
		return runValidateVote(subcmdArgs[1:], cfg)
	case "voter-choices":
		return runVoterChoices(subcmdArgs[1:], cfg)
	case "vote":
		return runVote(subcmdArgs[1:], cfg)
	case "verify":
		return runVerify(subcmdArgs[1:], cfg)
	default:
		return usageError()
	}
}

func runMIDAuthenticate(args []string, cfg *appConfig) error {
	fs := flag.NewFlagSet("mid-auth", flag.ContinueOnError)
	common := parseCommonFlags(fs, cfg)
	idCode := fs.String("id-code", "", "Estonian personal code")
	phoneNo := fs.String("phone-no", "", "Mobile-ID phone number")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := common.loadSession(); err != nil {
		return err
	}
	if *idCode == "" || *phoneNo == "" {
		return errors.New("mid-auth: -id-code and -phone-no are required")
	}

	c, err := common.newClient()
	if err != nil {
		return err
	}
	header, err := common.header()
	if err != nil {
		return err
	}
	ctx, cancel := common.requestContext()
	defer cancel()
	resp, err := c.MIDAuthenticate(ctx, client.MIDAuthenticateArgs{
		Header:  header,
		IDCode:  *idCode,
		PhoneNo: *phoneNo,
	})
	if err != nil {
		return err
	}
	common.persistSession(c.SessionID())
	if err := common.persistAuthState(authState{
		SessionID:      c.SessionID(),
		AuthMethod:     "ticket",
		DataToken:      resp.DataToken,
		MIDSessionCode: resp.SessionCode,
		MIDChallenge:   resp.Challenge,
	}); err != nil {
		return err
	}
	return writeJSON(struct {
		SessionID   string `json:"sessionId"`
		SessionCode string `json:"sessionCode"`
		Challenge   string `json:"challenge"`
		DataToken   string `json:"dataToken"`
	}{
		SessionID:   c.SessionID(),
		SessionCode: resp.SessionCode,
		Challenge:   base64.StdEncoding.EncodeToString(resp.Challenge),
		DataToken:   base64.StdEncoding.EncodeToString(resp.DataToken),
	})
}

func runMIDAuthenticateStatus(args []string, cfg *appConfig) error {
	fs := flag.NewFlagSet("mid-auth-status", flag.ContinueOnError)
	common := parseCommonFlags(fs, cfg)
	sessionCode := fs.String("session-code", "", "Mobile-ID session code")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := common.loadSession(); err != nil {
		return err
	}

	state, err := common.authState()
	if err != nil {
		return err
	}
	if *sessionCode == "" {
		*sessionCode = state.MIDSessionCode
	}
	if *sessionCode == "" {
		return errors.New("mid-auth-status: -session-code is required")
	}

	c, err := common.newClient()
	if err != nil {
		return err
	}
	header, err := common.header()
	if err != nil {
		return err
	}
	ctx, cancel := common.requestContext()
	defer cancel()
	resp, err := c.MIDAuthenticateStatus(ctx, client.MIDAuthenticateStatusArgs{
		Header:      header,
		SessionCode: *sessionCode,
	})
	if err != nil {
		return err
	}
	common.persistSession(c.SessionID())

	nextState := state
	nextState.SessionID = c.SessionID()
	nextState.AuthMethod = "ticket"
	nextState.MIDSessionCode = *sessionCode
	if resp.Status == "OK" {
		nextState.AuthToken = resp.AuthToken
	}
	if err := common.persistAuthState(nextState); err != nil {
		return err
	}

	return writeJSON(struct {
		SessionID    string `json:"sessionId"`
		Status       string `json:"status"`
		GivenName    string `json:"givenName"`
		Surname      string `json:"surname"`
		PersonalCode string `json:"personalCode"`
		AuthToken    string `json:"authToken,omitempty"`
		DataToken    string `json:"dataToken,omitempty"`
	}{
		SessionID:    c.SessionID(),
		Status:       resp.Status,
		GivenName:    resp.GivenName,
		Surname:      resp.Surname,
		PersonalCode: resp.PersonalCode,
		AuthToken:    encodeOptionalBase64(resp.AuthToken),
		DataToken:    encodeOptionalBase64(nextState.DataToken),
	})
}


func runVoterChoices(args []string, cfg *appConfig) error {
	fs := flag.NewFlagSet("voter-choices", flag.ContinueOnError)
	common := parseCommonFlags(fs, cfg)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := common.loadSession(); err != nil {
		return err
	}

	c, err := common.newClient()
	if err != nil {
		return err
	}
	header, err := common.header()
	if err != nil {
		return err
	}
	ctx, cancel := common.requestContext()
	defer cancel()
	resp, err := c.VoterChoices(ctx, client.VoterArgs{
		Header: header,
	})
	if err != nil {
		return err
	}
	common.persistSession(c.SessionID())
	return writeJSON(struct {
		SessionID string `json:"sessionId"`
		Choices   string `json:"choices"`
		List      string `json:"list"`
		Voted     bool   `json:"voted"`
	}{
		SessionID: c.SessionID(),
		Choices:   resp.Choices,
		List:      string(resp.List),
		Voted:     resp.Voted,
	})
}

func runVote(args []string, cfg *appConfig) error {
	fs := flag.NewFlagSet("vote", flag.ContinueOnError)
	common := parseCommonFlags(fs, cfg)
	choicesID := fs.String("choices", "", "choice list identifier")
	containerType := fs.String("type", "", "container type such as bdoc")
	votePath := fs.String("vote-file", "", "path to the signed vote container")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := common.loadSession(); err != nil {
		return err
	}
	if *choicesID == "" || *containerType == "" || *votePath == "" {
		return errors.New("vote: -choices, -type, and -vote-file are required")
	}

	votePayload, err := os.ReadFile(*votePath)
	if err != nil {
		return err
	}
	c, err := common.newClient()
	if err != nil {
		return err
	}
	header, err := common.header()
	if err != nil {
		return err
	}
	ctx, cancel := common.requestContext()
	defer cancel()
	resp, err := c.Vote(ctx, client.VoteArgs{
		Header:  header,
		Choices: *choicesID,
		Type:    *containerType,
		Vote:    votePayload,
	})
	if err != nil {
		return err
	}
	common.persistSession(c.SessionID())
	return writeJSON(struct {
		SessionID     string            `json:"sessionId"`
		VoteIDHex     string            `json:"voteIdHex"`
		Qualification map[string]string `json:"qualification"`
		TestVote      bool              `json:"testVote"`
	}{
		SessionID:     c.SessionID(),
		VoteIDHex:     hex.EncodeToString(resp.VoteID),
		Qualification: encodeByteMap(resp.Qualification),
		TestVote:      resp.TestVote,
	})
}

func runVerify(args []string, cfg *appConfig) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	common := parseCommonFlags(fs, cfg)
	voteIDHex := fs.String("vote-id", "", "hex-encoded vote ID")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := common.loadSession(); err != nil {
		return err
	}
	if *voteIDHex == "" {
		return errors.New("verify: -vote-id is required")
	}

	voteID, err := hex.DecodeString(*voteIDHex)
	if err != nil {
		return err
	}

	c, err := common.newClient()
	if err != nil {
		return err
	}
	header, err := common.header()
	if err != nil {
		return err
	}
	ctx, cancel := common.requestContext()
	defer cancel()
	resp, err := c.Verify(ctx, client.VerifyArgs{
		Header: header,
		VoteID: voteID,
	})
	if err != nil {
		return err
	}
	common.persistSession(c.SessionID())
	return writeJSON(struct {
		SessionID     string            `json:"sessionId"`
		Type          string            `json:"type"`
		VoteBase64    string            `json:"voteBase64"`
		ChoicesList   string            `json:"choicesList"`
		Qualification map[string]string `json:"qualification"`
	}{
		SessionID:     c.SessionID(),
		Type:          resp.Type,
		VoteBase64:    base64.StdEncoding.EncodeToString(resp.Vote),
		ChoicesList:   string(resp.ChoicesList),
		Qualification: encodeByteMap(resp.Qualification),
	})
}

type commonFlags struct {
	midAddr                *string
	choicesAddr            *string
	votingAddr             *string
	verificationAddr       *string
	caPath                 *string
	certPath               *string
	keyPath                *string
	serverName             *string
	midServerName          *string
	choicesServerName      *string
	votingServerName       *string
	verificationServerName *string
	sessionID              *string
	sessionFile            *string
	authStateFile          *string
	osName                 *string
	authMethod *string
	timeout    *time.Duration
}

func parseCommonFlags(fs *flag.FlagSet, cfg *appConfig) *commonFlags {
	fs.SetOutput(os.Stderr)
	return &commonFlags{
		midAddr:                fs.String("mid-addr", cfg.MIDAddr, "Mobile-ID service host:port"),
		choicesAddr:            fs.String("choices-addr", cfg.ChoicesAddr, "choices service host:port"),
		votingAddr:             fs.String("voting-addr", cfg.VotingAddr, "voting service host:port"),
		verificationAddr:       fs.String("verification-addr", cfg.VerificationAddr, "verification service host:port"),
		caPath:                 fs.String("ca", cfg.CAPath, "CA certificate PEM path"),
		certPath:               fs.String("cert", cfg.CertPath, "client certificate PEM path"),
		keyPath:                fs.String("key", cfg.KeyPath, "client private key PEM path"),
		serverName:             fs.String("server-name", cfg.ServerName, "TLS server name override used as a fallback for all services"),
		midServerName:          fs.String("mid-server-name", cfg.MIDServerName, "Mobile-ID TLS server name override"),
		choicesServerName:      fs.String("choices-server-name", cfg.ChoicesServerName, "choices TLS server name override"),
		votingServerName:       fs.String("voting-server-name", cfg.VotingServerName, "voting TLS server name override"),
		verificationServerName: fs.String("verification-server-name", cfg.VerificationServerName, "verification TLS server name override"),
		sessionID:              fs.String("session-id", "", "existing session ID"),
		sessionFile:            fs.String("session-file", cfg.SessionFile, "path to persist the session ID"),
		authStateFile:          fs.String("auth-state-file", cfg.AuthStateFile, "path to persist auth tokens and flow state"),
		osName:                 fs.String("os", cfg.OSName, "client OS string"),
		authMethod: fs.String("auth-method", cfg.AuthMethod, "IVXV auth method such as id, mid, sid, wid"),
		timeout:    fs.Duration("timeout", cfg.Timeout.Duration, "request timeout"),
	}
}

func (c *commonFlags) loadSession() error {
	state, err := c.authState()
	if err != nil {
		return err
	}
	if *c.sessionID == "" && state.SessionID != "" {
		*c.sessionID = state.SessionID
	}
	if *c.sessionID == "" && *c.sessionFile != "" {
		if b, err := os.ReadFile(*c.sessionFile); err == nil {
			*c.sessionID = string(bytesTrimSpace(b))
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("read session file: %w", err)
		}
	}
	return nil
}


func (c *commonFlags) newClient() (*client.Client, error) {
	cl, err := client.New(client.Config{
		MIDAddress:          *c.midAddr,
		ChoicesAddress:      *c.choicesAddr,
		VotingAddress:       *c.votingAddr,
		VerificationAddress: *c.verificationAddr,
		MIDServerName:       firstNonEmpty(*c.midServerName, *c.serverName),
		ChoicesServerName:   firstNonEmpty(*c.choicesServerName, *c.serverName),
		VotingServerName:    firstNonEmpty(*c.votingServerName, *c.serverName),
		VerificationSNI:     firstNonEmpty(*c.verificationServerName, *c.serverName),
		TLS: client.TLSConfig{
			RootCAPath: *c.caPath,
			CertPath:   *c.certPath,
			KeyPath:    *c.keyPath,
			ServerName: *c.serverName,
		},
	})
	if err != nil {
		return nil, err
	}
	cl.SetSessionID(*c.sessionID)
	return cl, nil
}

func (c *commonFlags) header() (client.Header, error) {
	state, err := c.authState()
	if err != nil {
		return client.Header{}, err
	}
	authMethod := *c.authMethod
	if authMethod == "" {
		authMethod = state.AuthMethod
	}
	return client.Header{
		SessionID:  *c.sessionID,
		OS:         *c.osName,
		AuthMethod: authMethod,
		AuthToken:  cloneBytes(state.AuthToken),
		DataToken:  cloneBytes(state.DataToken),
	}, nil
}


func (c *commonFlags) requestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), *c.timeout)
}

func (c *commonFlags) persistSession(sessionID string) {
	if *c.sessionFile == "" || sessionID == "" {
		return
	}
	_ = os.WriteFile(*c.sessionFile, []byte(sessionID+"\n"), 0o600)
}

func (c *commonFlags) authState() (authState, error) {
	if *c.authStateFile == "" {
		return authState{}, nil
	}
	b, err := os.ReadFile(*c.authStateFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return authState{}, nil
		}
		return authState{}, fmt.Errorf("read auth state file: %w", err)
	}
	var state authState
	if err := json.Unmarshal(b, &state); err != nil {
		return authState{}, fmt.Errorf("decode auth state file: %w", err)
	}
	return state, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func (c *commonFlags) persistAuthState(state authState) error {
	if *c.authStateFile == "" {
		return nil
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode auth state file: %w", err)
	}
	if err := os.WriteFile(*c.authStateFile, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write auth state file: %w", err)
	}
	return nil
}


func encodeByteMap(in map[string][]byte) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = base64.StdEncoding.EncodeToString(value)
	}
	return out
}

func writeJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func usageError() error {
	return errors.New("usage: ivxv-client <interactive-mid-vote|mid-auth|mid-auth-status|validate-vote|voter-choices|vote|verify> [flags]")
}

func bytesTrimSpace(b []byte) []byte {
	start := 0
	for start < len(b) && (b[start] == ' ' || b[start] == '\n' || b[start] == '\r' || b[start] == '\t') {
		start++
	}
	end := len(b)
	for end > start && (b[end-1] == ' ' || b[end-1] == '\n' || b[end-1] == '\r' || b[end-1] == '\t') {
		end--
	}
	return b[start:end]
}

type authState struct {
	SessionID      string `json:"sessionId,omitempty"`
	AuthMethod     string `json:"authMethod,omitempty"`
	AuthToken      []byte `json:"authToken,omitempty"`
	DataToken      []byte `json:"dataToken,omitempty"`
	MIDSessionCode string `json:"midSessionCode,omitempty"`
	MIDChallenge   []byte `json:"midChallenge,omitempty"`
}

func cloneBytes(in []byte) []byte {
	if len(in) == 0 {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}

func encodeOptionalBase64(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}
