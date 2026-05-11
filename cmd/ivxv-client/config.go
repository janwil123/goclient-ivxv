package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Duration is a time.Duration that marshals/unmarshals as a JSON string (e.g. "15s", "2m").
type Duration struct{ time.Duration }

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	d.Duration = dur
	return nil
}

// appConfig holds all configuration for ivxv-client, loadable from a JSON file.
// CLI flags always take precedence over config file values.
type appConfig struct {
	// Service addresses
	MIDAddr          string `json:"midAddr"`
	ChoicesAddr      string `json:"choicesAddr"`
	VotingAddr       string `json:"votingAddr"`
	VerificationAddr string `json:"verificationAddr"`

	// TLS certificates
	CAPath   string `json:"caPath"`
	CertPath string `json:"certPath"`
	KeyPath  string `json:"keyPath"`

	// TLS server name overrides
	ServerName             string `json:"serverName"`
	MIDServerName          string `json:"midServerName"`
	ChoicesServerName      string `json:"choicesServerName"`
	VotingServerName       string `json:"votingServerName"`
	VerificationServerName string `json:"verificationServerName"`

	// Session state persistence
	SessionFile   string `json:"sessionFile"`
	AuthStateFile string `json:"authStateFile"`

	// Client identity
	OSName string `json:"osName"`

	// Request timeout
	Timeout Duration `json:"timeout"`

	// Authentication
	AuthMethod string `json:"authMethod"`

	// Interactive voting
	ElectionID  string   `json:"electionID"`
	QuestionIDs []string `json:"questionIDs"`
	EncKeyPath  string   `json:"encKeyPath"`
	IDCode      string   `json:"idCode"`
	PhoneNo     string   `json:"phoneNo"`
	PollEvery   Duration `json:"pollEvery"`
	SubmitVote  bool     `json:"submitVote"`
	SaveVoteTo  string   `json:"saveVoteTo"`
	Origin      string   `json:"origin"`
}

func defaultConfig() *appConfig {
	return &appConfig{
		MIDAddr:           "ivxv1.ep.ivxv.ee:443",
		ChoicesAddr:       "ivxv1.ep.ivxv.ee:443",
		VotingAddr:        "ivxv1.ep.ivxv.ee:443",
		ServerName:        "inttest.ivxv.ee",
		MIDServerName:     "mid.inttest.ivxv.ee",
		ChoicesServerName: "choices.inttest.ivxv.ee",
		VotingServerName:  "voting.inttest.ivxv.ee",
		OSName:            "ivxv-codex-golang",
		Timeout:           Duration{15 * time.Second},
		PollEvery:         Duration{2 * time.Second},
		SubmitVote:        true,
		Origin:            "https://ivxv1.ep.ivxv.ee:443",
	}
}

// loadConfig reads a JSON config file from path and merges it over the defaults.
// If the file does not exist, defaults are returned. An empty path is treated
// the same as a missing file.
func loadConfig(path string) (*appConfig, error) {
	cfg := defaultConfig()
	if path == "" {
		return cfg, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	if err := json.Unmarshal(b, cfg); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}
	return cfg, nil
}
