package client

import "context"

type Header struct {
	Ctx        context.Context `json:"-"`
	SessionID  string          `json:",omitempty"`
	OS         string          `json:",omitempty"`
	AuthMethod string          `json:",omitempty"`
	AuthToken  []byte          `json:",omitempty"`
	DataToken  []byte          `json:",omitempty"`
}

type RequestHeader struct {
	SessionID  string
	OS         string
	AuthMethod string
	AuthToken  []byte
	DataToken  []byte
}

func (h RequestHeader) header(ctx context.Context, sessionID string) Header {
	return Header{
		Ctx:        ctx,
		SessionID:  firstNonEmpty(h.SessionID, sessionID),
		OS:         h.OS,
		AuthMethod: h.AuthMethod,
		AuthToken:  cloneBytes(h.AuthToken),
		DataToken:  cloneBytes(h.DataToken),
	}
}

type ChoicesArgs struct {
	Header
	Choices string `json:",omitempty"`
}

type VoterArgs struct {
	Header
}

type ChoicesResponse struct {
	Header
	Choices string
	List    []byte
	Voted   bool `json:",omitempty"`
}

type VoteArgs struct {
	Header
	Choices string
	Type    string
	Vote    []byte
}

type VoteResponse struct {
	Header
	VoteID        []byte
	Qualification map[string][]byte
	TestVote      bool `json:",omitempty"`
}

type VerifyArgs struct {
	Header
	VoteID []byte
}

type VerifyResponse struct {
	Header
	Type          string
	Vote          []byte
	Qualification map[string][]byte
	ChoicesList   []byte
}

type MIDAuthenticateArgs struct {
	Header
	IDCode  string
	PhoneNo string
}

type MIDAuthenticateResponse struct {
	Header
	SessionCode string
	Challenge   []byte
	DataToken   []byte
}

type MIDAuthenticateStatusArgs struct {
	Header
	SessionCode string
}

type MIDAuthenticateStatusResponse struct {
	Header
	Status       string
	GivenName    string
	Surname      string
	PersonalCode string
	AuthToken    []byte
}

type MIDCertificateArgs struct {
	Header
}

type MIDCertificateResponse struct {
	Header
	Certificate []byte
}

type MIDSignArgs struct {
	Header
	Hash     []byte
	HashType string
}

type MIDSignResponse struct {
	Header
	SessionCode string
}

type MIDSignStatusArgs struct {
	Header
	SessionCode string
}

type MIDSignStatusResponse struct {
	Header
	Status    string
	Signature []byte
	Algorithm string
}
