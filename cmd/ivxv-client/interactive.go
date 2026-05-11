package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"math/big"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"crypto/sha256"

	"github.com/janwil/ivxv-codex-golang/client"
)

var (
	ivxvModPElgamalOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 3029, 2, 1}
	ivxvECElgamalOID   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}
)

type candidateOption struct {
	Number      int
	CandidateID string
	Name        string
	Party       string
}

type subjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type modPPublicKeyParameters struct {
	P          *big.Int
	G          *big.Int
	ElectionID string
}

type modPPublicKeyValue struct {
	Y *big.Int
}

type ecPublicKeyParameters struct {
	Curve      string
	ElectionID string
}

type ecPublicKeyValue struct {
	PubY []byte
}

type interactiveConfig struct {
	ElectionID  string
	QuestionIDs []string
	EncKeyPath  string
	IDCode      string
	PhoneNo     string
	PollEvery   time.Duration
	Origin      string
	SubmitVote  bool
	SaveVoteTo  string
}

func runInteractiveMIDVote(args []string, cfg *appConfig) error {
	fs := flag.NewFlagSet("interactive-mid-vote", flag.ContinueOnError)
	common := parseCommonFlags(fs, cfg)
	electionID := fs.String("election-id", cfg.ElectionID, "IVXV election identifier")
	questionID := fs.String("question-id", "", "IVXV question identifier")
	questionIDs := fs.String("question-ids", "", "comma-separated IVXV question identifiers")
	encKeyPath := fs.String("enc-key-file", cfg.EncKeyPath, "PEM file containing the ElGamal vote encryption public key")
	idCode := fs.String("id-code", cfg.IDCode, "Estonian personal code for Mobile-ID authentication")
	phoneNo := fs.String("phone-no", cfg.PhoneNo, "Mobile-ID phone number")
	pollEvery := fs.Duration("poll-every", cfg.PollEvery.Duration, "poll interval for Mobile-ID status requests")
	submitVote := fs.Bool("submit-vote", cfg.SubmitVote, "submit the signed vote to the collector")
	saveVoteTo := fs.String("save-vote-file", cfg.SaveVoteTo, "optional path to write the signed vote container before submission")
	origin := fs.String("origin", cfg.Origin, "signature origin URL")
	if err := fs.Parse(args); err != nil {
		return err
	}

	parsedQuestionIDs := collectQuestionIDs(*questionID, *questionIDs)
	if len(parsedQuestionIDs) == 0 {
		parsedQuestionIDs = cfg.QuestionIDs
	}
	if *electionID == "" || len(parsedQuestionIDs) == 0 || *encKeyPath == "" {
		return errors.New("interactive-mid-vote: -election-id, at least one of -question-id or -question-ids, and -enc-key-file are required")
	}

	icfg := interactiveConfig{
		ElectionID:  *electionID,
		QuestionIDs: parsedQuestionIDs,
		EncKeyPath:  *encKeyPath,
		IDCode:      *idCode,
		PhoneNo:     *phoneNo,
		PollEvery:   *pollEvery,
		Origin:      *origin,
		SubmitVote:  *submitVote,
		SaveVoteTo:  *saveVoteTo,
	}
	if icfg.PollEvery <= 0 {
		icfg.PollEvery = 2 * time.Second
	}

	return runInteractiveVote(common, icfg)
}

func runInspectBDOC(args []string, _ *appConfig) error {
	fs := flag.NewFlagSet("inspect-bdoc", flag.ContinueOnError)
	path := fs.String("file", "", "path to the BDOC file to inspect")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" {
		return errors.New("inspect-bdoc: -file is required")
	}

	data, err := os.ReadFile(*path)
	if err != nil {
		return fmt.Errorf("read BDOC: %w", err)
	}
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("open BDOC zip: %w", err)
	}

	type zipEntry struct {
		Name             string `json:"name"`
		CompressedSize   uint64 `json:"compressedSize"`
		UncompressedSize uint64 `json:"uncompressedSize"`
	}
	out := struct {
		File         string     `json:"file"`
		Entries      []zipEntry `json:"entries"`
		SignatureXML string     `json:"signatureXml,omitempty"`
		ManifestXML  string     `json:"manifestXml,omitempty"`
		MimeType     string     `json:"mimetype,omitempty"`
	}{
		File: *path,
	}

	for _, f := range reader.File {
		out.Entries = append(out.Entries, zipEntry{
			Name:             f.Name,
			CompressedSize:   f.CompressedSize64,
			UncompressedSize: f.UncompressedSize64,
		})
		if f.Name != "META-INF/signatures0.xml" && f.Name != "META-INF/manifest.xml" && f.Name != "mimetype" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("open zip entry %q: %w", f.Name, err)
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return fmt.Errorf("read zip entry %q: %w", f.Name, err)
		}
		switch f.Name {
		case "META-INF/signatures0.xml":
			out.SignatureXML = string(b)
		case "META-INF/manifest.xml":
			out.ManifestXML = string(b)
		case "mimetype":
			out.MimeType = string(b)
		}
	}

	return writeJSON(out)
}

func runInteractiveVote(common *commonFlags, cfg interactiveConfig) error {
	c, err := common.newClient()
	if err != nil {
		return err
	}
	reader := bufio.NewReader(os.Stdin)

	idCode := strings.TrimSpace(cfg.IDCode)
	if idCode == "" {
		idCode, err = prompt(reader, "Estonian personal code")
		if err != nil {
			return err
		}
	}
	phoneNo := strings.TrimSpace(cfg.PhoneNo)
	if phoneNo == "" {
		phoneNo, err = prompt(reader, "Mobile-ID phone number")
		if err != nil {
			return err
		}
	}

	ctx, cancel := common.requestContext()
	defer cancel()
	authResp, err := c.MIDAuthenticate(ctx, client.MIDAuthenticateArgs{
		Header: client.Header{
			OS: *common.osName,
		},
		IDCode:  idCode,
		PhoneNo: phoneNo,
	})
	if err != nil {
		return err
	}
	common.persistSession(c.SessionID())
	state := authState{
		SessionID:      c.SessionID(),
		AuthMethod:     "ticket",
		DataToken:      authResp.DataToken,
		MIDSessionCode: authResp.SessionCode,
		MIDChallenge:   authResp.Challenge,
	}
	if err := common.persistAuthState(state); err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "Mobile-ID challenge: %s\n", string(authResp.Challenge))
	fmt.Fprintf(os.Stdout, "Waiting for Mobile-ID authentication on %s\n", phoneNo)

	statusResp, err := pollMIDAuthStatus(common, c, cfg.PollEvery, authResp.SessionCode)
	if err != nil {
		return err
	}
	state.AuthToken = statusResp.AuthToken
	if err := common.persistAuthState(state); err != nil {
		return err
	}

	header, err := common.header()
	if err != nil {
		return err
	}
	header.AuthMethod = "ticket"
	header.AuthToken = cloneBytes(statusResp.AuthToken)
	header.DataToken = cloneBytes(authResp.DataToken)

	ctx, cancel = common.requestContext()
	choicesResp, err := c.VoterChoices(ctx, client.VoterArgs{Header: header})
	cancel()
	if err != nil {
		return err
	}
	common.persistSession(c.SessionID())

	options, err := parseCandidateOptions(choicesResp.List)
	if err != nil {
		return fmt.Errorf("parse candidate list: %w", err)
	}
	if len(options) == 0 {
		return errors.New("candidate list is empty")
	}

	fmt.Fprintln(os.Stdout, "\nCandidates:")
	for _, option := range options {
		fmt.Fprintf(os.Stdout, "%d. %s [%s] (%s)\n", option.Number, option.Name, option.CandidateID, option.Party)
	}

	choiceInput, err := prompt(reader, "Enter candidate number")
	if err != nil {
		return err
	}
	choiceNo, err := strconv.Atoi(choiceInput)
	if err != nil {
		return fmt.Errorf("invalid candidate number: %w", err)
	}
	selected, ok := findCandidateOption(options, choiceNo)
	if !ok {
		return errors.New("candidate number not in candidate list")
	}

	fmt.Fprintf(os.Stdout, "Selected: %s [%s]\n", selected.Name, selected.CandidateID)

	publicKey, encElectionID, err := loadElectionPublicKey(cfg.EncKeyPath)
	if err != nil {
		return err
	}
	if encElectionID != "" && encElectionID != cfg.ElectionID {
		return fmt.Errorf("encryption key election id mismatch: key=%q flag=%q", encElectionID, cfg.ElectionID)
	}

	ballotCiphertext, err := publicKey.Encrypt(selected.CandidateID)
	if err != nil {
		return fmt.Errorf("encrypt candidate choice: %w", err)
	}

	ctx, cancel = common.requestContext()
	certResp, err := c.MIDGetCertificate(ctx, client.MIDCertificateArgs{Header: header})
	cancel()
	if err != nil {
		return err
	}
	signingCert, err := x509.ParseCertificate(certResp.Certificate)
	if err != nil {
		return fmt.Errorf("parse signing certificate: %w", err)
	}

	containerBytes, signHash, err := prepareBDOCVote(cfg.ElectionID, cfg.QuestionIDs, ballotCiphertext, signingCert)
	if err != nil {
		return err
	}

	ctx, cancel = common.requestContext()
	signResp, err := c.MIDSign(ctx, client.MIDSignArgs{
		Header:   header,
		Hash:     signHash,
		HashType: "SHA256",
	})
	cancel()
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, "Waiting for Mobile-ID signature confirmation")

	signStatusResp, err := pollMIDSignStatus(common, c, cfg.PollEvery, signResp.SessionCode, header)
	if err != nil {
		return err
	}

	signedContainer, err := finalizeBDOCVote(containerBytes, signingCert, signStatusResp.Signature, signStatusResp.Algorithm)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, "Prepared vote container (%d bytes)\n", len(signedContainer))
	if cfg.SaveVoteTo != "" {
		if err := os.WriteFile(cfg.SaveVoteTo, signedContainer, 0o600); err != nil {
			return fmt.Errorf("write signed vote container: %w", err)
		}
		fmt.Fprintf(os.Stdout, "Saved vote container to %s\n", cfg.SaveVoteTo)
	}
	if !cfg.SubmitVote {
		return writeJSON(struct {
			SessionID string `json:"sessionId"`
			Choices   string `json:"choices"`
			Candidate string `json:"candidateId"`
			Container string `json:"voteContainerBase64"`
		}{
			SessionID: c.SessionID(),
			Choices:   choicesResp.Choices,
			Candidate: selected.CandidateID,
			Container: base64.StdEncoding.EncodeToString(signedContainer),
		})
	}

	ctx, cancel = common.requestContext()
	voteResp, err := c.Vote(ctx, client.VoteArgs{
		Header:  header,
		Choices: choicesResp.Choices,
		Type:    "bdoc",
		Vote:    signedContainer,
	})
	cancel()
	if err != nil {
		if strings.Contains(err.Error(), "BAD_REQUEST") {
			return fmt.Errorf("%w; likely causes are an invalid BDOC container, wrong or incomplete question ids, or a ballot ciphertext format mismatch", err)
		}
		return err
	}
	common.persistSession(c.SessionID())

	return writeJSON(struct {
		SessionID     string            `json:"sessionId"`
		VoteIDHex     string            `json:"voteIdHex"`
		CandidateID   string            `json:"candidateId"`
		Qualification map[string]string `json:"qualification"`
	}{
		SessionID:     c.SessionID(),
		VoteIDHex:     hex.EncodeToString(voteResp.VoteID),
		CandidateID:   selected.CandidateID,
		Qualification: encodeByteMap(voteResp.Qualification),
	})
}

func pollMIDAuthStatus(common *commonFlags, c *client.Client, interval time.Duration, sessionCode string) (*client.MIDAuthenticateStatusResponse, error) {
	header := client.Header{}
	for {
		ctx, cancel := common.requestContext()
		resp, err := c.MIDAuthenticateStatus(ctx, client.MIDAuthenticateStatusArgs{
			Header:      header,
			SessionCode: sessionCode,
		})
		cancel()
		if err != nil {
			return nil, err
		}
		if resp.Status == "OK" {
			return resp, nil
		}
		time.Sleep(interval)
	}
}

func pollMIDSignStatus(common *commonFlags, c *client.Client, interval time.Duration, sessionCode string, header client.Header) (*client.MIDSignStatusResponse, error) {
	for {
		ctx, cancel := common.requestContext()
		resp, err := c.MIDSignStatus(ctx, client.MIDSignStatusArgs{
			Header:      header,
			SessionCode: sessionCode,
		})
		cancel()
		if err != nil {
			return nil, err
		}
		if resp.Status == "OK" {
			return resp, nil
		}
		time.Sleep(interval)
	}
}

func waitWithContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func prompt(reader *bufio.Reader, label string) (string, error) {
	fmt.Fprintf(os.Stdout, "%s: ", label)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func collectQuestionIDs(single, multi string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, part := range []string{single, multi} {
		for _, q := range strings.Split(part, ",") {
			q = strings.TrimSpace(q)
			if q == "" {
				continue
			}
			if _, ok := seen[q]; ok {
				continue
			}
			seen[q] = struct{}{}
			out = append(out, q)
		}
	}
	return out
}

func parseCandidateOptions(raw []byte) ([]candidateOption, error) {
	var choices map[string]map[string]string
	if err := json.Unmarshal(raw, &choices); err != nil {
		return nil, err
	}
	parties := make([]string, 0, len(choices))
	for party := range choices {
		parties = append(parties, party)
	}
	sort.Strings(parties)

	var options []candidateOption
	next := 1
	for _, party := range parties {
		candidates := choices[party]
		ids := make([]string, 0, len(candidates))
		for id := range candidates {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			options = append(options, candidateOption{
				Number:      next,
				CandidateID: id,
				Name:        candidates[id],
				Party:       party,
			})
			next++
		}
	}
	return options, nil
}

func findCandidateOption(options []candidateOption, number int) (candidateOption, bool) {
	for _, option := range options {
		if option.Number == number {
			return option, true
		}
	}
	return candidateOption{}, false
}

type electionPublicKey interface {
	Encrypt(candidateID string) ([]byte, error)
}

func loadElectionPublicKey(path string) (electionPublicKey, string, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("read encryption public key: %w", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, "", errors.New("decode encryption public key PEM")
	}
	var spki subjectPublicKeyInfo
	if _, err := asn1.Unmarshal(block.Bytes, &spki); err != nil {
		return nil, "", fmt.Errorf("parse SubjectPublicKeyInfo: %w", err)
	}

	switch {
	case spki.Algorithm.Algorithm.Equal(ivxvModPElgamalOID):
		return loadModPPublicKeyFromSPKI(spki)
	case spki.Algorithm.Algorithm.Equal(ivxvECElgamalOID):
		return loadECPublicKeyFromSPKI(spki)
	default:
		return nil, "", fmt.Errorf("unsupported encryption key algorithm OID %s", spki.Algorithm.Algorithm.String())
	}
}

func loadModPPublicKeyFromSPKI(spki subjectPublicKeyInfo) (electionPublicKey, string, error) {
	var params modPPublicKeyParameters
	if _, err := asn1.Unmarshal(spki.Algorithm.Parameters.FullBytes, &params); err != nil {
		return nil, "", fmt.Errorf("parse ModP parameters: %w", err)
	}
	var value modPPublicKeyValue
	if _, err := asn1.Unmarshal(spki.PublicKey.Bytes, &value); err != nil {
		return nil, "", fmt.Errorf("parse ModP public key element: %w", err)
	}
	if params.P == nil || params.G == nil || value.Y == nil {
		return nil, "", errors.New("encryption public key is incomplete")
	}
	return modPPublicKey{
		P: params.P,
		G: params.G,
		Y: value.Y,
	}, params.ElectionID, nil
}

func loadECPublicKeyFromSPKI(spki subjectPublicKeyInfo) (electionPublicKey, string, error) {
	var params ecPublicKeyParameters
	if _, err := asn1.Unmarshal(spki.Algorithm.Parameters.FullBytes, &params); err != nil {
		return nil, "", fmt.Errorf("parse EC parameters: %w", err)
	}
	curve, err := ivxvNamedCurve(params.Curve)
	if err != nil {
		return nil, "", err
	}
	var value ecPublicKeyValue
	if _, err := asn1.Unmarshal(spki.PublicKey.Bytes, &value); err != nil {
		return nil, "", fmt.Errorf("parse EC public key element: %w", err)
	}
	x, y := elliptic.Unmarshal(curve, value.PubY)
	if x == nil || y == nil {
		return nil, "", errors.New("decode EC public key point")
	}
	return ecPublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
		Name:  params.Curve,
	}, params.ElectionID, nil
}

type modPPublicKey struct {
	P *big.Int
	G *big.Int
	Y *big.Int
}

func (k modPPublicKey) q() *big.Int {
	return new(big.Int).Rsh(new(big.Int).Sub(k.P, big.NewInt(1)), 1)
}

func (key modPPublicKey) Encrypt(candidateID string) ([]byte, error) {
	padded, err := modPPad(key.q(), []byte(candidateID))
	if err != nil {
		return nil, err
	}
	m := new(big.Int).SetBytes(padded)
	q := key.q()
	if m.Sign() <= 0 || m.Cmp(q) > 0 {
		return nil, errors.New("padded plaintext does not fit ModP group")
	}

	encoded := new(big.Int).Set(m)
	if big.Jacobi(m, key.P) == -1 {
		encoded = new(big.Int).Sub(key.P, m)
	}

	r, err := rand.Int(rand.Reader, new(big.Int).Sub(q, big.NewInt(1)))
	if err != nil {
		return nil, err
	}
	r.Add(r, big.NewInt(1))

	a := new(big.Int).Exp(key.G, r, key.P)
	b := new(big.Int).Mul(new(big.Int).Exp(key.Y, r, key.P), encoded)
	b.Mod(b, key.P)

	return marshalIVXVCiphertext(a, b)
}

type ecPublicKey struct {
	Curve elliptic.Curve
	X     *big.Int
	Y     *big.Int
	Name  string
}

func (k ecPublicKey) Encrypt(candidateID string) ([]byte, error) {
	padded, err := ecPad(k.Curve.Params(), []byte(candidateID))
	if err != nil {
		return nil, err
	}
	msgX := new(big.Int).SetBytes(padded)
	mx, my, err := ecEncodeMessage(k.Curve, msgX)
	if err != nil {
		return nil, err
	}

	n := k.Curve.Params().N
	r, err := rand.Int(rand.Reader, new(big.Int).Sub(n, big.NewInt(1)))
	if err != nil {
		return nil, err
	}
	r.Add(r, big.NewInt(1))

	ux, uy := k.Curve.ScalarBaseMult(r.Bytes())
	rx, ry := k.Curve.ScalarMult(k.X, k.Y, r.Bytes())
	vx, vy := k.Curve.Add(rx, ry, mx, my)
	return marshalIVXVCiphertextEC(k.Curve, ux, uy, vx, vy)
}

func modPPad(q *big.Int, msg []byte) ([]byte, error) {
	totalBytes := (q.BitLen() + 7) / 8
	if len(msg) > totalBytes-3 {
		return nil, errors.New("candidate identifier too long for ModP ballot encoding")
	}
	padded := make([]byte, totalBytes)
	padded[0] = 0x00
	padded[1] = 0x01
	sep := totalBytes - len(msg) - 1
	for i := 2; i < sep; i++ {
		padded[i] = 0xff
	}
	copy(padded[sep+1:], msg)
	return padded, nil
}

func marshalIVXVCiphertext(a, b *big.Int) ([]byte, error) {
	algorithm := struct {
		Algorithm asn1.ObjectIdentifier
	}{
		Algorithm: ivxvModPElgamalOID,
	}
	data := struct {
		A *big.Int
		B *big.Int
	}{A: a, B: b}
	return asn1.Marshal(struct {
		Algorithm any
		Data      any
	}{
		Algorithm: algorithm,
		Data:      data,
	})
}

func marshalIVXVCiphertextEC(curve elliptic.Curve, ax, ay, bx, by *big.Int) ([]byte, error) {
	algorithm := struct {
		Algorithm asn1.ObjectIdentifier
	}{
		Algorithm: ivxvECElgamalOID,
	}
	data := struct {
		UBlind          []byte
		VBlindedMessage []byte
	}{
		UBlind:          elliptic.Marshal(curve, ax, ay),
		VBlindedMessage: elliptic.Marshal(curve, bx, by),
	}
	return asn1.Marshal(struct {
		Algorithm any
		Data      any
	}{
		Algorithm: algorithm,
		Data:      data,
	})
}

func ivxvNamedCurve(name string) (elliptic.Curve, error) {
	switch name {
	case "P-224":
		return elliptic.P224(), nil
	case "P-384":
		return elliptic.P384(), nil
	default:
		return nil, fmt.Errorf("unsupported EC curve %q", name)
	}
}

func ecPad(params *elliptic.CurveParams, msg []byte) ([]byte, error) {
	fieldBits := params.P.BitLen()
	maxPlaintextBits := fieldBits - 2 - 1 - 10
	plaintextBits := len(msg) * 8
	if plaintextBits+8 > maxPlaintextBits {
		return nil, errors.New("candidate identifier too long for EC ballot encoding")
	}

	paddingBitLen := fieldBits - 1 - plaintextBits - 10
	padding := new(big.Int).Lsh(big.NewInt(1), uint(paddingBitLen))
	padding.Sub(padding, big.NewInt(2))
	paddingBytes := padding.Bytes()

	padded := make([]byte, len(paddingBytes)+len(msg))
	copy(padded, paddingBytes)
	copy(padded[len(paddingBytes):], msg)
	return padded, nil
}

func ecEncodeMessage(curve elliptic.Curve, x *big.Int) (*big.Int, *big.Int, error) {
	const encodingSuccessBits = 10
	startX := new(big.Int).Lsh(new(big.Int).Set(x), encodingSuccessBits)
	limit := 1 << encodingSuccessBits
	params := curve.Params()

	for i := 0; i < limit; i++ {
		candidateX := new(big.Int).Add(startX, big.NewInt(int64(i)))
		if candidateX.Cmp(params.P) >= 0 {
			break
		}
		y, ok := weierstrassQuadraticResidue(curve, candidateX)
		if ok {
			return candidateX, y, nil
		}
	}
	return nil, nil, errors.New("failed to encode plaintext into EC point")
}

func weierstrassQuadraticResidue(curve elliptic.Curve, x *big.Int) (*big.Int, bool) {
	params := curve.Params()
	p := params.P

	x3 := new(big.Int).Exp(x, big.NewInt(3), p)
	threeX := new(big.Int).Mul(big.NewInt(3), x)
	threeX.Mod(threeX, p)
	rhs := new(big.Int).Sub(x3, threeX)
	rhs.Add(rhs, params.B)
	rhs.Mod(rhs, p)

	y, ok := modSqrt(rhs, p)
	if !ok {
		return nil, false
	}
	minusY := new(big.Int).Neg(y)
	minusY.Mod(minusY, p)
	if minusY.Cmp(y) < 0 {
		y = minusY
	}
	if !curve.IsOnCurve(x, y) {
		return nil, false
	}
	return y, true
}

func modSqrt(a, p *big.Int) (*big.Int, bool) {
	if a.Sign() == 0 {
		return big.NewInt(0), true
	}
	if jacobi := big.Jacobi(a, p); jacobi != 1 {
		return nil, false
	}

	if new(big.Int).And(new(big.Int).Set(p), big.NewInt(3)).Cmp(big.NewInt(3)) == 0 {
		exp := new(big.Int).Add(p, big.NewInt(1))
		exp.Rsh(exp, 2)
		y := new(big.Int).Exp(a, exp, p)
		check := new(big.Int).Mul(y, y)
		check.Mod(check, p)
		if check.Cmp(new(big.Int).Mod(new(big.Int).Set(a), p)) == 0 {
			return y, true
		}
		return nil, false
	}

	q := new(big.Int).Sub(p, big.NewInt(1))
	s := 0
	for q.Bit(0) == 0 {
		q.Rsh(q, 1)
		s++
	}

	z := big.NewInt(2)
	for big.Jacobi(z, p) != -1 {
		z.Add(z, big.NewInt(1))
	}

	c := new(big.Int).Exp(z, q, p)
	exp := new(big.Int).Add(q, big.NewInt(1))
	exp.Rsh(exp, 1)
	x := new(big.Int).Exp(a, exp, p)
	t := new(big.Int).Exp(a, q, p)
	m := s

	for t.Cmp(big.NewInt(1)) != 0 {
		i := 1
		t2i := new(big.Int).Mul(t, t)
		t2i.Mod(t2i, p)
		for i < m {
			if t2i.Cmp(big.NewInt(1)) == 0 {
				break
			}
			t2i.Mul(t2i, t2i)
			t2i.Mod(t2i, p)
			i++
		}
		if i == m {
			return nil, false
		}

		pow := m - i - 1
		bExp := big.NewInt(1)
		bExp.Lsh(bExp, uint(pow))
		b := new(big.Int).Exp(c, bExp, p)
		x.Mul(x, b)
		x.Mod(x, p)
		b2 := new(big.Int).Mul(b, b)
		b2.Mod(b2, p)
		t.Mul(t, b2)
		t.Mod(t, p)
		c.Set(b2)
		m = i
	}
	return x, true
}

type preparedVote struct {
	Ballots             []preparedBallot
	ManifestXML         string
	SignedPropertiesXML string
	SignedInfoXML       string
}

type preparedBallot struct {
	Name  string
	Bytes []byte
}

func prepareBDOCVote(electionID string, questionIDs []string, ballot []byte, cert *x509.Certificate) ([]byte, []byte, error) {
	vote, err := buildPreparedVote(electionID, questionIDs, ballot, cert)
	if err != nil {
		return nil, nil, err
	}
	hash := sha256.Sum256([]byte(vote.SignedInfoXML))
	container, err := writeUnsignedBDOC(vote)
	if err != nil {
		return nil, nil, err
	}
	return container, hash[:], nil
}

func finalizeBDOCVote(unsigned []byte, cert *x509.Certificate, signature []byte, algorithm string) ([]byte, error) {
	prepared, err := readPreparedVote(unsigned)
	if err != nil {
		return nil, err
	}
	signatureXML, err := buildSignatureXML(prepared, cert, signature, algorithm)
	if err != nil {
		return nil, err
	}
	return writeSignedBDOC(prepared, signatureXML)
}

func buildPreparedVote(electionID string, questionIDs []string, ballot []byte, cert *x509.Certificate) (preparedVote, error) {
	ballots := make([]preparedBallot, 0, len(questionIDs))
	for _, questionID := range questionIDs {
		ballots = append(ballots, preparedBallot{
			Name:  fmt.Sprintf("%s.%s.ballot", electionID, questionID),
			Bytes: cloneBytes(ballot),
		})
	}
	signedProps, err := canonicalizeXMLSnippet(buildSignedPropertiesXML(cert, len(ballots)))
	if err != nil {
		return preparedVote{}, fmt.Errorf("canonicalize SignedProperties: %w", err)
	}
	signedPropsDigest := sha256.Sum256([]byte(signedProps))
	manifest := buildManifestXML(ballots)
	signedInfo, err := canonicalizeXMLSnippet(buildSignedInfoXML(ballots, signedPropsDigest[:]))
	if err != nil {
		return preparedVote{}, fmt.Errorf("canonicalize SignedInfo: %w", err)
	}

	return preparedVote{
		Ballots:             ballots,
		ManifestXML:         manifest,
		SignedPropertiesXML: signedProps,
		SignedInfoXML:       signedInfo,
	}, nil
}

func writeUnsignedBDOC(v preparedVote) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if err := addZipFile(zw, "mimetype", []byte("application/vnd.etsi.asic-e+zip"), zip.Store); err != nil {
		return nil, err
	}
	if err := addZipFile(zw, "META-INF/manifest.xml", []byte(v.ManifestXML), zip.Deflate); err != nil {
		return nil, err
	}
	for _, ballot := range v.Ballots {
		if err := addZipFile(zw, ballot.Name, ballot.Bytes, zip.Deflate); err != nil {
			return nil, err
		}
	}
	if err := addZipFile(zw, "META-INF/prepared-signed-properties.xml", []byte(v.SignedPropertiesXML), zip.Deflate); err != nil {
		return nil, err
	}
	if err := addZipFile(zw, "META-INF/prepared-signed-info.xml", []byte(v.SignedInfoXML), zip.Deflate); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func readPreparedVote(container []byte) (preparedVote, error) {
	reader, err := zip.NewReader(bytes.NewReader(container), int64(len(container)))
	if err != nil {
		return preparedVote{}, err
	}
	files := make(map[string][]byte, len(reader.File))
	for _, file := range reader.File {
		rc, err := file.Open()
		if err != nil {
			return preparedVote{}, err
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return preparedVote{}, err
		}
		files[file.Name] = data
	}
	var ballots []preparedBallot
	for name, data := range files {
		if strings.HasSuffix(name, ".ballot") {
			ballots = append(ballots, preparedBallot{Name: name, Bytes: data})
		}
	}
	sort.Slice(ballots, func(i, j int) bool { return ballots[i].Name < ballots[j].Name })
	if len(ballots) == 0 {
		return preparedVote{}, errors.New("unsigned BDOC does not contain ballot file")
	}
	return preparedVote{
		Ballots:             ballots,
		ManifestXML:         string(files["META-INF/manifest.xml"]),
		SignedPropertiesXML: string(files["META-INF/prepared-signed-properties.xml"]),
		SignedInfoXML:       string(files["META-INF/prepared-signed-info.xml"]),
	}, nil
}

func writeSignedBDOC(v preparedVote, signatureXML string) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if err := addZipFile(zw, "mimetype", []byte("application/vnd.etsi.asic-e+zip"), zip.Store); err != nil {
		return nil, err
	}
	if err := addZipFile(zw, "META-INF/manifest.xml", []byte(v.ManifestXML), zip.Deflate); err != nil {
		return nil, err
	}
	for _, ballot := range v.Ballots {
		if err := addZipFile(zw, ballot.Name, ballot.Bytes, zip.Deflate); err != nil {
			return nil, err
		}
	}
	if err := addZipFile(zw, "META-INF/signatures0.xml", []byte(signatureXML), zip.Deflate); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func addZipFile(zw *zip.Writer, name string, data []byte, method uint16) error {
	header := &zip.FileHeader{
		Name:   name,
		Method: method,
	}
	if name == "mimetype" {
		header.Flags = 0
		header.UncompressedSize64 = uint64(len(data))
		header.CompressedSize64 = uint64(len(data))
		header.CRC32 = crc32.ChecksumIEEE(data)
		writer, err := zw.CreateRaw(header)
		if err != nil {
			return err
		}
		_, err = writer.Write(data)
		return err
	}
	writer, err := zw.CreateHeader(header)
	if err != nil {
		return err
	}
	_, err = writer.Write(data)
	return err
}

func buildManifestXML(ballots []preparedBallot) string {
	entries := `<?xml version="1.0" encoding="UTF-8" standalone="no"?>` +
		`<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.2">` +
		`<manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.etsi.asic-e+zip"/>`
	for _, ballot := range ballots {
		entries += `<manifest:file-entry manifest:full-path="` + xmlEscape(ballot.Name) + `" manifest:media-type="application/octet-stream"/>`
	}
	return entries + `</manifest:manifest>`
}

func buildSignedPropertiesXML(cert *x509.Certificate, ballotCount int) string {
	signTime := time.Now().UTC().Format(time.RFC3339)
	certDigest := sha256.Sum256(cert.Raw)
	issuer := cert.Issuer
	issuer.ExtraNames = issuer.Names
	issuerName := encodeRDNSequence(issuer.ToRDNSequence())
	xml := `<xades:SignedProperties xmlns:asic="http://uri.etsi.org/02918/v1.2.1#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="S0-SignedProperties">` +
		`<xades:SignedSignatureProperties>` +
		`<xades:SigningTime>` + xmlEscape(signTime) + `</xades:SigningTime>` +
		`<xades:SigningCertificate>` +
		`<xades:Cert>` +
		`<xades:CertDigest>` +
		`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>` +
		`<ds:DigestValue>` + base64.StdEncoding.EncodeToString(certDigest[:]) + `</ds:DigestValue>` +
		`</xades:CertDigest>` +
		`<xades:IssuerSerial>` +
		`<ds:X509IssuerName>` + xmlEscape(issuerName) + `</ds:X509IssuerName>` +
		`<ds:X509SerialNumber>` + cert.SerialNumber.String() + `</ds:X509SerialNumber>` +
		`</xades:IssuerSerial>` +
		`</xades:Cert>` +
		`</xades:SigningCertificate>` +
		`</xades:SignedSignatureProperties>` +
		`<xades:SignedDataObjectProperties>`
	for i := 0; i < ballotCount; i++ {
		xml += `<xades:DataObjectFormat ObjectReference="#S0-ref-` + strconv.Itoa(i) + `">` +
			`<xades:MimeType>application/octet-stream</xades:MimeType>` +
			`</xades:DataObjectFormat>`
	}
	return xml + `</xades:SignedDataObjectProperties></xades:SignedProperties>`
}

func buildSignedInfoXML(ballots []preparedBallot, signedPropsDigest []byte) string {
	xml := `<ds:SignedInfo xmlns:asic="http://uri.etsi.org/02918/v1.2.1#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#" Id="S0-SignedInfo">` +
		`<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"></ds:CanonicalizationMethod>` +
		`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"></ds:SignatureMethod>`
	for i, ballot := range ballots {
		ballotDigest := sha256.Sum256(ballot.Bytes)
		xml += `<ds:Reference Id="S0-ref-` + strconv.Itoa(i) + `" URI="` + xmlEscape(ballot.Name) + `">` +
			`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>` +
			`<ds:DigestValue>` + base64.StdEncoding.EncodeToString(ballotDigest[:]) + `</ds:DigestValue>` +
			`</ds:Reference>`
	}
	xml +=
		`<ds:Reference Id="S0-ref-sp" Type="http://uri.etsi.org/01903#SignedProperties" URI="#S0-SignedProperties">` +
			`<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11"></ds:Transform></ds:Transforms>` +
			`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"></ds:DigestMethod>` +
			`<ds:DigestValue>` + base64.StdEncoding.EncodeToString(signedPropsDigest) + `</ds:DigestValue>` +
			`</ds:Reference>` +
			`</ds:SignedInfo>`
	return xml
}

func buildSignatureXML(v preparedVote, cert *x509.Certificate, signature []byte, algorithm string) (string, error) {
	sigMethod, err := xmlSignatureMethodForMID(algorithm)
	if err != nil {
		return "", err
	}
	signatureValue, err := normalizeSignatureValueForXML(cert, signature, algorithm)
	if err != nil {
		return "", err
	}
	signedInfo := strings.Replace(v.SignedInfoXML, `http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256`, sigMethod, 1)
	keyInfo := `<ds:KeyInfo Id="S0-KeyInfo"><ds:X509Data><ds:X509Certificate>` +
		base64.StdEncoding.EncodeToString(cert.Raw) +
		`</ds:X509Certificate></ds:X509Data></ds:KeyInfo>`
	return `<?xml version="1.0" encoding="UTF-8" standalone="no"?>` +
		`<asic:XAdESSignatures xmlns:asic="http://uri.etsi.org/02918/v1.2.1#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#">` +
		`<ds:Signature Id="S0">` +
		signedInfo +
		`<ds:SignatureValue Id="S0-SIG">` + base64.StdEncoding.EncodeToString(signatureValue) + `</ds:SignatureValue>` +
		keyInfo +
		`<ds:Object Id="S0-object-xades"><xades:QualifyingProperties Id="S0-QualifyingProperties" Target="#S0" xmlns:xades="http://uri.etsi.org/01903/v1.3.2#">` +
		v.SignedPropertiesXML +
		`</xades:QualifyingProperties></ds:Object>` +
		`</ds:Signature></asic:XAdESSignatures>`, nil
}

func normalizeSignatureValueForXML(cert *x509.Certificate, signature []byte, algorithm string) ([]byte, error) {
	if !strings.Contains(algorithm, "ECEncryption") {
		return signature, nil
	}

	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("ECDSA Mobile-ID signature algorithm %q does not match certificate key type %T", algorithm, cert.PublicKey)
	}

	type ecdsaSignature struct {
		R *big.Int
		S *big.Int
	}
	var parsed ecdsaSignature
	if rest, err := asn1.Unmarshal(signature, &parsed); err == nil && len(rest) == 0 && parsed.R != nil && parsed.S != nil {
		size := (pub.Curve.Params().BitSize + 7) / 8
		out := make([]byte, size*2)
		rb := parsed.R.Bytes()
		sb := parsed.S.Bytes()
		copy(out[size-len(rb):size], rb)
		copy(out[2*size-len(sb):], sb)
		return out, nil
	}

	return signature, nil
}

type xmlCanonNode struct {
	Name     xml.Name
	Attrs    []xml.Attr
	Children []*xmlCanonNode
	Text     string
}

func canonicalizeXMLSnippet(raw string) (string, error) {
	decoder := xml.NewDecoder(strings.NewReader(raw))
	var stack []*xmlCanonNode
	var root *xmlCanonNode

	for {
		tok, err := decoder.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return "", err
		}
		switch tok := tok.(type) {
		case xml.StartElement:
			node := &xmlCanonNode{Name: tok.Name, Attrs: append([]xml.Attr(nil), tok.Attr...)}
			if len(stack) > 0 {
				parent := stack[len(stack)-1]
				parent.Children = append(parent.Children, node)
			} else {
				root = node
			}
			stack = append(stack, node)
		case xml.EndElement:
			if len(stack) == 0 {
				return "", errors.New("unexpected end element")
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) == 0 {
				if strings.TrimSpace(string(tok)) == "" {
					continue
				}
				return "", errors.New("unexpected character data")
			}
			stack[len(stack)-1].Text += string(tok)
		}
	}
	if root == nil {
		return "", errors.New("empty XML")
	}

	var b strings.Builder
	writeCanonicalXML(&b, root, true)
	return b.String(), nil
}

var canonicalPrefixes = map[string]string{
	"http://uri.etsi.org/02918/v1.2.1#":  "asic",
	"http://www.w3.org/2000/09/xmldsig#": "ds",
	"http://uri.etsi.org/01903/v1.3.2#":  "xades",
}

var canonicalNamespaces = []struct {
	Prefix string
	URI    string
}{
	{Prefix: "asic", URI: "http://uri.etsi.org/02918/v1.2.1#"},
	{Prefix: "ds", URI: "http://www.w3.org/2000/09/xmldsig#"},
	{Prefix: "xades", URI: "http://uri.etsi.org/01903/v1.3.2#"},
}

func writeCanonicalXML(b *strings.Builder, node *xmlCanonNode, root bool) {
	b.WriteByte('<')
	if prefix := canonicalPrefixes[node.Name.Space]; prefix != "" {
		b.WriteString(prefix)
		b.WriteByte(':')
	}
	b.WriteString(node.Name.Local)
	if root {
		for _, ns := range canonicalNamespaces {
			b.WriteString(` xmlns:`)
			b.WriteString(ns.Prefix)
			b.WriteString(`="`)
			b.WriteString(canonicalEscapeAttr(ns.URI))
			b.WriteByte('"')
		}
	}

	attrs := canonicalizeAttrs(node.Attrs)
	for _, attr := range attrs {
		b.WriteByte(' ')
		if prefix := canonicalPrefixes[attr.Name.Space]; prefix != "" {
			b.WriteString(prefix)
			b.WriteByte(':')
		}
		b.WriteString(attr.Name.Local)
		b.WriteString(`="`)
		b.WriteString(canonicalEscapeAttr(attr.Value))
		b.WriteByte('"')
	}
	b.WriteByte('>')
	if node.Text != "" {
		b.WriteString(canonicalEscapeText(node.Text))
	}
	for _, child := range node.Children {
		writeCanonicalXML(b, child, false)
	}
	b.WriteString(`</`)
	if prefix := canonicalPrefixes[node.Name.Space]; prefix != "" {
		b.WriteString(prefix)
		b.WriteByte(':')
	}
	b.WriteString(node.Name.Local)
	b.WriteByte('>')
}

func canonicalizeAttrs(attrs []xml.Attr) []xml.Attr {
	out := make([]xml.Attr, 0, len(attrs))
	for _, attr := range attrs {
		if attr.Name.Space == "xmlns" || (attr.Name.Space == "" && attr.Name.Local == "xmlns") {
			continue
		}
		out = append(out, attr)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name.Space != out[j].Name.Space {
			return out[i].Name.Space < out[j].Name.Space
		}
		return out[i].Name.Local < out[j].Name.Local
	})
	return out
}

func canonicalEscapeAttr(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	s = strings.ReplaceAll(s, "\t", "&#x9;")
	s = strings.ReplaceAll(s, "\n", "&#xA;")
	s = strings.ReplaceAll(s, "\r", "&#xD;")
	return s
}

func canonicalEscapeText(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\r", "&#xD;")
	return s
}

func xmlSignatureMethodForMID(algorithm string) (string, error) {
	switch algorithm {
	case "SHA256WithECEncryption":
		return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", nil
	case "SHA384WithECEncryption":
		return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384", nil
	case "SHA512WithECEncryption":
		return "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512", nil
	case "SHA256WithRSAEncryption":
		return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", nil
	case "SHA384WithRSAEncryption":
		return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", nil
	case "SHA512WithRSAEncryption":
		return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", nil
	default:
		return "", fmt.Errorf("unsupported Mobile-ID signature algorithm %q", algorithm)
	}
}

func xmlEscape(s string) string {
	replacer := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&apos;",
	)
	return replacer.Replace(s)
}

var rdnShortNames = map[string]string{
	"1.2.840.113549.1.9.1": "emailAddress",
	"2.5.4.3":              "CN",
	"2.5.4.4":              "SN",
	"2.5.4.5":              "serialNumber",
	"2.5.4.6":              "C",
	"2.5.4.7":              "L",
	"2.5.4.8":              "ST",
	"2.5.4.10":             "O",
	"2.5.4.11":             "OU",
	"2.5.4.42":             "GN",
	"2.5.4.97":             "organizationIdentifier",
}

var rdnEscapeRE = regexp.MustCompile(`(^#|^ |["+,;<=>\\]| $)`)

func encodeRDNSequence(dn pkix.RDNSequence) string {
	if len(dn) == 0 {
		return ""
	}
	var b strings.Builder
	for i := len(dn) - 1; i >= 0; i-- {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		for j, atv := range dn[i] {
			if j > 0 {
				b.WriteByte('+')
			}
			oid := atv.Type.String()
			if short, ok := rdnShortNames[oid]; ok {
				oid = short
			}
			b.WriteString(oid)
			b.WriteByte('=')
			value, ok := atv.Value.(string)
			if ok {
				value = rdnEscapeRE.ReplaceAllString(value, `\$1`)
				value = strings.ReplaceAll(value, "\x00", `\00`)
			}
			if ok && rdnShortNames[atv.Type.String()] != "" {
				b.WriteString(value)
				continue
			}
			der, err := asn1.Marshal(atv.Value)
			if err != nil {
				b.WriteString("#")
				continue
			}
			b.WriteByte('#')
			b.WriteString(hex.EncodeToString(der))
		}
	}
	return b.String()
}
