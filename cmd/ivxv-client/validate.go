package main

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"sort"
	"strings"
)

type validateVoteReport struct {
	File             string               `json:"file"`
	Entries          []string             `json:"entries"`
	ManifestFiles    []string             `json:"manifestFiles,omitempty"`
	BallotFiles      []string             `json:"ballotFiles,omitempty"`
	ReferenceChecks  []validateCheck      `json:"referenceChecks"`
	SignatureChecks  []validateCheck      `json:"signatureChecks"`
	CiphertextChecks []validateCiphertext `json:"ciphertextChecks,omitempty"`
	ProbableFailure  string               `json:"probableFailure,omitempty"`
	Notes            []string             `json:"notes,omitempty"`
}

type validateCheck struct {
	Name  string `json:"name"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type validateCiphertext struct {
	File      string `json:"file"`
	Algorithm string `json:"algorithm,omitempty"`
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
}

type manifestDoc struct {
	XMLName xml.Name            `xml:"manifest"`
	Files   []manifestFileEntry `xml:"file-entry"`
}

type manifestFileEntry struct {
	FullPath  string `xml:"full-path,attr"`
	MediaType string `xml:"media-type,attr"`
}

type xadesSignaturesDoc struct {
	XMLName   xml.Name       `xml:"XAdESSignatures"`
	Signature xadesSignature `xml:"Signature"`
}

type xadesSignature struct {
	ID             string          `xml:"Id,attr"`
	SignedInfo     xadesSignedInfo `xml:"SignedInfo"`
	SignatureValue xadesValue      `xml:"SignatureValue"`
	KeyInfo        xadesKeyInfo    `xml:"KeyInfo"`
	Object         xadesObject     `xml:"Object"`
}

type xadesSignedInfo struct {
	ID                     string           `xml:"Id,attr"`
	CanonicalizationMethod xadesAlgorithm   `xml:"CanonicalizationMethod"`
	SignatureMethod        xadesAlgorithm   `xml:"SignatureMethod"`
	References             []xadesReference `xml:"Reference"`
}

type xadesAlgorithm struct {
	Algorithm string `xml:"Algorithm,attr"`
}

type xadesReference struct {
	ID           string           `xml:"Id,attr"`
	URI          string           `xml:"URI,attr"`
	Type         string           `xml:"Type,attr"`
	DigestMethod xadesAlgorithm   `xml:"DigestMethod"`
	DigestValue  string           `xml:"DigestValue"`
	Transforms   []xadesTransform `xml:"Transforms>Transform"`
}

type xadesTransform struct {
	Algorithm string `xml:"Algorithm,attr"`
}

type xadesValue struct {
	ID    string `xml:"Id,attr"`
	Value string `xml:",chardata"`
}

type xadesKeyInfo struct {
	X509Data xadesX509Data `xml:"X509Data"`
}

type xadesX509Data struct {
	X509Certificate string `xml:"X509Certificate"`
}

type xadesObject struct {
	QualifyingProperties xadesQualifyingProperties `xml:"QualifyingProperties"`
}

type xadesQualifyingProperties struct {
	SignedProperties xadesSignedProperties `xml:"SignedProperties"`
}

type xadesSignedProperties struct {
	ID                         string                     `xml:"Id,attr"`
	SignedSignatureProperties  xadesSignedSignatureProps  `xml:"SignedSignatureProperties"`
	SignedDataObjectProperties xadesSignedDataObjectProps `xml:"SignedDataObjectProperties"`
}

type xadesSignedSignatureProps struct {
	SigningCertificate xadesSigningCertificate `xml:"SigningCertificate"`
}

type xadesSigningCertificate struct {
	Cert xadesCert `xml:"Cert"`
}

type xadesCert struct {
	CertDigest   xadesCertDigest   `xml:"CertDigest"`
	IssuerSerial xadesIssuerSerial `xml:"IssuerSerial"`
}

type xadesCertDigest struct {
	DigestMethod xadesAlgorithm `xml:"DigestMethod"`
	DigestValue  string         `xml:"DigestValue"`
}

type xadesIssuerSerial struct {
	X509IssuerName   string `xml:"X509IssuerName"`
	X509SerialNumber string `xml:"X509SerialNumber"`
}

type xadesSignedDataObjectProps struct {
	DataObjectFormats []xadesDataObjectFormat `xml:"DataObjectFormat"`
}

type xadesDataObjectFormat struct {
	ObjectReference string `xml:"ObjectReference,attr"`
	MimeType        string `xml:"MimeType"`
}

func runValidateVote(args []string, cfg *appConfig) error {
	fs := flag.NewFlagSet("validate-vote", flag.ContinueOnError)
	path := fs.String("file", "", "path to the BDOC file to validate")
	encKeyPath := fs.String("enc-key-file", cfg.EncKeyPath, "PEM file containing the ElGamal vote encryption public key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" {
		return errors.New("validate-vote: -file is required")
	}

	report, err := validateVoteFile(*path, *encKeyPath)
	if err != nil {
		return err
	}
	return writeJSON(report)
}

func validateVoteFile(path, encKeyPath string) (validateVoteReport, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return validateVoteReport{}, fmt.Errorf("read BDOC: %w", err)
	}
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return validateVoteReport{}, fmt.Errorf("open BDOC zip: %w", err)
	}

	report := validateVoteReport{File: path}
	files := make(map[string][]byte, len(reader.File))
	for _, f := range reader.File {
		report.Entries = append(report.Entries, f.Name)
		rc, err := f.Open()
		if err != nil {
			return validateVoteReport{}, fmt.Errorf("open zip entry %q: %w", f.Name, err)
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return validateVoteReport{}, fmt.Errorf("read zip entry %q: %w", f.Name, err)
		}
		files[f.Name] = b
		if strings.HasSuffix(f.Name, ".ballot") {
			report.BallotFiles = append(report.BallotFiles, f.Name)
		}
	}
	sort.Strings(report.Entries)
	sort.Strings(report.BallotFiles)

	report.ReferenceChecks = append(report.ReferenceChecks, checkRequiredEntry(files, "mimetype"))
	report.ReferenceChecks = append(report.ReferenceChecks, checkRequiredEntry(files, "META-INF/manifest.xml"))
	report.ReferenceChecks = append(report.ReferenceChecks, checkRequiredEntry(files, "META-INF/signatures0.xml"))

	if mime := string(files["mimetype"]); mime != "application/vnd.etsi.asic-e+zip" {
		report.ReferenceChecks = append(report.ReferenceChecks, validateCheck{
			Name:  "mimetype value",
			OK:    false,
			Error: fmt.Sprintf("got %q", mime),
		})
	} else {
		report.ReferenceChecks = append(report.ReferenceChecks, validateCheck{Name: "mimetype value", OK: true})
	}

	manifest, sigdoc, signedInfoRaw, signedPropsRaw, err := parseValidationInputs(files)
	if err != nil {
		report.ProbableFailure = "invalid BDOC metadata"
		report.Notes = append(report.Notes, err.Error())
		return report, nil
	}

	for _, entry := range manifest.Files {
		if entry.FullPath != "/" {
			report.ManifestFiles = append(report.ManifestFiles, entry.FullPath)
		}
	}
	sort.Strings(report.ManifestFiles)
	report.ReferenceChecks = append(report.ReferenceChecks, validateManifestMediaTypes(manifest))

	report.ReferenceChecks = append(report.ReferenceChecks, validateManifestMatchesBallots(report.ManifestFiles, report.BallotFiles))
	report.ReferenceChecks = append(report.ReferenceChecks, validateBallotReferences(sigdoc, files)...)
	report.ReferenceChecks = append(report.ReferenceChecks, validateSignedPropertiesReference(sigdoc, signedPropsRaw))
	report.ReferenceChecks = append(report.ReferenceChecks, validateSignerCertificate(sigdoc))

	report.SignatureChecks = append(report.SignatureChecks, validateRawSignature(sigdoc, signedInfoRaw))
	report.SignatureChecks = append(report.SignatureChecks, validateSignedPropertiesFormats(sigdoc, report.BallotFiles))

	for _, check := range append(append([]validateCheck{}, report.ReferenceChecks...), report.SignatureChecks...) {
		if !check.OK {
			report.ProbableFailure = "BDOC signature/container mismatch"
			break
		}
	}

	if encKeyPath != "" {
		report.CiphertextChecks = validateCiphertexts(files, encKeyPath)
		for _, item := range report.CiphertextChecks {
			if !item.OK && report.ProbableFailure == "" {
				report.ProbableFailure = "ballot ciphertext format mismatch"
			}
		}
	}

	if report.ProbableFailure == "" {
		report.ProbableFailure = "no local mismatch found; remaining likely issue is XML canonicalization mismatch on SignedInfo/SignedProperties"
		report.Notes = append(report.Notes, "The local signature checks use the raw XML bytes inside signatures0.xml. The IVXV collector re-canonicalizes SignedInfo and SignedProperties before verifying.")
	}

	return report, nil
}

func validateManifestMediaTypes(manifest manifestDoc) validateCheck {
	var sawRoot bool
	for _, entry := range manifest.Files {
		if entry.FullPath == "/" {
			sawRoot = true
			if entry.MediaType != "application/vnd.etsi.asic-e+zip" {
				return validateCheck{Name: "manifest root MIME", OK: false, Error: "unexpected root media-type"}
			}
			continue
		}
		if entry.MediaType == "" {
			return validateCheck{Name: "manifest file MIME", OK: false, Error: "empty media-type for " + entry.FullPath}
		}
	}
	if !sawRoot {
		return validateCheck{Name: "manifest root MIME", OK: false, Error: "missing root / entry"}
	}
	return validateCheck{Name: "manifest MIME types", OK: true}
}

func parseValidationInputs(files map[string][]byte) (manifestDoc, xadesSignaturesDoc, []byte, []byte, error) {
	var manifest manifestDoc
	if err := xml.Unmarshal(files["META-INF/manifest.xml"], &manifest); err != nil {
		return manifestDoc{}, xadesSignaturesDoc{}, nil, nil, fmt.Errorf("parse manifest.xml: %w", err)
	}

	var sigdoc xadesSignaturesDoc
	signatureXML := files["META-INF/signatures0.xml"]
	if err := xml.Unmarshal(signatureXML, &sigdoc); err != nil {
		return manifest, xadesSignaturesDoc{}, nil, nil, fmt.Errorf("parse signatures0.xml: %w", err)
	}

	signedInfoRaw, err := extractXMLSegment(signatureXML, "<ds:SignedInfo", "</ds:SignedInfo>")
	if err != nil {
		return manifest, sigdoc, nil, nil, fmt.Errorf("extract SignedInfo: %w", err)
	}
	signedPropsRaw, err := extractXMLSegment(signatureXML, "<xades:SignedProperties", "</xades:SignedProperties>")
	if err != nil {
		return manifest, sigdoc, nil, nil, fmt.Errorf("extract SignedProperties: %w", err)
	}
	return manifest, sigdoc, signedInfoRaw, signedPropsRaw, nil
}

func checkRequiredEntry(files map[string][]byte, name string) validateCheck {
	_, ok := files[name]
	if !ok {
		return validateCheck{Name: "required entry " + name, OK: false, Error: "missing"}
	}
	return validateCheck{Name: "required entry " + name, OK: true}
}

func validateManifestMatchesBallots(manifestFiles, ballotFiles []string) validateCheck {
	if len(manifestFiles) != len(ballotFiles) {
		return validateCheck{
			Name:  "manifest ballot file count",
			OK:    false,
			Error: fmt.Sprintf("manifest=%d ballot files=%d", len(manifestFiles), len(ballotFiles)),
		}
	}
	for i := range manifestFiles {
		if manifestFiles[i] != ballotFiles[i] {
			return validateCheck{
				Name:  "manifest ballot file names",
				OK:    false,
				Error: fmt.Sprintf("manifest=%v ballot=%v", manifestFiles, ballotFiles),
			}
		}
	}
	return validateCheck{Name: "manifest ballot files", OK: true}
}

func validateBallotReferences(sigdoc xadesSignaturesDoc, files map[string][]byte) []validateCheck {
	var checks []validateCheck
	for _, ref := range sigdoc.Signature.SignedInfo.References {
		if ref.Type == "http://uri.etsi.org/01903#SignedProperties" {
			continue
		}
		data, ok := files[ref.URI]
		if !ok {
			checks = append(checks, validateCheck{
				Name:  "reference " + ref.URI,
				OK:    false,
				Error: "missing referenced file",
			})
			continue
		}
		if len(ref.Transforms) > 0 {
			checks = append(checks, validateCheck{
				Name:  "reference transforms " + ref.URI,
				OK:    false,
				Error: "unexpected transforms on ballot reference",
			})
			continue
		}
		got := sha256.Sum256(data)
		expected, err := base64.StdEncoding.DecodeString(strings.TrimSpace(ref.DigestValue))
		if err != nil {
			checks = append(checks, validateCheck{
				Name:  "reference digest " + ref.URI,
				OK:    false,
				Error: "invalid base64 digest",
			})
			continue
		}
		if !bytes.Equal(got[:], expected) {
			checks = append(checks, validateCheck{
				Name:  "reference digest " + ref.URI,
				OK:    false,
				Error: fmt.Sprintf("expected %s got %s", base64.StdEncoding.EncodeToString(expected), base64.StdEncoding.EncodeToString(got[:])),
			})
			continue
		}
		checks = append(checks, validateCheck{Name: "reference digest " + ref.URI, OK: true})
	}
	return checks
}

func validateSignedPropertiesReference(sigdoc xadesSignaturesDoc, signedPropsRaw []byte) validateCheck {
	canonical, err := canonicalizeXMLSnippet(string(signedPropsRaw))
	if err != nil {
		return validateCheck{Name: "SignedProperties digest", OK: false, Error: "canonicalization failed: " + err.Error()}
	}
	for _, ref := range sigdoc.Signature.SignedInfo.References {
		if ref.Type != "http://uri.etsi.org/01903#SignedProperties" {
			continue
		}
		got := sha256.Sum256([]byte(canonical))
		expected, err := base64.StdEncoding.DecodeString(strings.TrimSpace(ref.DigestValue))
		if err != nil {
			return validateCheck{Name: "SignedProperties digest", OK: false, Error: "invalid base64 digest"}
		}
		if !bytes.Equal(got[:], expected) {
			return validateCheck{
				Name:  "SignedProperties digest",
				OK:    false,
				Error: fmt.Sprintf("canonical digest mismatch: expected %s got %s", base64.StdEncoding.EncodeToString(expected), base64.StdEncoding.EncodeToString(got[:])),
			}
		}
		return validateCheck{Name: "SignedProperties digest", OK: true}
	}
	return validateCheck{Name: "SignedProperties reference", OK: false, Error: "missing SignedProperties reference"}
}

func validateSignerCertificate(sigdoc xadesSignaturesDoc) validateCheck {
	certBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigdoc.Signature.KeyInfo.X509Data.X509Certificate))
	if err != nil {
		return validateCheck{Name: "signer certificate", OK: false, Error: "invalid base64 certificate"}
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return validateCheck{Name: "signer certificate", OK: false, Error: err.Error()}
	}

	certDigest, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigdoc.Signature.Object.QualifyingProperties.SignedProperties.SignedSignatureProperties.SigningCertificate.Cert.CertDigest.DigestValue))
	if err != nil {
		return validateCheck{Name: "signing certificate digest", OK: false, Error: "invalid base64 digest"}
	}
	gotDigest := sha256.Sum256(cert.Raw)
	if !bytes.Equal(gotDigest[:], certDigest) {
		return validateCheck{Name: "signing certificate digest", OK: false, Error: "certificate digest mismatch"}
	}
	if strings.TrimSpace(sigdoc.Signature.Object.QualifyingProperties.SignedProperties.SignedSignatureProperties.SigningCertificate.Cert.IssuerSerial.X509SerialNumber) != cert.SerialNumber.String() {
		return validateCheck{Name: "signing certificate serial", OK: false, Error: "issuer serial mismatch"}
	}
	issuer := cert.Issuer
	issuer.ExtraNames = issuer.Names
	if strings.TrimSpace(sigdoc.Signature.Object.QualifyingProperties.SignedProperties.SignedSignatureProperties.SigningCertificate.Cert.IssuerSerial.X509IssuerName) != encodeRDNSequence(issuer.ToRDNSequence()) {
		return validateCheck{Name: "signing certificate issuer", OK: false, Error: "issuer name mismatch"}
	}
	return validateCheck{Name: "signer certificate", OK: true}
}

func validateRawSignature(sigdoc xadesSignaturesDoc, signedInfoRaw []byte) validateCheck {
	certBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigdoc.Signature.KeyInfo.X509Data.X509Certificate))
	if err != nil {
		return validateCheck{Name: "SignatureValue", OK: false, Error: "invalid base64 certificate"}
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return validateCheck{Name: "SignatureValue", OK: false, Error: err.Error()}
	}
	sigValue, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigdoc.Signature.SignatureValue.Value))
	if err != nil {
		return validateCheck{Name: "SignatureValue", OK: false, Error: "invalid base64 signature"}
	}

	canonical, err := canonicalizeXMLSnippet(string(signedInfoRaw))
	if err != nil {
		return validateCheck{Name: "SignatureValue", OK: false, Error: "canonicalization failed: " + err.Error()}
	}
	hash := sha256.Sum256([]byte(canonical))
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		sigValue, err = xmlECDSAToASN1(pub, sigValue)
		if err != nil {
			return validateCheck{Name: "SignatureValue", OK: false, Error: err.Error()}
		}
		if !ecdsa.VerifyASN1(pub, hash[:], sigValue) {
			return validateCheck{Name: "SignatureValue", OK: false, Error: "raw SignedInfo signature verification failed"}
		}
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], sigValue); err != nil {
			return validateCheck{Name: "SignatureValue", OK: false, Error: err.Error()}
		}
	default:
		return validateCheck{Name: "SignatureValue", OK: false, Error: fmt.Sprintf("unsupported public key type %T", cert.PublicKey)}
	}

	return validateCheck{Name: "SignatureValue", OK: true}
}

func validateSignedPropertiesFormats(sigdoc xadesSignaturesDoc, ballotFiles []string) validateCheck {
	if len(sigdoc.Signature.Object.QualifyingProperties.SignedProperties.SignedDataObjectProperties.DataObjectFormats) != len(ballotFiles) {
		return validateCheck{Name: "DataObjectFormat count", OK: false, Error: "count mismatch"}
	}
	refs := make(map[string]struct{}, len(sigdoc.Signature.SignedInfo.References))
	for _, ref := range sigdoc.Signature.SignedInfo.References {
		refs["#"+ref.ID] = struct{}{}
	}
	for _, dof := range sigdoc.Signature.Object.QualifyingProperties.SignedProperties.SignedDataObjectProperties.DataObjectFormats {
		if dof.MimeType != "application/octet-stream" {
			return validateCheck{Name: "DataObjectFormat MIME", OK: false, Error: "unexpected MIME type"}
		}
		if _, ok := refs[dof.ObjectReference]; !ok {
			return validateCheck{Name: "DataObjectFormat reference", OK: false, Error: "unknown ObjectReference " + dof.ObjectReference}
		}
	}
	return validateCheck{Name: "DataObjectFormat metadata", OK: true}
}

func validateCiphertexts(files map[string][]byte, encKeyPath string) []validateCiphertext {
	key, _, err := loadElectionPublicKey(encKeyPath)
	if err != nil {
		return []validateCiphertext{{File: encKeyPath, OK: false, Error: err.Error()}}
	}

	var ballotNames []string
	for name := range files {
		if strings.HasSuffix(name, ".ballot") {
			ballotNames = append(ballotNames, name)
		}
	}
	sort.Strings(ballotNames)

	out := make([]validateCiphertext, 0, len(ballotNames))
	for _, name := range ballotNames {
		ct := validateCiphertext{File: name}
		switch pk := key.(type) {
		case modPPublicKey:
			ct.Algorithm = ivxvModPElgamalOID.String()
			ct.Error = validateModPCiphertext(files[name], pk)
		case ecPublicKey:
			ct.Algorithm = ivxvECElgamalOID.String()
			ct.Error = validateECCiphertext(files[name], pk)
		default:
			ct.Error = fmt.Sprintf("unsupported key type %T", key)
		}
		ct.OK = ct.Error == ""
		out = append(out, ct)
	}
	return out
}

func validateModPCiphertext(data []byte, key modPPublicKey) string {
	var outer struct {
		Algorithm struct {
			Algorithm asn1.ObjectIdentifier
		}
		Data struct {
			A *big.Int
			B *big.Int
		}
	}
	if _, err := asn1.Unmarshal(data, &outer); err != nil {
		return "invalid ASN.1: " + err.Error()
	}
	if !outer.Algorithm.Algorithm.Equal(ivxvModPElgamalOID) {
		return "unexpected ciphertext OID " + outer.Algorithm.Algorithm.String()
	}
	if outer.Data.A == nil || outer.Data.B == nil {
		return "missing ModP group elements"
	}
	q := key.q()
	for _, item := range []struct {
		name string
		v    *big.Int
	}{
		{name: "A", v: outer.Data.A},
		{name: "B", v: outer.Data.B},
	} {
		if item.v.Sign() <= 0 || item.v.Cmp(key.P) >= 0 {
			return item.name + " is not in the group range"
		}
		if new(big.Int).Exp(item.v, q, key.P).Cmp(big.NewInt(1)) != 0 {
			return item.name + " is not in the expected subgroup"
		}
	}
	return ""
}

func validateECCiphertext(data []byte, key ecPublicKey) string {
	var outer struct {
		Algorithm struct {
			Algorithm asn1.ObjectIdentifier
		}
		Data struct {
			UBlind          []byte
			VBlindedMessage []byte
		}
	}
	if _, err := asn1.Unmarshal(data, &outer); err != nil {
		return "invalid ASN.1: " + err.Error()
	}
	if !outer.Algorithm.Algorithm.Equal(ivxvECElgamalOID) {
		return "unexpected ciphertext OID " + outer.Algorithm.Algorithm.String()
	}
	ux, uy := elliptic.Unmarshal(key.Curve, outer.Data.UBlind)
	if ux == nil || uy == nil || !key.Curve.IsOnCurve(ux, uy) {
		return "invalid U blind point"
	}
	vx, vy := elliptic.Unmarshal(key.Curve, outer.Data.VBlindedMessage)
	if vx == nil || vy == nil || !key.Curve.IsOnCurve(vx, vy) {
		return "invalid V blinded message point"
	}
	return ""
}

func extractXMLSegment(data []byte, start, end string) ([]byte, error) {
	s := bytes.Index(data, []byte(start))
	if s < 0 {
		return nil, errors.New("start tag not found")
	}
	e := bytes.Index(data[s:], []byte(end))
	if e < 0 {
		return nil, errors.New("end tag not found")
	}
	e += s + len(end)
	return cloneBytes(data[s:e]), nil
}

func xmlECDSAToASN1(pub *ecdsa.PublicKey, raw []byte) ([]byte, error) {
	size := (pub.Curve.Params().BitSize + 7) / 8
	if len(raw) != size*2 {
		return nil, fmt.Errorf("unexpected XML ECDSA signature length %d", len(raw))
	}
	type ecdsaSignature struct {
		R *big.Int
		S *big.Int
	}
	return asn1.Marshal(ecdsaSignature{
		R: new(big.Int).SetBytes(raw[:size]),
		S: new(big.Int).SetBytes(raw[size:]),
	})
}
