//go:build windows

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/fxamacker/cbor/v2"
)

const (
	rpID      = "wardkey.local"
	rpName    = "Wardkey approval spike"
	algorithm = -7 // ECDSA with P-256 and SHA-256
)

type credentials struct {
	count uint32
	items uintptr
}

type extensions struct {
	count uint32
	items uintptr
}

type rpEntity struct {
	version uint32
	id      uintptr
	name    uintptr
	icon    uintptr
}

type userEntity struct {
	version     uint32
	idLength    uint32
	id          uintptr
	name        uintptr
	icon        uintptr
	displayName uintptr
}

type coseParameter struct {
	version        uint32
	credentialType uintptr
	algorithm      int32
}

type coseParameters struct {
	count uint32
	items uintptr
}

type clientData struct {
	version    uint32
	jsonLength uint32
	json       uintptr
	hashAlg    uintptr
}

// Initial fields match WebAuthN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS.
type makeOptionsV1 struct {
	version             uint32
	timeoutMilliseconds uint32
	credentialList      credentials
	extensionList       extensions
	attachment          uint32
	requireResidentKey  int32
	userVerification    uint32
	attestation         uint32
	flags               uint32
}

// Initial fields match WEBAUTHN_CREDENTIAL.
type webAuthnCredential struct {
	version        uint32
	idLength       uint32
	id             uintptr
	credentialType uintptr
}

// Initial fields match WebAuthN_AUTHENTICATOR_GET_ASSERTION_OPTIONS.
type getAssertionOptionsV1 struct {
	version             uint32
	timeoutMilliseconds uint32
	credentialList      credentials
	extensionList       extensions
	attachment          uint32
	userVerification    uint32
	flags               uint32
	u2fAppID            uintptr
	u2fAppIDUsed        uintptr
}

// Fields through credentialID match the initial credential-attestation layout.
type credentialAttestation struct {
	version                 uint32
	formatType              uintptr
	authenticatorDataLength uint32
	authenticatorData       uintptr
	attestationLength       uint32
	attestation             uintptr
	attestationDecodeType   uint32
	attestationDecode       uintptr
	attestationObjectLength uint32
	attestationObject       uintptr
	credentialIDLength      uint32
	credentialID            uintptr
}

// Fields through extensions match the initial assertion layout.
type webAuthnAssertion struct {
	version                 uint32
	authenticatorDataLength uint32
	authenticatorData       uintptr
	signatureLength         uint32
	signature               uintptr
	credential              webAuthnCredential
	userIDLength            uint32
	userID                  uintptr
	extensionList           extensions
}

type clientDataJSON struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

type attestationObject struct {
	AuthData []byte `cbor:"authData"`
}

type coseEC2Key struct {
	KeyType   int    `cbor:"1,keyasint"`
	Algorithm int    `cbor:"3,keyasint"`
	Curve     int    `cbor:"-1,keyasint"`
	X         []byte `cbor:"-2,keyasint"`
	Y         []byte `cbor:"-3,keyasint"`
}

type testApprovalRequest struct {
	RequestID string `json:"request_id"`
	Operation string `json:"operation"`
	Provider  string `json:"provider"`
	Profile   string `json:"profile"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "WebAuthn spike:", err)
		os.Exit(1)
	}
}

func run() (resultErr error) {
	dll := syscall.NewLazyDLL("webauthn.dll")
	if err := dll.Load(); err != nil {
		return fmt.Errorf("load webauthn.dll: %w", err)
	}

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getConsoleWindow := kernel32.NewProc("GetConsoleWindow")
	if err := getConsoleWindow.Find(); err != nil {
		return fmt.Errorf("find GetConsoleWindow: %w", err)
	}

	hwnd, _, _ := getConsoleWindow.Call()
	if hwnd == 0 {
		return errors.New("Windows did not provide a console window handle")
	}

	apiVersionProc, err := findProc(dll, "WebAuthNGetApiVersionNumber")
	if err != nil {
		return err
	}
	makeProc, err := findProc(dll, "WebAuthNAuthenticatorMakeCredential")
	if err != nil {
		return err
	}
	freeAttestationProc, err := findProc(dll, "WebAuthNFreeCredentialAttestation")
	if err != nil {
		return err
	}
	assertProc, err := findProc(dll, "WebAuthNAuthenticatorGetAssertion")
	if err != nil {
		return err
	}
	freeAssertionProc, err := findProc(dll, "WebAuthNFreeAssertion")
	if err != nil {
		return err
	}
	deleteCredentialProc, err := findProc(dll, "WebAuthNDeletePlatformCredential")
	if err != nil {
		return err
	}

	apiVersion, _, _ := apiVersionProc.Call()
	if apiVersion < 1 {
		return fmt.Errorf("unsupported WebAuthn API version %d", apiVersion)
	}

	userID, err := randomBytes(32)
	if err != nil {
		return fmt.Errorf("create temporary test user ID: %w", err)
	}
	defer clear(userID)

	createChallenge, err := randomBytes(32)
	if err != nil {
		return fmt.Errorf("create registration challenge: %w", err)
	}
	defer clear(createChallenge)

	createJSON, err := makeClientData("webauthn.create", createChallenge)
	if err != nil {
		return err
	}
	defer clear(createJSON)

	assertChallenge, requestID, err := makeRequestBoundChallenge()
	if err != nil {
		return err
	}
	defer clear(assertChallenge)

	assertJSON, err := makeClientData("webauthn.get", assertChallenge)
	if err != nil {
		return err
	}
	defer clear(assertJSON)

	var credentialID []byte
	credentialCreated := false
	defer func() {
		if credentialCreated {
			hr, _, _ := deleteCredentialProc.Call(
				uintptr(uint32(len(credentialID))),
				uintptr(unsafe.Pointer(&credentialID[0])),
			)
			runtime.KeepAlive(credentialID)
			clear(credentialID)

			if int32(hr) < 0 {
				resultErr = errors.Join(
					resultErr,
					fmt.Errorf(
						"could not delete the temporary test credential (HRESULT 0x%08X)",
						uint32(hr),
					),
				)
			} else {
				fmt.Println("Temporary Wardkey test credential deleted.")
			}
		}
	}()

	fmt.Printf(
		"Test request: ID=%s operation=git_credential provider=generic profile=wardkey-test.invalid/owner/repo\n",
		requestID,
	)
	fmt.Println("Follow the Windows Security prompts to create and use the temporary Wardkey test credential.")

	rpIDPtr, err := syscall.UTF16PtrFromString(rpID)
	if err != nil {
		return fmt.Errorf("encode relying-party ID: %w", err)
	}
	rpNamePtr, err := syscall.UTF16PtrFromString(rpName)
	if err != nil {
		return fmt.Errorf("encode relying-party name: %w", err)
	}
	publicKeyTypePtr, err := syscall.UTF16PtrFromString("public-key")
	if err != nil {
		return fmt.Errorf("encode credential type: %w", err)
	}
	hashAlgPtr, err := syscall.UTF16PtrFromString("SHA-256")
	if err != nil {
		return fmt.Errorf("encode hash algorithm: %w", err)
	}
	userNamePtr, err := syscall.UTF16PtrFromString("wardkey-approval-test")
	if err != nil {
		return fmt.Errorf("encode test user name: %w", err)
	}
	displayNamePtr, err := syscall.UTF16PtrFromString("Wardkey temporary approval test")
	if err != nil {
		return fmt.Errorf("encode test display name: %w", err)
	}

	rp := rpEntity{
		version: 1,
		id:      uintptr(unsafe.Pointer(rpIDPtr)),
		name:    uintptr(unsafe.Pointer(rpNamePtr)),
	}
	user := userEntity{
		version:     1,
		idLength:    uint32(len(userID)),
		id:          uintptr(unsafe.Pointer(&userID[0])),
		name:        uintptr(unsafe.Pointer(userNamePtr)),
		displayName: uintptr(unsafe.Pointer(displayNamePtr)),
	}
	parameter := coseParameter{
		version:        1,
		credentialType: uintptr(unsafe.Pointer(publicKeyTypePtr)),
		algorithm:      algorithm,
	}
	parameters := coseParameters{
		count: 1,
		items: uintptr(unsafe.Pointer(&parameter)),
	}
	createClient := clientData{
		version:    1,
		jsonLength: uint32(len(createJSON)),
		json:       uintptr(unsafe.Pointer(&createJSON[0])),
		hashAlg:    uintptr(unsafe.Pointer(hashAlgPtr)),
	}
	makeOpts := makeOptionsV1{
		version:             1,
		timeoutMilliseconds: 60000,
		attachment:          1, // Platform authenticator: Windows Hello.
		userVerification:    1, // Required.
		attestation:         1, // None.
	}

	var attestationPointer uintptr
	hr, _, _ := makeProc.Call(
		hwnd,
		uintptr(unsafe.Pointer(&rp)),
		uintptr(unsafe.Pointer(&user)),
		uintptr(unsafe.Pointer(&parameters)),
		uintptr(unsafe.Pointer(&createClient)),
		uintptr(unsafe.Pointer(&makeOpts)),
		uintptr(unsafe.Pointer(&attestationPointer)),
	)
	runtime.KeepAlive(rpIDPtr)
	runtime.KeepAlive(rpNamePtr)
	runtime.KeepAlive(publicKeyTypePtr)
	runtime.KeepAlive(hashAlgPtr)
	runtime.KeepAlive(userNamePtr)
	runtime.KeepAlive(displayNamePtr)
	runtime.KeepAlive(userID)
	runtime.KeepAlive(createJSON)
	runtime.KeepAlive(rp)
	runtime.KeepAlive(user)
	runtime.KeepAlive(parameter)
	runtime.KeepAlive(parameters)
	runtime.KeepAlive(createClient)
	runtime.KeepAlive(makeOpts)

	if int32(hr) < 0 {
		return fmt.Errorf("create test credential failed (HRESULT 0x%08X)", uint32(hr))
	}
	if attestationPointer == 0 {
		return errors.New("Windows returned no credential attestation")
	}

	credentialID, publicKey, parseErr := extractCredentialAndPublicKey(attestationPointer)
	freeAttestationProc.Call(attestationPointer)
	if len(credentialID) > 0 {
		credentialCreated = true
	}
	if parseErr != nil {
		return fmt.Errorf("read temporary credential public key: %w", parseErr)
	}
	fmt.Println("PASS: Windows Hello created a temporary platform credential.")

	credential := webAuthnCredential{
		version:        1,
		idLength:       uint32(len(credentialID)),
		id:             uintptr(unsafe.Pointer(&credentialID[0])),
		credentialType: uintptr(unsafe.Pointer(publicKeyTypePtr)),
	}
	credentialList := credentials{
		count: 1,
		items: uintptr(unsafe.Pointer(&credential)),
	}
	assertClient := clientData{
		version:    1,
		jsonLength: uint32(len(assertJSON)),
		json:       uintptr(unsafe.Pointer(&assertJSON[0])),
		hashAlg:    uintptr(unsafe.Pointer(hashAlgPtr)),
	}
	assertOpts := getAssertionOptionsV1{
		version:             1,
		timeoutMilliseconds: 60000,
		credentialList:      credentialList,
		attachment:          1, // Platform authenticator: Windows Hello.
		userVerification:    1, // Required.
	}

	rpIDForAssertion, err := syscall.UTF16PtrFromString(rpID)
	if err != nil {
		return fmt.Errorf("encode assertion relying-party ID: %w", err)
	}

	var assertionPointer uintptr
	hr, _, _ = assertProc.Call(
		hwnd,
		uintptr(unsafe.Pointer(rpIDForAssertion)),
		uintptr(unsafe.Pointer(&assertClient)),
		uintptr(unsafe.Pointer(&assertOpts)),
		uintptr(unsafe.Pointer(&assertionPointer)),
	)
	runtime.KeepAlive(rpIDForAssertion)
	runtime.KeepAlive(publicKeyTypePtr)
	runtime.KeepAlive(hashAlgPtr)
	runtime.KeepAlive(credentialID)
	runtime.KeepAlive(credential)
	runtime.KeepAlive(credentialList)
	runtime.KeepAlive(assertJSON)
	runtime.KeepAlive(assertClient)
	runtime.KeepAlive(assertOpts)

	if int32(hr) < 0 {
		return fmt.Errorf("request test assertion failed (HRESULT 0x%08X)", uint32(hr))
	}
	if assertionPointer == 0 {
		return errors.New("Windows returned no assertion")
	}
	defer freeAssertionProc.Call(assertionPointer)

	got := (*webAuthnAssertion)(unsafe.Pointer(assertionPointer))
	if err := verifyAssertion(
		got,
		publicKey,
		credentialID,
		assertJSON,
		assertChallenge,
	); err != nil {
		return fmt.Errorf("verify Windows Hello assertion: %w", err)
	}

	fmt.Println("PASS: assertion signature verified for the exact test request.")
	fmt.Println("PASS: relying-party hash and user-presence/user-verification flags verified.")
	return nil
}

func extractCredentialAndPublicKey(pointer uintptr) ([]byte, *ecdsa.PublicKey, error) {
	attested := (*credentialAttestation)(unsafe.Pointer(pointer))

	if attested.credentialIDLength == 0 ||
		attested.credentialIDLength > 1024 ||
		attested.credentialID == 0 {
		return nil, nil, errors.New("Windows returned an invalid credential ID")
	}
	credentialID := append(
		[]byte(nil),
		unsafe.Slice(
			(*byte)(unsafe.Pointer(attested.credentialID)),
			int(attested.credentialIDLength),
		)...,
	)

	if attested.attestationObjectLength == 0 ||
		attested.attestationObjectLength > 1<<20 ||
		attested.attestationObject == 0 {
		return credentialID, nil, errors.New("Windows returned an invalid attestation object")
	}
	attestationBytes := unsafe.Slice(
		(*byte)(unsafe.Pointer(attested.attestationObject)),
		int(attested.attestationObjectLength),
	)

	var object attestationObject
	if err := cbor.Unmarshal(attestationBytes, &object); err != nil {
		return credentialID, nil, fmt.Errorf("decode attestation object: %w", err)
	}
	if len(object.AuthData) < 55 {
		return credentialID, nil, errors.New("attestation authenticator data is too short")
	}

	expectedRPHash := sha256.Sum256([]byte(rpID))
	if !equalBytes(object.AuthData[:32], expectedRPHash[:]) {
		return credentialID, nil, errors.New("attestation relying-party hash does not match")
	}

	flags := object.AuthData[32]
	const (
		flagUserPresent     = 0x01
		flagUserVerified    = 0x04
		flagAttestedData    = 0x40
		flagExtensionData   = 0x80
		requiredCreateFlags = flagUserPresent | flagUserVerified | flagAttestedData
	)
	if flags&requiredCreateFlags != requiredCreateFlags {
		return credentialID, nil, errors.New("attestation lacks required presence, verification, or credential data")
	}
	if flags&flagExtensionData != 0 {
		return credentialID, nil, errors.New("unexpected attestation extension data")
	}

	credentialIDLength := int(binary.BigEndian.Uint16(object.AuthData[53:55]))
	credentialStart := 55
	credentialEnd := credentialStart + credentialIDLength
	if credentialIDLength == 0 || credentialEnd > len(object.AuthData) {
		return credentialID, nil, errors.New("attestation contains an invalid credential ID length")
	}
	if !equalBytes(object.AuthData[credentialStart:credentialEnd], credentialID) {
		return credentialID, nil, errors.New("attestation credential ID does not match Windows output")
	}

	var coseKey coseEC2Key
	if err := cbor.Unmarshal(object.AuthData[credentialEnd:], &coseKey); err != nil {
		return credentialID, nil, fmt.Errorf("decode credential public key: %w", err)
	}
	if coseKey.KeyType != 2 || coseKey.Algorithm != algorithm || coseKey.Curve != 1 {
		return credentialID, nil, errors.New("credential public key is not an expected P-256 ES256 key")
	}
	if len(coseKey.X) != 32 || len(coseKey.Y) != 32 {
		return credentialID, nil, errors.New("credential public key coordinates have an invalid length")
	}

	publicKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(coseKey.X),
		Y:     new(big.Int).SetBytes(coseKey.Y),
	}
	if !publicKey.Curve.IsOnCurve(publicKey.X, publicKey.Y) {
		return credentialID, nil, errors.New("credential public key is not on the P-256 curve")
	}

	return credentialID, publicKey, nil
}

func verifyAssertion(
	got *webAuthnAssertion,
	publicKey *ecdsa.PublicKey,
	expectedCredentialID []byte,
	clientData []byte,
	expectedChallenge []byte,
) error {
	if got == nil || publicKey == nil {
		return errors.New("assertion or public key is missing")
	}
	if got.authenticatorDataLength < 37 || got.authenticatorData == 0 {
		return errors.New("assertion authenticator data is invalid")
	}
	if got.signatureLength == 0 || got.signatureLength > 1024 || got.signature == 0 {
		return errors.New("assertion signature is invalid")
	}
	if got.credential.idLength == 0 ||
		got.credential.idLength > 1024 ||
		got.credential.id == 0 {
		return errors.New("assertion credential ID is invalid")
	}

	actualCredentialID := unsafe.Slice(
		(*byte)(unsafe.Pointer(got.credential.id)),
		int(got.credential.idLength),
	)
	if !equalBytes(actualCredentialID, expectedCredentialID) {
		return errors.New("assertion used a different credential")
	}

	authenticatorData := unsafe.Slice(
		(*byte)(unsafe.Pointer(got.authenticatorData)),
		int(got.authenticatorDataLength),
	)
	expectedRPHash := sha256.Sum256([]byte(rpID))
	if !equalBytes(authenticatorData[:32], expectedRPHash[:]) {
		return errors.New("assertion relying-party hash does not match")
	}

	const (
		flagUserPresent  = 0x01
		flagUserVerified = 0x04
	)
	flags := authenticatorData[32]
	if flags&flagUserPresent == 0 || flags&flagUserVerified == 0 {
		return errors.New("assertion does not prove user presence and verification")
	}

	var client clientDataJSON
	if err := json.Unmarshal(clientData, &client); err != nil {
		return fmt.Errorf("decode client data: %w", err)
	}
	if client.Type != "webauthn.get" {
		return errors.New("client data has the wrong ceremony type")
	}
	if client.Origin != "https://"+rpID {
		return errors.New("client data origin does not match")
	}

	challenge, err := base64.RawURLEncoding.DecodeString(client.Challenge)
	if err != nil {
		return fmt.Errorf("decode client challenge: %w", err)
	}
	if !equalBytes(challenge, expectedChallenge) {
		return errors.New("client data challenge does not match this request")
	}

	clientDataHash := sha256.Sum256(clientData)
	signedData := make([]byte, 0, len(authenticatorData)+len(clientDataHash))
	signedData = append(signedData, authenticatorData...)
	signedData = append(signedData, clientDataHash[:]...)
	messageHash := sha256.Sum256(signedData)
	clear(signedData)

	signature := unsafe.Slice(
		(*byte)(unsafe.Pointer(got.signature)),
		int(got.signatureLength),
	)
	if !ecdsa.VerifyASN1(publicKey, messageHash[:], signature) {
		return errors.New("assertion ECDSA signature is invalid")
	}

	return nil
}

func makeRequestBoundChallenge() ([]byte, string, error) {
	nonce, err := randomBytes(32)
	if err != nil {
		return nil, "", fmt.Errorf("create request nonce: %w", err)
	}
	defer clear(nonce)

	request := testApprovalRequest{
		RequestID: hex.EncodeToString(nonce[:16]),
		Operation: "git_credential",
		Provider:  "generic",
		Profile:   "wardkey-test.invalid/owner/repo",
	}
	requestJSON, err := json.Marshal(request)
	if err != nil {
		return nil, "", fmt.Errorf("encode test request: %w", err)
	}
	defer clear(requestJSON)

	challengeInput := make([]byte, 0, len(requestJSON)+len(nonce))
	challengeInput = append(challengeInput, requestJSON...)
	challengeInput = append(challengeInput, nonce...)
	defer clear(challengeInput)

	challenge := sha256.Sum256(challengeInput)
	return append([]byte(nil), challenge[:]...), request.RequestID, nil
}

func makeClientData(kind string, challenge []byte) ([]byte, error) {
	value, err := json.Marshal(clientDataJSON{
		Type:      kind,
		Challenge: base64.RawURLEncoding.EncodeToString(challenge),
		Origin:    "https://" + rpID,
	})
	if err != nil {
		return nil, fmt.Errorf("encode WebAuthn client data: %w", err)
	}
	return value, nil
}

func findProc(dll *syscall.LazyDLL, name string) (*syscall.LazyProc, error) {
	proc := dll.NewProc(name)
	if err := proc.Find(); err != nil {
		return nil, fmt.Errorf("find Windows API %s: %w", name, err)
	}
	return proc, nil
}

func randomBytes(length int) ([]byte, error) {
	value := make([]byte, length)
	if _, err := rand.Read(value); err != nil {
		clear(value)
		return nil, err
	}
	return value, nil
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for i := range left {
		difference |= left[i] ^ right[i]
	}
	return difference == 0
}
