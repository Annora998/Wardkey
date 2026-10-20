package approval

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/fxamacker/cbor/v2"

	"wardkey/internal/vault"
)

const (
	RPID      = "wardkey.local"
	rpName    = "Wardkey credential approval"
	algorithm = -7 // ECDSA with P-256 and SHA-256
)

var ErrAlreadyEnrolled = errors.New("Windows Hello approval is already enrolled")

type webAuthnAPI struct {
	makeCredential   *syscall.LazyProc
	freeAttestation  *syscall.LazyProc
	getAssertion     *syscall.LazyProc
	freeAssertion    *syscall.LazyProc
	deleteCredential *syscall.LazyProc
}

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

type webAuthnCredential struct {
	version        uint32
	idLength       uint32
	id             unsafe.Pointer
	credentialType uintptr
}

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
	attestationObject       unsafe.Pointer
	credentialIDLength      uint32
	credentialID            unsafe.Pointer
}

type webAuthnAssertion struct {
	version                 uint32
	authenticatorDataLength uint32
	authenticatorData       unsafe.Pointer
	signatureLength         uint32
	signature               unsafe.Pointer
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

// Enroll creates the first Windows Hello platform credential and stores its
// public verification data. It never overwrites an existing enrollment.
func Enroll(store *Store, approvalKey []byte) error {
	if store == nil {
		return errors.New("approval enrollment store is unavailable")
	}
	if len(approvalKey) != vault.ApprovalKeySize {
		return errors.New("invalid approval enrollment key")
	}

	if _, err := store.Load(approvalKey); err == nil {
		return ErrAlreadyEnrolled
	} else if !errors.Is(err, ErrNotEnrolled) {
		return fmt.Errorf("check existing approval enrollment: %w", err)
	}

	userID := userHandle(approvalKey)
	defer clear(userID)

	enrollment, err := createPlatformCredential(RPID, userID)
	if err != nil {
		if len(enrollment.CredentialID) != 0 {
			if deleteErr := deletePlatformCredential(enrollment.CredentialID); deleteErr != nil {
				return errors.Join(err, deleteErr)
			}
		}
		return err
	}

	if err := store.Create(enrollment, approvalKey); err != nil {
		deleteErr := deletePlatformCredential(enrollment.CredentialID)
		clear(enrollment.CredentialID)
		clear(enrollment.PublicKeyX)
		clear(enrollment.PublicKeyY)
		if deleteErr != nil {
			return errors.Join(fmt.Errorf("save approval enrollment: %w", err), deleteErr)
		}
		return fmt.Errorf("save approval enrollment: %w", err)
	}

	clear(enrollment.CredentialID)
	clear(enrollment.PublicKeyX)
	clear(enrollment.PublicKeyY)
	return nil
}

// Approve asks for explicit confirmation, then verifies a new Windows Hello
// assertion bound to the complete request. No approval is cached or reused.
func Approve(
	ctx context.Context,
	store *Store,
	approvalKey []byte,
	request Request,
) (bool, error) {
	if ctx == nil {
		return false, errors.New("approval context is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if store == nil {
		return false, errors.New("approval enrollment store is unavailable")
	}
	if len(approvalKey) != vault.ApprovalKeySize {
		return false, errors.New("invalid approval enrollment key")
	}
	if request.RPID != RPID {
		return false, errors.New("approval relying-party ID does not match")
	}

	enrollment, err := store.Load(approvalKey)
	if err != nil {
		return false, fmt.Errorf("load Windows Hello enrollment: %w", err)
	}
	defer clear(enrollment.CredentialID)
	defer clear(enrollment.PublicKeyX)
	defer clear(enrollment.PublicKeyY)

	if enrollment.RPID != RPID {
		return false, errors.New("enrollment relying-party ID does not match")
	}

	challenge, err := NewRequestChallenge(request)
	if err != nil {
		return false, err
	}
	defer clear(challenge)

	approved, err := ConfirmRequest(ctx, request)
	if err != nil || !approved {
		return approved, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}

	if err := verifyPlatformAssertion(ctx, enrollment, challenge); err != nil {
		return false, err
	}
	return true, nil
}

func createPlatformCredential(rpID string, userID []byte) (Enrollment, error) {
	var enrollment Enrollment
	if len(userID) == 0 || len(userID) > 64 {
		return enrollment, errors.New("invalid approval user handle")
	}

	api, err := loadWebAuthnAPI()
	if err != nil {
		return enrollment, err
	}
	window, err := consoleWindow()
	if err != nil {
		return enrollment, err
	}

	challenge, err := randomBytes(32)
	if err != nil {
		return enrollment, fmt.Errorf("create registration challenge: %w", err)
	}
	defer clear(challenge)

	clientJSON, err := makeClientData("webauthn.create", rpID, challenge)
	if err != nil {
		return enrollment, err
	}
	defer clear(clientJSON)

	rpIDPtr, err := syscall.UTF16PtrFromString(rpID)
	if err != nil {
		return enrollment, errors.New("encode relying-party ID")
	}
	rpNamePtr, err := syscall.UTF16PtrFromString(rpName)
	if err != nil {
		return enrollment, errors.New("encode relying-party name")
	}
	publicKeyTypePtr, err := syscall.UTF16PtrFromString("public-key")
	if err != nil {
		return enrollment, errors.New("encode credential type")
	}
	hashAlgPtr, err := syscall.UTF16PtrFromString("SHA-256")
	if err != nil {
		return enrollment, errors.New("encode hash algorithm")
	}
	userNamePtr, err := syscall.UTF16PtrFromString("wardkey")
	if err != nil {
		return enrollment, errors.New("encode user name")
	}
	displayNamePtr, err := syscall.UTF16PtrFromString("Wardkey approval")
	if err != nil {
		return enrollment, errors.New("encode display name")
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
	client := clientData{
		version:    1,
		jsonLength: uint32(len(clientJSON)),
		json:       uintptr(unsafe.Pointer(&clientJSON[0])),
		hashAlg:    uintptr(unsafe.Pointer(hashAlgPtr)),
	}
	options := makeOptionsV1{
		version:             1,
		timeoutMilliseconds: 60000,
		attachment:          1, // Platform authenticator: Windows Hello.
		userVerification:    1, // Required.
		attestation:         1, // None.
	}

	var attestationPointer unsafe.Pointer
	hr, _, _ := api.makeCredential.Call(
		window,
		uintptr(unsafe.Pointer(&rp)),
		uintptr(unsafe.Pointer(&user)),
		uintptr(unsafe.Pointer(&parameters)),
		uintptr(unsafe.Pointer(&client)),
		uintptr(unsafe.Pointer(&options)),
		uintptr(unsafe.Pointer(&attestationPointer)),
	)
	runtime.KeepAlive(rpIDPtr)
	runtime.KeepAlive(rpNamePtr)
	runtime.KeepAlive(publicKeyTypePtr)
	runtime.KeepAlive(hashAlgPtr)
	runtime.KeepAlive(userNamePtr)
	runtime.KeepAlive(displayNamePtr)
	runtime.KeepAlive(userID)
	runtime.KeepAlive(clientJSON)
	runtime.KeepAlive(rp)
	runtime.KeepAlive(user)
	runtime.KeepAlive(parameter)
	runtime.KeepAlive(parameters)
	runtime.KeepAlive(client)
	runtime.KeepAlive(options)

	if int32(hr) < 0 {
		return enrollment, hresultError("create Windows Hello credential", hr)
	}
	if attestationPointer == nil {
		return enrollment, errors.New("Windows returned no credential attestation")
	}
	defer func() {
		api.freeAttestation.Call(uintptr(attestationPointer))
		runtime.KeepAlive(attestationPointer)
	}()

	enrollment, err = extractEnrollment(attestationPointer, rpID)
	if err != nil {
		return enrollment, err
	}
	return enrollment, nil
}

func verifyPlatformAssertion(
	ctx context.Context,
	enrollment Enrollment,
	challenge []byte,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateEnrollment(enrollment); err != nil {
		return err
	}

	api, err := loadWebAuthnAPI()
	if err != nil {
		return err
	}
	window, err := consoleWindow()
	if err != nil {
		return err
	}

	clientJSON, err := makeClientData("webauthn.get", enrollment.RPID, challenge)
	if err != nil {
		return err
	}
	defer clear(clientJSON)

	rpIDPtr, err := syscall.UTF16PtrFromString(enrollment.RPID)
	if err != nil {
		return errors.New("encode assertion relying-party ID")
	}
	publicKeyTypePtr, err := syscall.UTF16PtrFromString("public-key")
	if err != nil {
		return errors.New("encode assertion credential type")
	}
	hashAlgPtr, err := syscall.UTF16PtrFromString("SHA-256")
	if err != nil {
		return errors.New("encode assertion hash algorithm")
	}

	credential := webAuthnCredential{
		version:        1,
		idLength:       uint32(len(enrollment.CredentialID)),
		id:             unsafe.Pointer(&enrollment.CredentialID[0]),
		credentialType: uintptr(unsafe.Pointer(publicKeyTypePtr)),
	}
	credentialList := credentials{
		count: 1,
		items: uintptr(unsafe.Pointer(&credential)),
	}
	client := clientData{
		version:    1,
		jsonLength: uint32(len(clientJSON)),
		json:       uintptr(unsafe.Pointer(&clientJSON[0])),
		hashAlg:    uintptr(unsafe.Pointer(hashAlgPtr)),
	}
	options := getAssertionOptionsV1{
		version:             1,
		timeoutMilliseconds: 60000,
		credentialList:      credentialList,
		attachment:          1, // Platform authenticator: Windows Hello.
		userVerification:    1, // Required.
	}

	var assertionPointer unsafe.Pointer
	hr, _, _ := api.getAssertion.Call(
		window,
		uintptr(unsafe.Pointer(rpIDPtr)),
		uintptr(unsafe.Pointer(&client)),
		uintptr(unsafe.Pointer(&options)),
		uintptr(unsafe.Pointer(&assertionPointer)),
	)
	runtime.KeepAlive(rpIDPtr)
	runtime.KeepAlive(publicKeyTypePtr)
	runtime.KeepAlive(hashAlgPtr)
	runtime.KeepAlive(enrollment.CredentialID)
	runtime.KeepAlive(credential)
	runtime.KeepAlive(credentialList)
	runtime.KeepAlive(clientJSON)
	runtime.KeepAlive(client)
	runtime.KeepAlive(options)

	if int32(hr) < 0 {
		return hresultError("request Windows Hello assertion", hr)
	}
	if assertionPointer == nil {
		return errors.New("Windows returned no assertion")
	}
	defer func() {
		api.freeAssertion.Call(uintptr(assertionPointer))
		runtime.KeepAlive(assertionPointer)
	}()

	if err := ctx.Err(); err != nil {
		return err
	}

	assertion := (*webAuthnAssertion)(assertionPointer)
	return verifyAssertion(
		assertion,
		enrollment,
		clientJSON,
		challenge,
	)
}

func extractEnrollment(pointer unsafe.Pointer, rpID string) (Enrollment, error) {
	var enrollment Enrollment
	if pointer == nil {
		return enrollment, errors.New("Windows returned no credential attestation")
	}
	attested := (*credentialAttestation)(pointer)

	if attested.credentialIDLength == 0 ||
		attested.credentialIDLength > 1024 ||
		attested.credentialID == nil {
		return enrollment, errors.New("Windows returned an invalid credential ID")
	}
	enrollment.CredentialID = append(
		[]byte(nil),
		unsafe.Slice(
			(*byte)(attested.credentialID),
			int(attested.credentialIDLength),
		)...,
	)

	if attested.attestationObjectLength == 0 ||
		attested.attestationObjectLength > 1<<20 ||
		attested.attestationObject == nil {
		return enrollment, errors.New("Windows returned an invalid attestation object")
	}
	attestationBytes := unsafe.Slice(
		(*byte)(attested.attestationObject),
		int(attested.attestationObjectLength),
	)

	var object attestationObject
	if err := cbor.Unmarshal(attestationBytes, &object); err != nil {
		return enrollment, fmt.Errorf("decode attestation object: %w", err)
	}
	defer clear(object.AuthData)

	if len(object.AuthData) < 55 {
		return enrollment, errors.New("attestation authenticator data is too short")
	}

	expectedRPHash := sha256.Sum256([]byte(rpID))
	if !equalBytes(object.AuthData[:32], expectedRPHash[:]) {
		return enrollment, errors.New("attestation relying-party hash does not match")
	}

	const (
		flagUserPresent     = 0x01
		flagUserVerified    = 0x04
		flagAttestedData    = 0x40
		flagExtensionData   = 0x80
		requiredCreateFlags = flagUserPresent | flagUserVerified | flagAttestedData
	)
	flags := object.AuthData[32]
	if flags&requiredCreateFlags != requiredCreateFlags || flags&flagExtensionData != 0 {
		return enrollment, errors.New("attestation lacks required user verification or has unexpected extensions")
	}

	credentialIDLength := int(binary.BigEndian.Uint16(object.AuthData[53:55]))
	credentialStart := 55
	credentialEnd := credentialStart + credentialIDLength
	if credentialIDLength == 0 || credentialEnd > len(object.AuthData) {
		return enrollment, errors.New("attestation contains an invalid credential ID length")
	}
	if !equalBytes(object.AuthData[credentialStart:credentialEnd], enrollment.CredentialID) {
		return enrollment, errors.New("attestation credential ID does not match Windows output")
	}

	var coseKey coseEC2Key
	if err := cbor.Unmarshal(object.AuthData[credentialEnd:], &coseKey); err != nil {
		return enrollment, fmt.Errorf("decode credential public key: %w", err)
	}
	defer clear(coseKey.X)
	defer clear(coseKey.Y)

	if coseKey.KeyType != 2 || coseKey.Algorithm != algorithm || coseKey.Curve != 1 {
		return enrollment, errors.New("credential public key is not an expected P-256 ES256 key")
	}
	if len(coseKey.X) != 32 || len(coseKey.Y) != 32 {
		return enrollment, errors.New("credential public key coordinates have an invalid length")
	}

	x := new(big.Int).SetBytes(coseKey.X)
	y := new(big.Int).SetBytes(coseKey.Y)
	if !elliptic.P256().IsOnCurve(x, y) {
		return enrollment, errors.New("credential public key is not on the P-256 curve")
	}

	enrollment.Version = enrollmentVersion
	enrollment.RPID = rpID
	enrollment.PublicKeyX = make([]byte, 32)
	enrollment.PublicKeyY = make([]byte, 32)
	x.FillBytes(enrollment.PublicKeyX)
	y.FillBytes(enrollment.PublicKeyY)
	return enrollment, nil
}

func verifyAssertion(
	got *webAuthnAssertion,
	enrollment Enrollment,
	clientJSON []byte,
	expectedChallenge []byte,
) error {
	if got == nil {
		return errors.New("Windows returned an invalid assertion")
	}
	if got.authenticatorDataLength < 37 ||
		got.authenticatorDataLength > 1<<20 ||
		got.authenticatorData == nil {
		return errors.New("assertion authenticator data is invalid")
	}
	if got.signatureLength == 0 || got.signatureLength > 1024 || got.signature == nil {
		return errors.New("assertion signature is invalid")
	}
	if got.credential.idLength == 0 ||
		got.credential.idLength > 1024 ||
		got.credential.id == nil {
		return errors.New("assertion credential ID is invalid")
	}

	actualCredentialID := unsafe.Slice(
		(*byte)(got.credential.id),
		int(got.credential.idLength),
	)
	if !equalBytes(actualCredentialID, enrollment.CredentialID) {
		return errors.New("assertion used a different credential")
	}

	authenticatorData := unsafe.Slice(
		(*byte)(got.authenticatorData),
		int(got.authenticatorDataLength),
	)
	expectedRPHash := sha256.Sum256([]byte(enrollment.RPID))
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
	if err := json.Unmarshal(clientJSON, &client); err != nil {
		return fmt.Errorf("decode assertion client data: %w", err)
	}
	if client.Type != "webauthn.get" || client.Origin != "https://"+enrollment.RPID {
		return errors.New("assertion client data type or origin does not match")
	}

	challenge, err := base64.RawURLEncoding.DecodeString(client.Challenge)
	if err != nil {
		return fmt.Errorf("decode assertion challenge: %w", err)
	}
	defer clear(challenge)
	if !equalBytes(challenge, expectedChallenge) {
		return errors.New("assertion challenge does not match this request")
	}

	x := new(big.Int).SetBytes(enrollment.PublicKeyX)
	y := new(big.Int).SetBytes(enrollment.PublicKeyY)
	publicKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}
	if !publicKey.Curve.IsOnCurve(publicKey.X, publicKey.Y) {
		return errors.New("enrolled public key is invalid")
	}

	clientDataHash := sha256.Sum256(clientJSON)
	signedData := make([]byte, 0, len(authenticatorData)+len(clientDataHash))
	signedData = append(signedData, authenticatorData...)
	signedData = append(signedData, clientDataHash[:]...)
	messageHash := sha256.Sum256(signedData)
	clear(signedData)

	signature := unsafe.Slice(
		(*byte)(got.signature),
		int(got.signatureLength),
	)
	if !ecdsa.VerifyASN1(publicKey, messageHash[:], signature) {
		return errors.New("assertion ECDSA signature is invalid")
	}
	return nil
}

func loadWebAuthnAPI() (*webAuthnAPI, error) {
	dll := syscall.NewLazyDLL("webauthn.dll")
	if err := dll.Load(); err != nil {
		return nil, fmt.Errorf("load Windows WebAuthn API: %w", err)
	}

	apiVersion, err := findWebAuthnProc(dll, "WebAuthNGetApiVersionNumber")
	if err != nil {
		return nil, err
	}
	version, _, _ := apiVersion.Call()
	if version < 1 {
		return nil, fmt.Errorf("unsupported Windows WebAuthn API version %d", version)
	}

	makeCredential, err := findWebAuthnProc(dll, "WebAuthNAuthenticatorMakeCredential")
	if err != nil {
		return nil, err
	}
	freeAttestation, err := findWebAuthnProc(dll, "WebAuthNFreeCredentialAttestation")
	if err != nil {
		return nil, err
	}
	getAssertion, err := findWebAuthnProc(dll, "WebAuthNAuthenticatorGetAssertion")
	if err != nil {
		return nil, err
	}
	freeAssertion, err := findWebAuthnProc(dll, "WebAuthNFreeAssertion")
	if err != nil {
		return nil, err
	}
	deleteCredential, err := findWebAuthnProc(dll, "WebAuthNDeletePlatformCredential")
	if err != nil {
		return nil, err
	}

	return &webAuthnAPI{
		makeCredential:   makeCredential,
		freeAttestation:  freeAttestation,
		getAssertion:     getAssertion,
		freeAssertion:    freeAssertion,
		deleteCredential: deleteCredential,
	}, nil
}

func deletePlatformCredential(credentialID []byte) error {
	if len(credentialID) == 0 || len(credentialID) > 1024 {
		return errors.New("cannot delete an invalid Windows Hello credential ID")
	}

	api, err := loadWebAuthnAPI()
	if err != nil {
		return err
	}
	hr, _, _ := api.deleteCredential.Call(
		uintptr(uint32(len(credentialID))),
		uintptr(unsafe.Pointer(&credentialID[0])),
	)
	runtime.KeepAlive(credentialID)
	if int32(hr) < 0 {
		return hresultError("delete Windows Hello credential", hr)
	}
	return nil
}

func consoleWindow() (uintptr, error) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("GetConsoleWindow")
	if err := proc.Find(); err != nil {
		return 0, fmt.Errorf("find console window API: %w", err)
	}
	window, _, _ := proc.Call()
	if window == 0 {
		return 0, errors.New("Windows did not provide a console window handle")
	}
	return window, nil
}

func findWebAuthnProc(dll *syscall.LazyDLL, name string) (*syscall.LazyProc, error) {
	proc := dll.NewProc(name)
	if err := proc.Find(); err != nil {
		return nil, fmt.Errorf("find Windows WebAuthn API %s: %w", name, err)
	}
	return proc, nil
}

func hresultError(action string, result uintptr) error {
	return fmt.Errorf("%s failed (HRESULT 0x%08X)", action, uint32(result))
}

func makeClientData(kind, rpID string, challenge []byte) ([]byte, error) {
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

func userHandle(approvalKey []byte) []byte {
	mac := hmac.New(sha256.New, approvalKey)
	_, _ = mac.Write([]byte("wardkey/webauthn/user-handle/v1"))
	return mac.Sum(nil)
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
