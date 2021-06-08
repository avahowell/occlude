package occlude

// occlude implements the OPAQUE protocol
// (https://eprint.iacr.org/2018/163.pdf`), providing an asymmetric password
// authenticated key exchange (aPAKE) which is secure against precomputation
// attacks. This library can be used to provide password authentication for a
// networked service which never exposes the user's plaintext password to the
// server or to any network attacker. `occlude` utilizes the Ristretto group for
// protocol operations. Ristretto is preferred since it provides a safe,
// prime-order elliptic curve group, elements have a defined unique string
// representation, it provides a correct and simple hash-to-curve operation in
// Elligator2, and the implementation used in `occlude` is fully constant-time.
//
// The OPAQUE design calls for the following paramters:
//
//  Hash function H (e.g., a SHA2 or SHA3 function), a cyclic
//  group G of prime order q (with a defined unique string representation
//  of its elements), a generator g of G, and hash function H' mapping
//  arbitrary strings into G (where H' is modeled as a random oracle).
//
// `occlude` makes the following choices:
// H: SHA3 (Keccak)
// Group: Ristretto
// H': Elligator2
//
// All group operations, including hashing to the curve, are constant-time.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/subtle"
	"encoding/json"
	"errors"

	"golang.org/x/crypto/sha3"

	ristretto "github.com/gtank/ristretto255"
)

// TODO:
// - Think more about session identifiers and potential attacks here.
// - Add support for an extra round to mutually authenticate server and client.
// - Consider adding support for wrapping and returning arbitrary data in the
//   ciphertext, to enable exchange of material other than keys.
// - Implement session ID's, currently clients and servers are one-to-one
// - API Design: does the current API encourage safe usage by average
// developers? More importantly, does it do the correct thing when it is used
// unsafely?

type (
	// pendingRegistration is the result of a newly initialized registration. The
	// server stores these pendingregistrations in its state so that the generated
	// server public key, private key pair and random scalar `ks` can be used in
	// the registration process.
	pendingRegistration struct {
		ks *ristretto.Scalar
		Ps *ristretto.Element
		ps *ristretto.Scalar
	}

	// Registration is a request from the Client to register a new username. The
	// username is specified by Username, and the client supplies some
	// authCiphertext as well as their public key.
	Registration struct {
		ID  string
		aci authCiphertext
		Pu  *ristretto.Element
	}

	// pwdFile is the data stored by the server used to authenticate new user
	// sessions for registered users, according to the OPAQUE protocol.
	//
	// NOTE: this has essentially the same security properties as a password hash
	// in that anyone who knows this information can execute a dictionary attack
	// against the user's passphrase. This is an unavoidable property of PAKE designs.
	// Thus, it should be treated like a password
	// hash and not exposed to anyone except for the server. `occlude` uses
	// Argon2id to derive the OPRF key, so in practice dictionary attacks will be
	// very costly.
	pwdFile struct {
		ks *ristretto.Scalar
		ps *ristretto.Scalar
		Ps *ristretto.Element
		Pu *ristretto.Element
		c  authCiphertext
	}

	// UsrSession is sent by a client who wants to log in and create a session to
	// the Server.
	UsrSession struct {
		Alpha *ristretto.Element
		Xu    *ristretto.Element
		Sid   string
	}

	// SvrSession is the server's response to the session initiation by the Client.
	SvrSession struct {
		Beta *ristretto.Element
		Xs   *ristretto.Element
		fk1  []byte
		c    authCiphertext
	}

	ClientVerification struct {
		ID  string
		FK2 []byte
	}

	// authCiphertext is a simple struct which encodes an arbitrary-length
	// ciphertext with its associated MAC tag. In OPAQUE, we require a stronger
	// assumption than what is given by traditional AEAD modes ("key committal"),
	// so we use AES-CTR with an HMAC-SHA3 MAC.
	authCiphertext struct {
		Tag        []byte
		Ciphertext []byte
	}

	// ciphertextData is the structure of the plaintext that is encrypted to
	// ciphertext.
	ciphertextData struct {
		pu *ristretto.Scalar
		Pu *ristretto.Element
		Ps *ristretto.Element
	}

	// Server is the server in the OPAQUE protocol.
	Server struct {
		passwordFiles        map[string]pwdFile
		pendingRegistrations map[string]pendingRegistration
	}

	// Client is the client in the OPAQUE protocol.
	Client struct {
		Sid string
		xu  *ristretto.Scalar
		r   *ristretto.Scalar
	}
)

// NewClient creates a new OPAQUE client using the provided id.
func NewClient(id string) *Client {
	return &Client{
		Sid: id,
	}
}

// NewSession creates a new UsrSession using the provided password.
func (c *Client) NewSession(password string) (*UsrSession, error) {
	xu := randomScalar()
	Xu := new(ristretto.Element).ScalarBaseMult(xu)

	x := sha3.Sum512([]byte(password))
	Alpha := new(ristretto.Element).FromUniformBytes(x[:])
	r := randomScalar()
	Alpha.ScalarMult(r, Alpha)

	c.xu = xu
	c.r = r

	return &UsrSession{
		Alpha: Alpha,
		Xu:    Xu,
		Sid:   c.Sid,
	}, nil
}

// NewServer creates a new server.
func NewServer() *Server {
	return &Server{
		passwordFiles:        make(map[string]pwdFile),
		pendingRegistrations: make(map[string]pendingRegistration),
	}
}

// Register a new user with the server. NOTE: this step of the
// protocol should be executed over a secure, authenticated and
// confidential medium such as TLS.
func (s *Server) NewRegistration(sid string) (*pendingRegistration, error) {
	ks := randomScalar()
	ps := randomScalar()
	Ps := new(ristretto.Element).ScalarBaseMult(ps)
	s.pendingRegistrations[sid] = pendingRegistration{
		ks: ks,
		Ps: Ps,
		ps: ps,
	}
	return &pendingRegistration{ks: ks, Ps: Ps}, nil
}

// Register creates a new registration in the server using the
// provided details.
func (s *Server) Register(reg *Registration) error {
	pendingRegistration, exists := s.pendingRegistrations[reg.ID]
	if !exists {
		return errors.New("no pending registration")
	}
	defer delete(s.pendingRegistrations, reg.ID)
	if _, exists = s.passwordFiles[reg.ID]; exists {
		return errors.New("user already registered")
	}
	pf := pwdFile{
		ks: pendingRegistration.ks,
		ps: pendingRegistration.ps,
		Ps: pendingRegistration.Ps,
		Pu: reg.Pu,
		c:  reg.aci,
	}
	s.passwordFiles[reg.ID] = pf
	return nil
}

func (c *Client) NewRegistration(sinfo *pendingRegistration, username string, password string) (*Registration, error) {
	pu := randomScalar()
	Pu := new(ristretto.Element).ScalarBaseMult(pu)

	x := sha3.Sum512([]byte(password))
	rw := oprfA(x[:], sinfo.ks)

	// Use AES-CTR with HMAC and a separate HMAC key as a wrapping function, since
	// key-committing property is desired.
	hmacKey, cipherKey := deriveHKDFKeys(rw)

	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, block.BlockSize())
	ctr := cipher.NewCTR(block, iv)
	authHmac := hmac.New(sha3.New256, hmacKey)

	//	c←AuthEncrw(pu,Pu,Ps);
	toencrypt, err := json.Marshal(&ciphertextData{pu: pu, Pu: Pu, Ps: sinfo.Ps})
	if err != nil {
		return nil, err
	}

	ctext := make([]byte, len(toencrypt))
	ctr.XORKeyStream(ctext, toencrypt)
	tag := authHmac.Sum(ctext)

	aci := authCiphertext{
		Tag:        tag,
		Ciphertext: ctext,
	}

	return &Registration{
		username,
		aci,
		Pu,
	}, nil
}

func (s *Server) NewSession(session *UsrSession) (*SvrSession, []byte, error) {
	pf, exist := s.passwordFiles[session.Sid]
	if !exist {
		return nil, nil, errors.New("no such sid")
	}

	xs := randomScalar()
	Xs := new(ristretto.Element).ScalarBaseMult(xs)
	beta := new(ristretto.Element).ScalarMult(pf.ks, session.Alpha)

	K := keServer(pf.ps, xs, pf.Pu, session.Xu)
	SK := prf(K, []byte{0})
	fk1 := prf(K, []byte{1})

	return &SvrSession{Beta: beta, Xs: Xs, c: pf.c, fk1: fk1}, SK, nil
}

func (c *Client) SessionKey(session *SvrSession, password string) ([]byte, []byte, error) {
	x := sha3.Sum512([]byte(password))
	rw := oprfB(session.Beta, c.r, x)

	hmacKey, cipherKey := deriveHKDFKeys(rw)
	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return nil, nil, err
	}
	iv := make([]byte, block.BlockSize())
	ctr := cipher.NewCTR(block, iv)
	authHmac := hmac.New(sha3.New256, hmacKey)

	if subtle.ConstantTimeCompare(authHmac.Sum(session.c.Ciphertext), session.c.Tag) != 1 {
		return nil, nil, errors.New("invalid hmac tag on server-sent c")
	}

	var ca ciphertextData
	caData := make([]byte, len(session.c.Ciphertext))
	ctr.XORKeyStream(caData, session.c.Ciphertext)
	err = json.Unmarshal(caData, &ca)
	if err != nil {
		return nil, nil, err
	}

	K := keUser(ca.pu, c.xu, ca.Ps, session.Xs)
	SK := prf(K, []byte{0})
	fk1 := prf(K, []byte{1})
	if subtle.ConstantTimeCompare(fk1, session.fk1) != 1 {
		return nil, nil, errors.New("server authentication failed")
	}
	fk2 := prf(K, []byte{2})
	return SK, fk2, nil
}

func (c *ciphertextData) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Puscalar []byte `json:"pu"`
		Pu       []byte `json:"Pu"`
		Ps       []byte `json:"Ps"`
	}{
		c.pu.Encode(nil),
		c.Pu.Encode(nil),
		c.Ps.Encode(nil),
	})
}

func (c *ciphertextData) UnmarshalJSON(data []byte) error {
	encoded := &struct {
		Puscalar []byte `json:"pu"`
		Pu       []byte `json:"Pu"`
		Ps       []byte `json:"Ps"`
	}{}

	if err := json.Unmarshal(data, &encoded); err != nil {
		return err
	}
	return func() error {
		c.Pu = new(ristretto.Element)
		if err := c.Pu.Decode(encoded.Pu); err != nil {
			return err
		}
		c.pu = new(ristretto.Scalar)
		if err := c.pu.Decode(encoded.Puscalar); err != nil {
			return err
		}
		c.Ps = new(ristretto.Element)
		return c.Ps.Decode(encoded.Ps)
	}()
}
