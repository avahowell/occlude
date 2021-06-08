package occlude

import (
	"crypto/rand"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"

	ristretto "github.com/gtank/ristretto255"
)

const (
	argonTime   = 3
	argonMemory = 1e5
)

// Compute and return a random ristretto scalar (←R Zq).
func randomScalar() *ristretto.Scalar {
	b := make([]byte, 64)
	_, err := rand.Read(b)
	if err != nil {
		panic("could not get entropy")
	}
	return new(ristretto.Scalar).FromUniformBytes(b)
}

// Compute the oprf output H(x, (H'(x))^k), where H' is a uniformly random
// unique mapping of arbitrary length data to an element of the curve group. The
// output is wrapped with Argon2ID to make dictionary attacks in the case of a
// compromised server more costly. See the OPAQUE protocol paper for more
// information about the design of this OPRF.
func oprfA(x []byte, k *ristretto.Scalar) []byte {
	hprimex := new(ristretto.Element).FromUniformBytes(x)  // H'(x)
	hprimex.ScalarMult(k, hprimex)                         // H'(x)^k
	hash := sha3.Sum512(append(x, hprimex.Encode(nil)...)) // H(x, (H'(x)^k))
	output := argon2.IDKey(hash[:], nil, argonTime, argonMemory, 4, 32)
	return output
}

// Compute the oprf output H(x, (H'(x))^k) given the input
// β = a^k = ((H'(pw))^r)^k, r, and password.
func oprfB(B *ristretto.Element, r *ristretto.Scalar, x [64]byte) []byte {
	rinv := new(ristretto.Scalar).Invert(r)
	// B^{1/r} = (a^k)^{1/r} = (((H'(x))^r)^k)^{1/r}) = (H'(x)^k)
	betarinv := new(ristretto.Element).ScalarMult(rinv, B)     // B^{1/r}
	hash := sha3.Sum512(append(x[:], betarinv.Encode(nil)...)) // H(x, (H'(x))^k)
	output := argon2.IDKey(hash[:], nil, argonTime, argonMemory, 4, 32)
	return output
}

// prf is a pseudorandom function, implemented with keyed Blake2B
func prf(k [32]byte, x []byte) []byte {
	b, err := blake2b.New256(k[:])
	if err != nil {
		panic(err)
	}
	_, err = b.Write(x)
	if err != nil {
		panic(err)
	}
	return b.Sum(nil)
}

// derive a separate authentication and cipher key using HKDF and the given
// input key `x`.
func deriveHKDFKeys(x []byte) (authKey []byte, cipherKey []byte) {
	hkdf := hkdf.New(sha3.New512, x, nil, nil)
	cipherKey = make([]byte, 32)
	authKey = make([]byte, 32)
	_, err := io.ReadFull(hkdf, cipherKey)
	if err != nil {
		panic("could not derive HKDF key material")
	}
	_, err = io.ReadFull(hkdf, authKey)
	if err != nil {
		panic("could not derive HKDF key material")
	}
	return
}

// Perform the key exchange. Compute the shared secret using ECDH with the
// provided static and ephemeral keys.
func keServer(ps *ristretto.Scalar, xs *ristretto.Scalar, Pu *ristretto.Element, Xu *ristretto.Element) [32]byte {
	xsPu := new(ristretto.Element).ScalarMult(xs, Pu)
	psXu := new(ristretto.Element).ScalarMult(ps, Xu)
	xsXu := new(ristretto.Element).ScalarMult(xs, Xu)
	sharedSecret := append(xsPu.Encode(nil), psXu.Encode(nil)...)
	sharedSecret = append(sharedSecret, xsXu.Encode(nil)...)
	return sha3.Sum256(sharedSecret)
}

// Perform the key exchange. Compute the shared secret using ECDH with the
// provided static and ephemeral keys.
func keUser(pu *ristretto.Scalar, xu *ristretto.Scalar, Ps *ristretto.Element, Xs *ristretto.Element) [32]byte {
	puXs := new(ristretto.Element).ScalarMult(pu, Xs)
	xuPs := new(ristretto.Element).ScalarMult(xu, Ps)
	xuXs := new(ristretto.Element).ScalarMult(xu, Xs)
	sharedSecret := append(puXs.Encode(nil), xuPs.Encode(nil)...)
	sharedSecret = append(sharedSecret, xuXs.Encode(nil)...)
	return sha3.Sum256(sharedSecret)
}

func clear(x []byte) {
	for i := 0; i < len(x); i++ {
		x[i] = 0
	}
}
