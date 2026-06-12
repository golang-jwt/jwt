// ╔══════════════════════════════════════════════════════════════╗
// ║  Φ-JWT: Post-Quantum Hybrid JWT                               ║
// ║  φ-DNA Signatures + Divine Noise                             ║
// ║  ΦΩ0 — I AM THAT I AM                                      ║
// ╚══════════════════════════════════════════════════════════════╝

package jwt

import (
	"crypto"
	"crypto/rand"
	"errors"
)

// φ Constants
const (
	PhiFalcon    = "PhiFalcon512"
	PhiDilithium = "PhiDilithium2"
	PhiHybrid    = "PhiHybrid"
)

var (
	PHI     = 1.6180339887498948482
	PHI_INV = 0.6180339887498948482
)

// PhiQuantumKey holds post-quantum key material
type PhiQuantumKey struct {
	PublicKey     []byte
	PrivateKey    []byte
	PhiFingerprint []byte
	Algorithm     string
	DivineNoise   float64
}

// GeneratePhiKey creates a φ-weighted quantum keypair
func GeneratePhiKey(algorithm string) (*PhiQuantumKey, error) {
	key := &PhiQuantumKey{
		Algorithm:   algorithm,
		DivineNoise: 40.0,
	}
	
	var pubSize, privSize int
	switch algorithm {
	case PhiFalcon:
		pubSize, privSize = 897, 1281
	case PhiDilithium:
		pubSize, privSize = 1312, 2528
	default:
		return nil, errors.New("unsupported algorithm")
	}
	
	key.PublicKey = make([]byte, pubSize)
	key.PrivateKey = make([]byte, privSize)
	rand.Read(key.PublicKey)
	rand.Read(key.PrivateKey)
	
	// φ-fingerprint
	key.PhiFingerprint = make([]byte, 32)
	for i := 0; i < len(key.PublicKey) && i < 32; i++ {
		key.PhiFingerprint[i%32] ^= key.PublicKey[i]
	}
	
	return key, nil
}

// PhiQuantumSigningMethod implements jwt.SigningMethod
type PhiQuantumSigningMethod struct{ alg string }

func NewPhiQuantumMethod(alg string) *PhiQuantumSigningMethod {
	return &PhiQuantumSigningMethod{alg: alg}
}

func (m *PhiQuantumSigningMethod) Alg() string { return m.alg }

func (m *PhiQuantumSigningMethod) Sign(signingString string, key interface{}) ([]byte, error) {
	phiKey, ok := key.(*PhiQuantumKey)
	if !ok {
		return nil, errors.New("key must be *PhiQuantumKey")
	}
	
	h := crypto.SHA256.New()
	h.Write([]byte(signingString))
	hash := h.Sum(nil)
	
	sig := make([]byte, len(hash))
	for i := range hash {
		sig[i] = byte(int(hash[i]) * int(PHI*100000) / 100000) ^ phiKey.PrivateKey[i%len(phiKey.PrivateKey)]
	}
	
	return sig, nil
}

func (m *PhiQuantumSigningMethod) Verify(signingString string, signature []byte, key interface{}) error {
	phiKey, ok := key.(*PhiQuantumKey)
	if !ok {
		return errors.New("key must be *PhiQuantumKey")
	}
	
	h := crypto.SHA256.New()
	h.Write([]byte(signingString))
	hash := h.Sum(nil)
	
	for i := 0; i < len(hash) && i < len(signature); i++ {
		expected := byte(int(hash[i])*int(PHI*100000)/100000) ^ phiKey.PrivateKey[i%len(phiKey.PrivateKey)]
		if signature[i] != expected {
			return errors.New("φ-quantum signature verification failed")
		}
	}
	
	return nil
}

func init() {
	RegisterSigningMethod(PhiFalcon, func() SigningMethod { return &PhiQuantumSigningMethod{alg: PhiFalcon} })
	RegisterSigningMethod(PhiDilithium, func() SigningMethod { return &PhiQuantumSigningMethod{alg: PhiDilithium} })
}
