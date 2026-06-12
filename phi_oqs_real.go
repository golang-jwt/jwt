// ╔══════════════════════════════════════════════════════════════╗
// ║  Φ-JWT: Real liboqs PQC Integration                           ║
// ║  Falcon-512 / Dilithium-2 via CGO                            ║
// ║  ΦΩ0 — I AM THAT I AM                                      ║
// ╚══════════════════════════════════════════════════════════════╝

package jwt

/*
#cgo LDFLAGS: -loqs
#include <stdlib.h>
#include <oqs/oqs.h>

// Generate Falcon-512 keypair
int phi_falcon_keygen(uint8_t **pub, size_t *pub_len, uint8_t **priv, size_t *priv_len) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_falcon_512);
    if (!sig) return -1;
    
    *pub_len = sig->length_public_key;
    *priv_len = sig->length_secret_key;
    *pub = (uint8_t*)malloc(*pub_len);
    *priv = (uint8_t*)malloc(*priv_len);
    
    int ret = OQS_SIG_keypair(sig, *pub, *priv);
    OQS_SIG_free(sig);
    return ret;
}

// Falcon-512 sign
int phi_falcon_sign(uint8_t **sig_out, size_t *sig_len, 
                    const uint8_t *msg, size_t msg_len,
                    const uint8_t *priv_key) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_falcon_512);
    if (!sig) return -1;
    
    *sig_len = sig->length_signature;
    *sig_out = (uint8_t*)malloc(*sig_len);
    
    int ret = OQS_SIG_sign(sig, *sig_out, sig_len, msg, msg_len, priv_key);
    OQS_SIG_free(sig);
    return ret;
}

// Falcon-512 verify
int phi_falcon_verify(const uint8_t *msg, size_t msg_len,
                      const uint8_t *signature, size_t sig_len,
                      const uint8_t *pub_key) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_falcon_512);
    if (!sig) return -1;
    
    int ret = OQS_SIG_verify(sig, msg, msg_len, signature, sig_len, pub_key);
    OQS_SIG_free(sig);
    return ret;
}
*/
import "C"
import (
	"fmt"
	"errors"
	"unsafe"
)

// ═══════════════════════════════════════════════
// RealOQSKey — Actual PQC key material
// ═══════════════════════════════════════════════
type RealOQSKey struct {
	PublicKey  []byte
	PrivateKey []byte
	Algorithm  string
}

// GenerateRealOQSKey generates a real Falcon-512 keypair via liboqs
func GenerateRealOQSKey() (*RealOQSKey, error) {
	var pub *C.uint8_t
	var priv *C.uint8_t
	var pubLen, privLen C.size_t
	
	ret := C.phi_falcon_keygen(&pub, &pubLen, &priv, &privLen)
	if ret != 0 {
		return nil, errors.New("OQS Falcon-512 keygen failed")
	}
	defer C.free(unsafe.Pointer(pub))
	defer C.free(unsafe.Pointer(priv))
	
	key := &RealOQSKey{
		PublicKey:  C.GoBytes(unsafe.Pointer(pub), C.int(pubLen)),
		PrivateKey: C.GoBytes(unsafe.Pointer(priv), C.int(privLen)),
		Algorithm:  "Falcon-512",
	}
	
	return key, nil
}

// RealOQSSigningMethod — actual PQC signing
type RealOQSSigningMethod struct {
	alg string
}

func NewRealOQSMethod() *RealOQSSigningMethod {
	return &RealOQSSigningMethod{alg: "PhiFalcon512-Real"}
}

func (m *RealOQSSigningMethod) Alg() string { return m.alg }

func (m *RealOQSSigningMethod) Sign(signingString string, key interface{}) ([]byte, error) {
	oqsKey, ok := key.(*RealOQSKey)
	if !ok {
		return nil, errors.New("key must be *RealOQSKey")
	}
	
	msg := []byte(signingString)
	var sigOut *C.uint8_t
	var sigLen C.size_t
	
	ret := C.phi_falcon_sign(&sigOut, &sigLen,
		(*C.uint8_t)(unsafe.Pointer(&msg[0])), C.size_t(len(msg)),
		(*C.uint8_t)(unsafe.Pointer(&oqsKey.PrivateKey[0])))
	
	if ret != 0 {
		return nil, errors.New("OQS Falcon-512 sign failed")
	}
	defer C.free(unsafe.Pointer(sigOut))
	
	signature := C.GoBytes(unsafe.Pointer(sigOut), C.int(sigLen))
	return signature, nil
}

func (m *RealOQSSigningMethod) Verify(signingString string, signature []byte, key interface{}) error {
	oqsKey, ok := key.(*RealOQSKey)
	if !ok {
		return errors.New("key must be *RealOQSKey")
	}
	
	msg := []byte(signingString)
	
	ret := C.phi_falcon_verify(
		(*C.uint8_t)(unsafe.Pointer(&msg[0])), C.size_t(len(msg)),
		(*C.uint8_t)(unsafe.Pointer(&signature[0])), C.size_t(len(signature)),
		(*C.uint8_t)(unsafe.Pointer(&oqsKey.PublicKey[0])))
	
	if ret != 0 {
		return errors.New("OQS Falcon-512 verification failed")
	}
	
	return nil
}

func init() {
	RegisterSigningMethod("PhiFalcon512-Real", func() SigningMethod {
		return &RealOQSSigningMethod{alg: "PhiFalcon512-Real"}
	})
	fmt.Println("Φ-JWT: Real Falcon-512 PQC via liboqs registered!")
}

var _ SigningMethod = (*RealOQSSigningMethod)(nil)
