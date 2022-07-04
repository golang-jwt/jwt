package jwe_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/golang-jwt/jwt/v4/jwe"
	"math/big"
	"os"
	"strings"
	"testing"
)

func TestParseEncrypted(t *testing.T) {
	originalToken := "eyJlbmMiOiJzb21lIn0.ZW5jcnlwdGVkS2V5.aXY.Y2lwaGVydGV4dA.dGFn"

	jweToken, err := jwe.ParseEncrypted(originalToken)

	if err != nil {
		t.Error(err)
		return
	}

	rawToken, err := jweToken.CompactSerialize()
	if err != nil {
		t.Error(err)
		return
	}

	if rawToken != originalToken {
		t.Error(fmt.Errorf("tokens are different: %s != %s", rawToken, originalToken))
	}
}

func TestRFC7516_A1(t *testing.T) {
	resultParts := []string{
		"eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ",
		"OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg",
		"48V1_ALb6US04U3b",
		"5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A",
		"XFBoMYUZodetZdvTiFvSkQ",
	}

	rawKey := `oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUW
				cJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3S
				psk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2a
				sbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMS
				tPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2dj
				YgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw`
	decodeString, err := base64.RawURLEncoding.DecodeString(strings.Replace(rawKey, "\t", "", -1))
	if err != nil {
		t.Error(err)
		return
	}
	b := big.Int{}
	b.SetBytes(decodeString)
	pk := &rsa.PublicKey{
		N: &b,
		E: 65537,
	}

	jwe.RandReader = bytes.NewReader([]byte{
		// CEK
		177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154,
		212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122,
		234, 64, 252,

		// IV
		227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219})
	defer func() {
		jwe.RandReader = rand.Reader
	}()

	originalText := []byte("The true sign of intelligence is not knowledge but imagination.")
	token, err := jwe.NewJWE(jwe.KeyAlgorithmRSAOAEP, pk, jwe.EncryptionTypeA256GCM, originalText)
	if err != nil {
		t.Error(err)
		return
	}

	compact, err := token.CompactSerialize()
	if err != nil {
		t.Error(err)
		return
	}

	for i, part := range strings.Split(compact, ".") {
		if part != resultParts[i] {
			if i == 1 {
				// Skip key encryption
				// rfc7516 Appendix-A.1.8
				// Note that since the RSAES-OAEP computation includes random values,
				// the encryption results above will not be completely reproducible.
				continue
			}
			t.Errorf("part %d: %s != %s", i, part, resultParts[i])
		}
	}
}

func TestDecrypt(t *testing.T) {
	keyData, _ := os.ReadFile("../test/sample_key.pub")
	pk, _ := jwt.ParseRSAPublicKeyFromPEM(keyData)

	originalText := "The true sign of intelligence is not knowledge but imagination."
	token, err := jwe.NewJWE(jwe.KeyAlgorithmRSAOAEP, pk, jwe.EncryptionTypeA256GCM, []byte(originalText))
	if err != nil {
		t.Error(err)
		return
	}

	keyData, _ = os.ReadFile("../test/sample_key")
	k, _ := jwt.ParseRSAPrivateKeyFromPEM(keyData)

	decrypted, err := token.Decrypt(k)
	if err != nil {
		t.Error(err)
		return
	}

	if string(decrypted) != originalText {
		t.Errorf("%s != %s", decrypted, originalText)
	}
}
