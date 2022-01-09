package snaptest

import (
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"gopkg.in/h2non/gock.v1"
)

// KID is the kid used by JWTGen
const KID = "iavFkL-RHipSr2PLhZ_u8gDDBBWc__e-0bVCPPkc0Tw"

// PEM is the certificate used for testing with a jwt
const PEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAsawHbOXHWCO7ZpI6YzPa/t8mTZyqvwtaKSr8YJGDMP8ClzN0
iI7Bm+y76+/1LD//1mtyERF1gSKEOAQjlp/vr42XAijnwedykP3vT8l72zRPY2na
PHWhsR3IejARH5WrAmooNOShqAZQmm/FQ4SvKywv0nE2/W0ZDjtG488wHfSUL45j
fnGVkNu1j72y2pWwRFf26H/zitE7ROzB/qcROK3Rxtfik2//7u2KUzXoGMEdjJpO
/ja/HAHdZwAj0WPvMN2jtPipvC1+sNLQX1QYXN+dHG0q9S/zX+6NtKsZkJB0H/83
uaVwQqTb55Tedh1j5sIm+YiDttnyMwyH85g0gwIDAQABAoIBAQCFTxNfNOUmj+Dr
bCpdBqp5c8uUjklbANSMcRFeD7BE0gIKmvQEBkDkknLJ64ikw/xc0M+MWPI2i0Rz
lz9wo94+dVlpqHGD/vnqKm4mCoJhDdXHPMQfew9wCm3CqFAgx7bBIA+86BMXNG3E
ArsbFvIrzYKwPnxJGFOlZvqgsXNj9T5xHMhN5HdMpiVz/XG/VoWXZPeS25vx/Nvn
TF/9PSEDiSLIOXAUvkmP754DaNE/JdY77wKB29ImmHwXTbyTXTww+XQRw+Um6FG3
xcJeqypC65nkQYHd8BtvWWsmg9xCWFpuGSwgZuGarj+Qp95Ky8DBLAG2ZDb58jKs
ORmlcvAxAoGBAOzZFqAsPJIX192cMkx8TWiUDy913r9B6H6/YUd78EjTby+qWxlc
9FHjxvKVscNetrffIitHrApHU84czsR0Jg3B2fTHOq/k69fMifdZAEHAvGmCGDDj
PlouTz1mjg/E4VXJ+0a+LqzNr5G0hHsNs/aNlpMQfBK4l34B8BzFPDoZAoGBAMAJ
9SpiCOwKF2GtodmYot81KCsOopBmCc+3PFbIeFQ5EJljoLY1p0eIu0jgxdiqZ/7u
WLflLSsMhxqikUUJUfp+qRzGxPPa10xbZdmpr+yhnXPQ1SaN0WriFDWFIaxBpBEt
hOaT1hZbJE9lSlEkMNQjXHK4JeMNkeFYnGawyO77AoGBAJJJKx5W9DpPm7Z2qOJw
y+bRu+dWZ/O9I3pVfiIGvMxeOwg3sfiiXwzNIK3oI1lGAJjkqlgM9oeKsopVZKgW
DQLmPlZfTzIgtEIfRP+O6wexoS2RepuHX5WXkL2dwBShR4QTMq3o/S8iA1R9KG5Q
clzP6rZ+sgNmG7tqOwGqGJ7RAoGAb3aYJYSHdzGYRqq4UYtFpda9vNgexT9knHrX
e+uZ5BDHMLDh/ECCGoQjaHaGf27RM+f1+K79m4oG9Q+8z9xMB9/ymnBIqt2vr3Mx
V7glE2zu7eUdguY30hjs7++ZDtl+uDW6ePcAATPfjHHXQ+eEq+zmYPO/kd0zeh+r
j/M2fXcCgYEA5bLUL0EEjVEQTnrQuxZp8f6INcAdRJoWU0hPMoheG5z6aLI1Lgdx
zPDmjUIw5pLfCuF/z6ObkMI/k5jW0jD3cttF5CO8V8FiXTnT7qyqz0UfH8KZJOKk
r+YcMRPq9Q6901xgww9X3iIO9HzZGYVkByh1XxfudpZnXcOfIM5/3Mw=
-----END RSA PRIVATE KEY-----`

// URLTest wraps making an http request to local test server
func URLTest(req *http.Request, jwtToken string, t *testing.T) (int, []byte, http.Header) {
	if len(jwtToken) > 0 {
		req.Header.Set("Authorization", "Bearer "+jwtToken)
	}
	client := &http.Client{}
	resp, err := client.Do(req)

	var body []byte

	if err != nil {
		t.Errorf("error making the request %v", err)
	} else {
		body, err = ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			log.Fatal(err)
		}
	}

	return resp.StatusCode, body, resp.Header
}

// Fatal fails the test if err is present
func Fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

// JWTGen generates a jwt token that can be used for testing
func JWTGen(userID int64, roles []string) string {
	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(PEM))
	Fatal(err)

	// get the signing alg
	alg := jwt.GetSigningMethod("RS512")
	if alg == nil {
		log.Fatal("Couldn't find signing method: RS512")
	}
	// setup claims
	claims := jwt.MapClaims{
		"uid":             "uid",
		"private_channel": "channel",
		"user_id":         userID,
		"roles":           roles,
	}

	// create a new token
	token := jwt.NewWithClaims(alg, claims)
	token.Header["kid"] = KID

	validJwt, signErr := token.SignedString(key)
	Fatal(signErr)

	return validJwt
}

// MockJwks adds mocks for the jwks servers
func MockJwks(url string) {

	// Register our local server
	gock.New(url).Persist().EnableNetworking()

	// Allow requests to local test url
	dynamoDbURL := os.Getenv("AWS_TEST_DYNAMODB")
	if dynamoDbURL == "" {
		Fatal(errors.New("AWS_TEST_DYNAMODB must be set to run tests"))
	}
	gock.New(dynamoDbURL).Persist().EnableNetworking()

	gock.New("https://www.snaplinker.com").
		Get("/jwks.json").
		Persist().
		Reply(200).
		BodyString(`{"keys":[{"kty":"RSA","e":"AQAB","n":"sawHbOXHWCO7ZpI6YzPa_t8mTZyqvwtaKSr8YJGDMP8ClzN0iI7Bm-y76-_1LD__1mtyERF1gSKEOAQjlp_vr42XAijnwedykP3vT8l72zRPY2naPHWhsR3IejARH5WrAmooNOShqAZQmm_FQ4SvKywv0nE2_W0ZDjtG488wHfSUL45jfnGVkNu1j72y2pWwRFf26H_zitE7ROzB_qcROK3Rxtfik2__7u2KUzXoGMEdjJpO_ja_HAHdZwAj0WPvMN2jtPipvC1-sNLQX1QYXN-dHG0q9S_zX-6NtKsZkJB0H_83uaVwQqTb55Tedh1j5sIm-YiDttnyMwyH85g0gw","kid":"iavFkL-RHipSr2PLhZ_u8gDDBBWc__e-0bVCPPkc0Tw","use":"sig","alg":"RS512"}]}`)

	gock.New("https://snaplinker.atomicjolt.xyz").
		Get("/jwks.json").
		Persist().
		Reply(200).
		BodyString(`{"keys":[{"kty":"RSA","e":"AQAB","n":"sawHbOXHWCO7ZpI6YzPa_t8mTZyqvwtaKSr8YJGDMP8ClzN0iI7Bm-y76-_1LD__1mtyERF1gSKEOAQjlp_vr42XAijnwedykP3vT8l72zRPY2naPHWhsR3IejARH5WrAmooNOShqAZQmm_FQ4SvKywv0nE2_W0ZDjtG488wHfSUL45jfnGVkNu1j72y2pWwRFf26H_zitE7ROzB_qcROK3Rxtfik2__7u2KUzXoGMEdjJpO_ja_HAHdZwAj0WPvMN2jtPipvC1-sNLQX1QYXN-dHG0q9S_zX-6NtKsZkJB0H_83uaVwQqTb55Tedh1j5sIm-YiDttnyMwyH85g0gw","kid":"iavFkL-RHipSr2PLhZ_u8gDDBBWc__e-0bVCPPkc0Tw","use":"sig","alg":"RS512"}]}`)

	gock.New("https://beta.snaplinker.com").
		Get("/jwks.json").
		Persist().
		Reply(200).
		BodyString(`{"keys":[{"kty":"RSA","e":"AQAB","n":"sawHbOXHWCO7ZpI6YzPa_t8mTZyqvwtaKSr8YJGDMP8ClzN0iI7Bm-y76-_1LD__1mtyERF1gSKEOAQjlp_vr42XAijnwedykP3vT8l72zRPY2naPHWhsR3IejARH5WrAmooNOShqAZQmm_FQ4SvKywv0nE2_W0ZDjtG488wHfSUL45jfnGVkNu1j72y2pWwRFf26H_zitE7ROzB_qcROK3Rxtfik2__7u2KUzXoGMEdjJpO_ja_HAHdZwAj0WPvMN2jtPipvC1-sNLQX1QYXN-dHG0q9S_zX-6NtKsZkJB0H_83uaVwQqTb55Tedh1j5sIm-YiDttnyMwyH85g0gw","kid":"iavFkL-RHipSr2PLhZ_u8gDDBBWc__e-0bVCPPkc0Tw","use":"sig","alg":"RS512"}]}`)
}
