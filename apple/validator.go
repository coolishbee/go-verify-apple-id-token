package apple

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/mitchellh/mapstructure"
)

const APPLE_BASE_URL = "https://appleid.apple.com"
const JWKS_APPLE_URI = "/auth/keys"

// global cache for fast subsequent fetching
var applePublicKeyObject map[string]*rsa.PublicKey

// key object fetched from APPLE_KEYS_URL
type AppleKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type IdTokenResponse struct {
	Aud            string `json:"aud"`
	C_hash         string `mapstructure:"c_hash" json:"c_hash"`
	Email          string `json:"email"`
	EmailVerified  string `mapstructure:"email_verified" json:"email_verified"`
	AuthTime       int64  `mapstructure:"auth_time" json:"auth_time"`
	Exp            int64  `json:"exp"`
	Iat            int64  `json:"iat"`
	Iss            string `json:"iss"`
	Nonce          string `json:"nonce"`
	NonceSupported bool   `mapstructure:"nonce_supported" json:"nonce_supported"`
	Sub            string `json:"sub"`
}

type Client struct {
	httpCli *http.Client
}

func New() *Client {
	applePublicKeyObject = make(map[string]*rsa.PublicKey)

	client := &Client{
		httpCli: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
	return client
}

func (c *Client) VerifyIdToken(clientId, idToken string) (*IdTokenResponse, error) {
	jwtClaims := IdTokenResponse{}
	tokenClaims, err := jwt.ParseWithClaims(idToken, &jwt.MapClaims{}, func(t *jwt.Token) (interface{}, error) {
		//log.Println(t.Header["kid"].(string))
		//log.Println(t.Header["alg"].(string))
		kid := t.Header["kid"].(string)
		alg := t.Header["alg"].(string)
		return c.GetApplePublicKeyObject(kid, alg), nil
	})

	err = mapstructure.Decode(tokenClaims.Claims, &jwtClaims)
	if err != nil {
		log.Fatal(err)
	}

	// log.Printf("%t\n%#v", tokenClaims.Valid, tokenClaims.Claims)

	if jwtClaims.Iss != APPLE_BASE_URL {
		return nil, fmt.Errorf("The iss does not match the Apple URL - iss: %s | expected: %s", jwtClaims.Iss, APPLE_BASE_URL)
	}
	if jwtClaims.Aud != clientId {
		return nil, fmt.Errorf("The aud parameter does not include this client - is: %s | expected: %s", jwtClaims.Aud, clientId)
	}

	expTime := time.UnixMilli(jwtClaims.Exp)
	if time.Now().Before(expTime) {
		return nil, errors.New("exp is earlier than the current time.")
	}

	return &jwtClaims, nil
}

// locally cache and get apple rsa.PublicKey object
func (c *Client) GetApplePublicKeyObject(kid string, alg string) *rsa.PublicKey {
	//applePublicKeyObject := map[string]*rsa.PublicKey{}

	//if computed earlier, return the object
	if key, ok := applePublicKeyObject[kid+alg]; ok {
		return key
	}

	//get the key with specified kid from the web
	applePublicKey := c.getApplePublicKey(kid)
	//if key found, contrust a rsa.PublikKey object
	if applePublicKey != nil && applePublicKey.Alg == alg {
		key := getPublicKeyObject(applePublicKey.N, applePublicKey.E)
		applePublicKeyObject[kid+alg] = key
		return key
	}
	return nil
}

// get apple public key from the keys array
func (c *Client) getApplePublicKey(kid string) *AppleKey {

	var keys []AppleKey
	var err error

	//get the apple published public keys
	keys, err = c.getApplePublicKeys()
	if err != nil || keys == nil {
		return nil
	}

	//extract the key with specified kid
	for _, key := range keys {
		if key.Kid == kid {
			//stop and return if found
			return &key
		}
	}

	return nil
}

// make request to APPLE_KEYS_URL to get the keys
func (c *Client) getApplePublicKeys() ([]AppleKey, error) {

	//var c http.Client
	var req *http.Request
	var resp *http.Response
	var bodyContents []byte
	var err error
	var keys struct {
		Keys []AppleKey `json:"keys"`
	}

	//make http client
	//c = http.Client{Timeout: 5 * time.Second}
	req, err = http.NewRequest("GET", APPLE_BASE_URL+JWKS_APPLE_URI, nil)
	if err != nil {
		return nil, err
	}
	log.Println(req.URL)
	//perform request
	resp, err = c.httpCli.Do(req)
	if err != nil {
		return nil, err
	}

	//read response
	bodyContents, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	//unmarshal into struct
	err = json.Unmarshal(bodyContents, &keys)
	if err != nil {
		return nil, err
	}

	//return the keys fetched
	return keys.Keys, nil
}

// function to generate rsa.PublicKey object from encoded modulo and exponent
func getPublicKeyObject(base64urlEncodedN string, base64urlEncodedE string) *rsa.PublicKey {

	var pub rsa.PublicKey
	var decE, decN []byte
	var eInt int
	var err error

	//get the modulo
	decN, err = base64.RawURLEncoding.DecodeString(base64urlEncodedN)
	if err != nil {
		return nil
	}
	pub.N = new(big.Int)
	pub.N.SetBytes(decN)
	//get exponent
	decE, err = base64.RawURLEncoding.DecodeString(base64urlEncodedE)
	if err != nil {
		return nil
	}
	//convert the bytes into int
	for _, v := range decE {
		eInt = eInt << 8
		eInt = eInt | int(v)
	}
	pub.E = eInt

	return &pub
}
