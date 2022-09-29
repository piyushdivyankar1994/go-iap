package appstore

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

const (
	SandboxHistorySK2URL    string = "https://api.storekit-sandbox.itunes.apple.com/inApps/v1/history/"
	ProductionHistorySK2URL string = "https://api.storekit.itunes.apple.com/inApps/v1/history/"
	SandboxConsumeSK2URL    string = "https://api.storekit-sandbox.itunes.apple.com/inApps/v1/transactions/consumption/"
	ProductionConsumeSK2URL string = "https://api.storekit.itunes.apple.com/inApps/v1/transactions/consumption/"
)

type IAPClientSK2 interface {
	GetTransactionHistory(
		ctx context.Context,
		originalTransactionId string,
		queryParams map[string]interface{},
		historyResponse interface{},
	) error
	SendConsumptionInfo(
		ctx context.Context,
		originalTransactionId string,
		req_body ConsumptionRequest,
	) error
	GenerateJWTToken() string
}

type ClientSK2 struct {
	SandboxHistorySK2URL    string
	ProductionHistorySK2URL string
	SandboxConsumeSK2URL    string
	ProductionConsumeSK2URL string
	JWTSettings             *JWTSettings
	httpCli                 *http.Client
}

type JWTSettings struct {
	alg string
	kid string
	typ string
	bid string // bundle id
	iss string // issuer id
	key *ecdsa.PrivateKey
}

type JWTPayload struct {
	Iss string `json:"iss"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Aud string `json:"aud"`
	Bid string `json:"bid"`
}

func (payload *JWTPayload) Valid() error {
	return nil
}

func (jwts *JWTSettings) New(kid, bid, iss string, privateKey *ecdsa.PrivateKey) {
	jwts.alg = "ES256"
	jwts.kid = kid
	jwts.typ = "JWT"
	jwts.bid = bid
	jwts.iss = iss
	jwts.key = privateKey
}

func NewSK2Client(kid, bid, iss, keyFile string) *ClientSK2 {
	client := &ClientSK2{
		ProductionHistorySK2URL: ProductionHistorySK2URL,
		ProductionConsumeSK2URL: ProductionConsumeSK2URL,
		SandboxHistorySK2URL:    SandboxHistorySK2URL,
		SandboxConsumeSK2URL:    SandboxConsumeSK2URL,
		httpCli:                 &http.Client{},
		JWTSettings:             &JWTSettings{},
	}
	privateKey, err := GetPrivateKeyFromFile(keyFile)
	if err != nil {
		return nil
	}
	client.JWTSettings.New(kid, bid, iss, privateKey)
	return client
}

func GenerateJWTToken(payload *JWTPayload, jwtSettings *JWTSettings) (string, error) {
	t := jwt.NewWithClaims(jwt.GetSigningMethod(jwtSettings.alg), payload)
	t.Header["kid"] = jwtSettings.kid
	fmt.Println(t.Claims)
	return t.SignedString(jwtSettings.key)
}

func (client *ClientSK2) GetTransactionHistory(
	ctx context.Context,
	originalTransactionId string,
	queryParams map[string]interface{},
	historyResponse interface{},
) error {
	url := client.SandboxHistorySK2URL + originalTransactionId
	for k, v := range queryParams {
		url += fmt.Sprint("?%s=%v", k, v)
	}
	fmt.Println(url)
	b := new(bytes.Buffer)
	req, err := http.NewRequest("GET", url, b)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", ContentType)
	now := time.Now().Unix()
	payload := JWTPayload{
		Iss: client.JWTSettings.iss,
		Iat: now,
		Exp: now + time.Duration.Milliseconds(600*1000),
		Aud: "appstoreconnect-v1",
		Bid: client.JWTSettings.bid,
	}
	token, err := GenerateJWTToken(&payload, client.JWTSettings)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req = req.WithContext(ctx)
	resp, err := client.httpCli.Do(req)
	if err != nil {
		return err
	}
	rb, _ := io.ReadAll(resp.Body)
	fmt.Println(string(rb))
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf(
			"Recieved http status code %d from App Store:%w",
			resp.StatusCode,
			ErrAppStoreServer,
		)
	}
	// Handle response

	return nil
}

func (client *ClientSK2) SendConsumptionInfo(
	ctx context.Context,
	originalTransactionId string,
	req_body ConsumptionRequest,
) error {
	url := fmt.Sprintf("%s%s/", client.ProductionConsumeSK2URL, originalTransactionId)
	b := new(bytes.Buffer)
	if err := json.NewEncoder(b).Encode(req_body); err != nil {
		return err
	}
	req, err := http.NewRequest("PUT", url, b)
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", ContentType)
	req = req.WithContext(ctx)
	resp, err := client.httpCli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf(
			"Received http status code %d from App Store: %w",
			resp.StatusCode,
			ErrAppStoreServer,
		)
	} else if resp.StatusCode == 400 {
		return fmt.Errorf(
			"Invalid request. Ensure that the originalTransactionId represents a consumable in-app purchase, that all required fields are present in the ConsumptionRequest, and that the ConsumptionRequest indicates that you obtained customer consent in the customerConsented field.",
		)
	} else if resp.StatusCode == 401 {
		return fmt.Errorf(
			"The JSON Web Token (JWT) in the authorization header is invalid. For more information, see Generating Tokens for API Requests.",
		)
	} else if resp.StatusCode == 404 {
		return fmt.Errorf(
			"Not Found. The original transaction identifier wasn’t found.",
		)
	}
	return nil
}

func GetPrivateKeyFromFile(filepath string) (*ecdsa.PrivateKey, error) {
	bytes, err := ioutil.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, errors.New("invalid .p8 PEM file")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pk := key.(type) {
	case *ecdsa.PrivateKey:
		return pk, nil
	default:
		return nil, errors.New("AuthKey must be of type ecdsa.PrivateKey")
	}

}
