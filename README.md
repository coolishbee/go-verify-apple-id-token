# go-verify-apple-id-token

![](https://img.shields.io/badge/golang-1.19-blue.svg?style=flat)

This repository is inspired by [verify-apple-id-token](https://github.com/stefanprokopdev/verify-apple-id-token)

# Feature

- Small utility which verifies the Apple idToken
- You can use it on the backend side
- Token verification is part of [Apple sign-in](https://developer.apple.com/documentation/signinwithapplerestapi) process
- The flow is
  - Client app (iOS or Android) will redirect user to the OAuth2 login screen
  - User will login
  - App will receive the tokens
  - App should send the `idToken` to the backend which will verify it
- [Verification steps implemented](https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_rest_api/verifying_a_user):
  - Verify the JWS E256 signature using the server’s public key
  - Verify the nonce for the authentication
  - Verify that the iss field contains https://appleid.apple.com
  - Verify that the aud field is the developer’s client_id
  - Verify that the time is earlier than the exp value of the token

# Installation
```
go get github.com/coolishbee/go-verify-apple-id-token
```

## Usage

```go
import(
    "github.com/coolishbee/go-verify-apple-id-token"
)

var idToken = ""

func main() {
	client := apple.New()

	jwtClaims, err := client.VerifyIdToken("clientId", idToken)
	if err != nil {
        fmt.Println(err)
	} else {
		fmt.Println(jwtClaims.Email)
	}
}
```