package apple

import (
	"fmt"
	"testing"
)

var idToken = ""
var wrongToken = ""

func TestVerifyIdToken(t *testing.T) {
	client := New()

	jwtClaims, err := client.VerifyIdToken("com.game.sample", idToken)
	if err != nil {
		t.Errorf("%s", err)
	} else {
		fmt.Println(jwtClaims.Email)
	}
}

func TestVerifyWrongToken(t *testing.T) {
	client := New()

	jwtClaims, err := client.VerifyIdToken("com.ios.sample", wrongToken)
	if err != nil {
		t.Errorf("%s", err)
	} else {
		fmt.Println(jwtClaims.Email)
	}
}
