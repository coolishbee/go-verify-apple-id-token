package apple

import (
	"fmt"
	"testing"
)

var idToken = ""

func TestVerifyIdToken(t *testing.T) {
	client := New()

	err := client.VerifyIdToken("", idToken)
	if err != nil {
		t.Errorf("%s", err)
	} else {
		fmt.Println("Pass")
	}
}
