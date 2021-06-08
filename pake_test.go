package occlude

import (
	"bytes"
	"testing"
)

// verify that a username can be registered.
func TestRegister(t *testing.T) {
	testpassword := "this is a test password"
	testusername := "this is a test username"

	s := NewServer()
	pr, err := s.NewRegistration(testusername)
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient(testusername)
	reg, err := c.NewRegistration(pr, testusername, testpassword)
	if err != nil {
		t.Fatal(err)
	}
	err = s.Register(reg)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := s.passwordFiles[testusername]; !exists {
		t.Fatal("did not create password file entry")
	}
	if _, exists := s.pendingRegistrations[testusername]; exists {
		t.Fatal("pending registration still exists")
	}
}

// verify that a session can be successfully created.
func TestLogin(t *testing.T) {
	// first, register
	testpassword := "this is a test password"
	testusername := "this is a test username"

	s := NewServer()
	c := NewClient(testusername)

	pr, err := s.NewRegistration(testusername)
	if err != nil {
		t.Fatal(err)
	}

	reg, err := c.NewRegistration(pr, testusername, testpassword)
	if err != nil {
		t.Fatal(err)
	}

	err = s.Register(reg)
	if err != nil {
		t.Fatal(err)
	}

	if _, exists := s.passwordFiles[testusername]; !exists {
		t.Fatal("did not create password file entry")
	}

	sess, err := c.NewSession(testpassword)
	if err != nil {
		t.Fatal(err)
	}

	svrsess, sessionKey, err := s.NewSession(sess)
	if err != nil {
		t.Fatal(err)
	}

	clientSessionKey, _, err := c.SessionKey(svrsess, testpassword)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(sessionKey, clientSessionKey) {
		t.Fatal("client and server did not compute identical session key")
	}

}
