package genpass

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	random "math/rand"
	"time"
	"unicode/utf8"
)

const Symbols = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
const Digits = "0123456789"
const Letters = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm"

func validate(s string) bool {
	return utf8.RuneCountInString(s) != len(s)

}

type password struct {
	pass  []byte
	chars bytes.Buffer
}

func newPassword() *password {
	return &password{
		pass:  []byte{},
		chars: bytes.Buffer{},
	}
}

// New returns new password and error.
// Contains characters (a-zA-Z0-9) by defoult.
func New(chars ...string) (*password, error) {
	p, err := NewOnlyChars(chars...)
	if err != nil {
		return &password{}, err
	}
	err = p.Add(Digits, Letters)
	return p, err
}

// NewOnlyChars returns new password and error.
// The list of available characters is empty by default.
func NewOnlyChars(chars ...string) (*password, error) {
	p := newPassword()
	err := p.Add(chars...)
	return p, err
}

// Reset the list of characters from which the password is generated.
func (p *password) Reset() {
	p.chars.Reset()
}

// Add characters to the list of characters from which the password is generated.
func (p *password) Add(chars ...string) error {
	for i := range chars {
		if validate(chars[i]) {
			err := fmt.Sprintf("error: string( %s ) - contains invalid characters", chars[i])
			return errors.New(err)
		}
		if _, err := p.chars.WriteString(chars[i]); err != nil {
			return err
		}
	}
	return nil
}

// Generate password.
// The password must contain one character from each line of the list.
func (p *password) GenPass(n int, list ...string) (string, error) {
	if p.chars.Len() == 0 {
		return "", errors.New("error: the list of available characters is empty")
	}

	for i := range list {
		if validate(list[i]) {
			err := fmt.Sprintf("error: string( %s ) - contains invalid characters", list[i])
			return "", errors.New(err)
		}
	}

	p.pass = make([]byte, n)

	if err := p.randomBytes(); err != nil {
		return "", err
	}

	p.getPass(list...)
	p.shuffle()

	return string(p.pass), nil
}

func (p *password) randomBytes() error {
	_, err := rand.Read(p.pass)
	return err
}

func getChar(i int, chars string) byte {
	return chars[i%len(chars)]
}

func (p *password) getPass(listChars ...string) {
	chars := p.chars.Bytes()

	for i := range listChars {
		p.pass[i] = getChar(int(p.pass[i]), listChars[i])
	}
	pass := p.pass[len(listChars):]

	for i := range pass {
		j := int(pass[i])
		pass[i] = chars[j%len(chars)]
	}
}

func (p *password) shuffle() {
	random.Seed(time.Now().UnixNano())
	random.Shuffle(len(p.pass), func(i, j int) {
		p.pass[i], p.pass[j] = p.pass[j], p.pass[i]
	})
}
