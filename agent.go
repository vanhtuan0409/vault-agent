package vaultagent

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"

	vault "github.com/hashicorp/vault/api"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	ErrOperationUnsupported = errors.New("operation unsupported")
	negativeForSign         = map[string]bool{
		"0":     true,
		"false": true,
	}
)

type Agent struct {
	c         *vault.Client
	mountPath string
	keyPrefix string
}

func NewAgent(c *vault.Client, path string) (*Agent, error) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 1 {
		return nil, errors.New("invalid secret path")
	}

	return &Agent{
		c:         c,
		mountPath: parts[0],
		keyPrefix: strings.Join(parts[1:], "/"),
	}, nil
}

func (a *Agent) ServeConn(c net.Conn) error {
	defer c.Close()
	if err := agent.ServeAgent(a, c); err != io.EOF {
		log.Println("Agent handle connection failed:", err)
		return err
	}
	return nil
}

func (a *Agent) List() ([]*agent.Key, error) {
	signers, err := a.getSigners(false)
	if err != nil {
		return nil, err
	}
	ret := []*agent.Key{}
	for _, s := range signers {
		pk := s.PublicKey()
		ret = append(ret, &agent.Key{
			Format: pk.Type(),
			Blob:   pk.Marshal(),
		})
	}
	return ret, nil
}

func (a *Agent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	signers, err := a.getSigners(false)
	if err != nil {
		return nil, err
	}
	for _, s := range signers {
		if !bytes.Equal(s.PublicKey().Marshal(), key.Marshal()) {
			continue
		}
		return s.Sign(rand.Reader, data)
	}

	return nil, fmt.Errorf("no private key match requested public key")
}

func (a *Agent) Add(key agent.AddedKey) error {
	return ErrOperationUnsupported
}

func (a *Agent) Remove(key ssh.PublicKey) error {
	return ErrOperationUnsupported
}

func (a *Agent) RemoveAll() error {
	return ErrOperationUnsupported
}

func (a *Agent) Lock(passphrase []byte) error {
	return ErrOperationUnsupported
}

func (a *Agent) Unlock(passphrase []byte) error {
	return ErrOperationUnsupported
}

func (a *Agent) Signers() ([]ssh.Signer, error) {
	return a.getSigners(true)
}

func (a *Agent) getSigners(forSign bool) ([]ssh.Signer, error) {
	path := a.keyListPath()
	secret, err := a.c.Logical().List(path)
	if err != nil {
		return nil, err
	}
	items, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return nil, errors.New("unable to get logical list")
	}

	ret := []ssh.Signer{}
	for _, key := range items {
		keyStr, ok := key.(string)
		if !ok {
			continue
		}
		aKey, keyForSign, err := a.getSSHKey(keyStr)
		if err != nil {
			log.Printf("Unable to get ssh key name `%s`:%v\n", keyStr, err)
			continue
		}
		if keyForSign == forSign {
			ret = append(ret, aKey)
		}
	}

	return ret, nil
}

func (a *Agent) kv2() *vault.KVv2 {
	return a.c.KVv2(a.mountPath)
}

func (a *Agent) keyListPath() string {
	return strings.Join([]string{a.mountPath, "metadata", a.keyPrefix}, "/")
}

func (a *Agent) keyPath(name string) string {
	return strings.Join([]string{a.keyPrefix, name}, "/")
}

func (a *Agent) getSSHKey(name string) (ssh.Signer, bool, error) {
	ctx := context.Background()
	secret, err := a.kv2().Get(ctx, a.keyPath(name))
	if err != nil {
		return nil, false, err
	}
	privateKeyData, privateOk := secret.Data["private"].(string)
	if !privateOk {
		return nil, false, fmt.Errorf("invalid private key for `%s`", name)
	}
	privateKey, err := ssh.ParsePrivateKey([]byte(privateKeyData))
	if err != nil {
		return nil, false, err
	}

	forSign := false
	forSignData, forSignOk := secret.Data["sign"].(string)
	if forSignOk {
		forSignData = strings.ToLower(strings.TrimSpace(forSignData))
		forSign = !negativeForSign[forSignData]
	}

	return privateKey, forSign, nil
}
