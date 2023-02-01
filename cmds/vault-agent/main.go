package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	vaultagent "github.com/vanhtuan0409/vault-agent"
)

var (
	socketPath string
	vaultAddr  string
	vaultToken string
	keyPath    string
)

func main() {
	flag.StringVar(&socketPath, "sock", "", "Socket path")
	flag.StringVar(&vaultAddr, "vault", "", "Vault address")
	flag.StringVar(&vaultToken, "token", "", "Vault token")
	flag.StringVar(&keyPath, "path", "kv/ssh_keys", "Vault secret key path")
	flag.Parse()
	setDefaultConfig()
	validateConfig()

	ctx := context.Background()
	c, err := vaultagent.GetVaultClient(ctx, vaultAddr, vaultToken)
	if err != nil {
		log.Fatalln("Failed to create vault client:", err)
	}

	a, err := vaultagent.NewAgent(c, keyPath)
	if err != nil {
		log.Fatalln("Failed to create vault agent:", err)
	}

	if err := runAgent(ctx, a); err != nil {
		log.Fatalln("Failed to run agent:", err)
	}
}

func setDefaultConfig() {
	if socketPath == "" {
		cfgDir, err := os.UserConfigDir()
		if err == nil {
			socketPath = filepath.Join(cfgDir, "vault-agent", "agent.sock")
		}
	}
	if vaultAddr == "" {
		vaultAddr = os.Getenv("VAULT_ADDR")
	}
	if vaultToken == "" {
		homeDir, _ := os.UserHomeDir()
		tokenFile := filepath.Join(homeDir, ".vault-token")
		tokenData, err := ioutil.ReadFile(tokenFile)
		if err == nil {
			vaultToken = strings.TrimSpace(string(tokenData))
		}
	}
}

func validateConfig() {
	if socketPath == "" {
		log.Fatalln("Invalid socket path")
	}
	if vaultAddr == "" {
		log.Fatalln("Invalid vault address")
	}
	if vaultToken == "" {
		log.Fatalln("Invalid vault token")
	}
}

func runAgent(ctx context.Context, a *vaultagent.Agent) error {
	os.Remove(socketPath)
	if err := os.MkdirAll(filepath.Dir(socketPath), 0777); err != nil {
		return fmt.Errorf("failed to create UNIX socket: %v", err)
	}

	l, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on UNIX socket: %v", err)
	}
	defer l.Close()

	log.Println("Listening on socket", socketPath)
	for {
		c, err := l.Accept()
		if err != nil {
			type temporary interface {
				Temporary() bool
			}
			if err, ok := err.(temporary); ok && err.Temporary() {
				log.Println("Temporary accept error:", err)
				time.Sleep(time.Second)
				continue
			}
			log.Fatalln("Failed to accept connection:", err)
		}
		go a.ServeConn(c)
	}

	return nil
}
