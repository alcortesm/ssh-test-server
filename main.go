// see https://blog.gopheracademy.com/go-and-ssh/
// and https://blog.gopheracademy.com/advent-2015/ssh-server-in-go/
//
// this is exactly what I want to do: https://github.com/gogits/gogs/blob/master/modules/ssh/ssh.go
// this is also very relevant: https://dev.justinjudd.org/justin/easyssh/src/master/session.go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type AllowedCmds map[string]*exec.Cmd

func main() {
	//Github()
	myServer()
}

type ServerInfo struct {
	Addr         string // "host:port"
	ClientConfig *ssh.ClientConfig
}

func myServer() {
	allowedCmds := AllowedCmds{
		"ls":   exec.Command("ls"),
		"echo": exec.Command("echo"),
	}

	serverInfo, err := createServer(allowedCmds)
	if err != nil {
		log.Fatal("creating SSH server: ", err)
	}

	client, err := ssh.Dial("tcp", serverInfo.Addr, serverInfo.ClientConfig)
	if err != nil {
		log.Fatal("dialing server: ", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			log.Fatal("closing client: ", err)
		}
	}()

	doSomething(client)
}

func Github() {
	auth, _ := SSHAgentAuthMethod()

	clientConfig := &ssh.ClientConfig{
		User: "git",
		Auth: auth,
	}

	client, err := ssh.Dial("tcp", "github.com:22", clientConfig)
	if err != nil {
		log.Fatal("dialing server: ", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			log.Fatal("closing client: ", err)
		}
	}()

	doSomething(client)
}

// get ssh auth credentials from a running ssh agent
func SSHAgentAuthMethod() ([]ssh.AuthMethod, io.Closer) {
	sockAddr := os.Getenv("SSH_AUTH_SOCK")
	if sockAddr == "" {
		log.Fatal(
			"cannot find ssh agent: environment variable SSH_AUTH_SOCK is empty")
	}

	sock, err := net.Dial("unix", sockAddr)
	if err != nil {
		log.Fatal("dialing ssh agent", err)
	}

	agent := agent.NewClient(sock)

	signers, err := agent.Signers()
	if err != nil {
		log.Fatal("getting signers from agent:", err)
	}

	return []ssh.AuthMethod{ssh.PublicKeys(signers...)}, sock
}

const (
	proto = "tcp"
	host  = "localhost"
	port  = "2222"
)

func createServer(cmds AllowedCmds) (*ServerInfo, error) {
	signer, private, err := makeRSAKeyPair()
	if err != nil {
		return nil, fmt.Errorf("Failed to create a new host key pair: ", err)
	}

	config, err := configureServer(private)
	if err != nil {
		return nil, fmt.Errorf("cannot configure SSH server: ", err)
	}

	addr := host + ":" + port
	clientConfig := &ssh.ClientConfig{
		User: "",
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
	}

	go listen(addr, config, cmds)

	return &ServerInfo{
		Addr:         addr,
		ClientConfig: clientConfig,
	}, nil
}

func configureServer(pemPrivateHostKey []byte) (*ssh.ServerConfig, error) {
	config := &ssh.ServerConfig{
		NoClientAuth: true,
	}

	private, err := ssh.ParsePrivateKey(pemPrivateHostKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse private host key: ", err)
	}
	config.AddHostKey(private)

	return config, nil
}

func listen(addr string, config *ssh.ServerConfig, cmds AllowedCmds) error {
	//log.Println("listening")
	listener, err := net.Listen(proto, addr)
	if err != nil {
		return fmt.Errorf("failed to listen for connection")
	}

	//log.Println("accept")
	nConn, err := listener.Accept()
	if err != nil {
		log.Println("failed to accept incoming connection")
	}

	// Before use, a handshake must be performed on the incoming
	// net.Conn.
	_, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		log.Fatal("failed to handshake: ", err)
	}

	// The incoming Request channel must be serviced, but we don't allow
	// for requests outside the normal stream of data.
	go ssh.DiscardRequests(reqs)

	// The incoming NewChannel channel must be serviced,
	newChannel := <-chans
	if newChannel.ChannelType() != "session" {
		newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
		return nil
	}
	//fmt.Println("newChannel.ChannelType()", newChannel.ChannelType())

	channel, requests, err := newChannel.Accept()
	if err != nil {
		log.Fatalf("Could not accept channel: %v", err)
	}

	// Sessions have out-of-band requests such as "shell",
	// "pty-req" and "env".  Here we handle only the
	// "shell" request.
	req := <-requests
	if req.Type != "exec" {
		req.Reply(false, nil)
	}
	go ssh.DiscardRequests(requests)

	var payload cmdPath
	if err = ssh.Unmarshal(req.Payload, &payload); err != nil {
		log.Fatal("unmarshal error:", err)
	}
	//fmt.Println("executing", payload.Path)

	cmd, ok := cmds[payload.Path]
	if !ok {
		req.Reply(false, nil)
		return nil
	}

	//log.Printf("exec starting: %s", cmd.Path)

	output, err := cmd.Output()
	channel.Write(output)
	return nil
}

type cmdPath struct {
	Path string
}

type exitStatusReq struct {
	ExitStatus uint32
}

// MakeRSAKeyPair makes a pair of public and private keys for SSH
// access, and returns a signer for the key and the PEM encoded privte
// key.
func makeRSAKeyPair() (signer ssh.Signer, private []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, nil, err
	}

	privateKeyPEM := &pem.Block{
		Type: "RSA PRIVATE KEY",
		// no optional headers
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	private = pem.EncodeToMemory(privateKeyPEM)

	signer, err = ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, nil, err
	}

	return signer, private, nil
}

func doSomething(c *ssh.Client) (err error) {
	session, i, o, e, done, err := openSSHSession(c, "ls")
	if err != nil {
		return fmt.Errorf("cannot open SSH session: %s", err)
	}
	defer func() {
		errClose := session.Close()
		if err == nil {
			err = errClose
		}
	}()

	go func() {
		if _, err := io.Copy(i, os.Stdin); err != nil {
			log.Printf("remote stdout: %s", err)
		}
	}()

	go func() {
		if _, err := io.Copy(os.Stdout, o); err != nil {
			log.Printf("remote stdout: %s", err)
		}
	}()

	go func() {
		if _, err := io.Copy(os.Stderr, e); err != nil {
			log.Printf("remote stderr: %s", err)
		}
	}()

	msg := <-done
	log.Print("done: ", msg)

	return nil
}

func openSSHSession(c *ssh.Client, cmd string) (
	*ssh.Session, io.WriteCloser, io.Reader, io.Reader, <-chan error, error) {

	session, err := c.NewSession()
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("cannot open SSH session: %s", err)
	}

	i, err := session.StdinPipe()
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("cannot pipe remote stdin: %s", err)
	}

	o, err := session.StdoutPipe()
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("cannot pipe remote stdout: %s", err)
	}

	e, err := session.StderrPipe()
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("cannot pipe remote stderr: %s", err)
	}

	done := make(chan error)
	go func() {
		done <- session.Run(cmd)
	}()

	return session, i, o, e, done, nil
}
