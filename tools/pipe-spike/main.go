//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func main() {
	if len(os.Args) != 2 {
		fail("usage: pipe-spike.exe server")
	}

	var err error
	switch os.Args[1] {
	case "server":
		err = runServer()
	case "client":
		err = runClient()
	default:
		err = fmt.Errorf("unknown mode %q", os.Args[1])
	}

	if err != nil {
		fail("%v", err)
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "pipe spike: "+format+"\n", args...)
	os.Exit(1)
}

func currentUserSID() (string, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_QUERY,
		&token,
	); err != nil {
		return "", fmt.Errorf("open current process token: %w", err)
	}
	defer token.Close()

	user, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("read current user: %w", err)
	}

	return user.User.Sid.String(), nil
}

func pipeName() (string, error) {
	sid, err := currentUserSID()
	if err != nil {
		return "", err
	}
	return `\\.\pipe\wardkey-spike-` + sid, nil
}

func runServer() error {
	name, err := pipeName()
	if err != nil {
		return err
	}

	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return fmt.Errorf("encode pipe name: %w", err)
	}

	sid, err := currentUserSID()
	if err != nil {
		return err
	}

	// Only this Windows user is granted access to the pipe.
	securityDescriptor, err := windows.SecurityDescriptorFromString(
		"D:P(A;;GA;;;" + sid + ")",
	)
	if err != nil {
		return fmt.Errorf("create pipe security descriptor: %w", err)
	}

	securityAttributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: securityDescriptor,
	}

	const pipeMode = windows.PIPE_TYPE_BYTE |
		windows.PIPE_READMODE_BYTE |
		windows.PIPE_WAIT |
		windows.PIPE_REJECT_REMOTE_CLIENTS

	pipe, err := windows.CreateNamedPipe(
		namePtr,
		windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
		pipeMode,
		1,
		4096,
		4096,
		0,
		&securityAttributes,
	)
	if err != nil {
		return fmt.Errorf("create first pipe instance: %w", err)
	}
	defer windows.CloseHandle(pipe)

	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("find this program: %w", err)
	}

	client := exec.Command(executable, "client")
	client.Stdout = os.Stdout
	client.Stderr = os.Stderr
	if err := client.Start(); err != nil {
		return fmt.Errorf("start test client: %w", err)
	}

	err = windows.ConnectNamedPipe(pipe, nil)
	if err != nil && !errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
		_ = client.Wait()
		return fmt.Errorf("connect client: %w", err)
	}

	var clientPID uint32
	if err := windows.GetNamedPipeClientProcessId(pipe, &clientPID); err != nil {
		_ = client.Wait()
		return fmt.Errorf("get connected client PID: %w", err)
	}

	if clientPID != uint32(client.Process.Pid) {
		_ = client.Wait()
		return fmt.Errorf(
			"client PID mismatch: pipe reported %d, started process is %d",
			clientPID,
			client.Process.Pid,
		)
	}

	if err := client.Wait(); err != nil {
		return fmt.Errorf("test client failed: %w", err)
	}

	fmt.Printf("PASS: custom user ACL and first pipe instance created\n")
	fmt.Printf("PASS: remote clients rejected by pipe mode\n")
	fmt.Printf("PASS: Windows-reported client PID %d matches the started client\n", clientPID)
	return nil
}

func runClient() error {
	name, err := pipeName()
	if err != nil {
		return err
	}

	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return fmt.Errorf("encode pipe name: %w", err)
	}

	pipe, err := windows.CreateFile(
		namePtr,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return fmt.Errorf("open server pipe: %w", err)
	}
	defer windows.CloseHandle(pipe)

	var serverPID uint32
	if err := windows.GetNamedPipeServerProcessId(pipe, &serverPID); err != nil {
		return fmt.Errorf("get server PID: %w", err)
	}
	fmt.Printf("Client connected; Windows reports server PID %d\n", serverPID)

	// Keep the connection open while the server reads the client PID.
	time.Sleep(2 * time.Second)
	return nil
}
