package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
)

func deriveKey(code string) []byte {
	h := sha256.Sum256([]byte(code))
	return h[:]
}

func sendFile(addr, filePath, code string) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("error connecting to %s: %w", addr, err)
	}
	defer conn.Close()

	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	defer f.Close()

	name := filepath.Base(filePath)
	fmt.Fprintf(conn, "%s\n", name)

	key := deriveKey(code)
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("error creating cipher: %w", err)
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return fmt.Errorf("error generating IV: %w", err)
	}
	if _, err := conn.Write(iv); err != nil {
		return fmt.Errorf("error sending IV: %w", err)
	}

	stream := cipher.NewCTR(block, iv)

	buf := make([]byte, 32*1024)
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			out := make([]byte, n)
			stream.XORKeyStream(out, buf[:n])
			if _, err := conn.Write(out); err != nil {
				return fmt.Errorf("error writing to connection: %w", err)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return fmt.Errorf("error reading file: %w", rerr)
		}
	}

	return nil
}

func recvFile(listenAddr, outDir, code string) error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("error listening on %s: %w", listenAddr, err)
	}
	defer ln.Close()
	fmt.Println("Waiting for connection on", ln.Addr())

	conn, err := ln.Accept()
	if err != nil {
		return fmt.Errorf("error accepting connection: %w", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	name, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("error reading file name: %w", err)
	}
	name = name[:len(name)-1]

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(reader, iv); err != nil {
		return fmt.Errorf("error reading IV: %w", err)
	}

	key := deriveKey(code)
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("error creating cipher: %w", err)
	}
	stream := cipher.NewCTR(block, iv)

	outPath := filepath.Join(outDir, name)
	out, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("error creating output file: %w", err)
	}
	defer out.Close()

	buf := make([]byte, 32*1024)
	for {
		n, rerr := reader.Read(buf)
		if n > 0 {
			plain := make([]byte, n)
			stream.XORKeyStream(plain, buf[:n])
			if _, err := out.Write(plain); err != nil {
				return fmt.Errorf("error writing file: %w", err)
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return fmt.Errorf("error reading stream: %w", rerr)
		}
	}

	fmt.Println("File received at", outPath)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		usageAndExit()
	}

	switch os.Args[1] {
	case "send":
		sendCmd := flag.NewFlagSet("send", flag.ExitOnError)
		addr := sendCmd.String("addr", "", "Ip address of reciver (e.g., 192.168.1.32:9000)")
		file := sendCmd.String("file", "", "Path to the file to send")
		code := sendCmd.String("code", "", "Shared secret code (e.g., 123ABC)")
		sendCmd.Parse(os.Args[2:])

		if *addr == "" || *file == "" || *code == "" {
			fmt.Println("send: missing parameters.")
			sendCmd.Usage()
			os.Exit(1)
		}

		fmt.Println("Sending", *file, "to", *addr)
		if err := sendFile(*addr, *file, *code); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}
		fmt.Println("Send completed")

	case "recv":
		recvCmd := flag.NewFlagSet("recv", flag.ExitOnError)
		listen := recvCmd.String("listen", ":9000", "Local address to listen (e.g., :9000)")
		out := recvCmd.String("out", ".", "Folder to save the received file")
		code := recvCmd.String("code", "", "Shared secret code")
		recvCmd.Parse(os.Args[2:])

		if *code == "" {
			fmt.Println("recv: missing parameters.")
			recvCmd.Usage()
			os.Exit(1)
		}

		fmt.Println("Waiting to receive on", *listen, "saving to", *out)
		if err := recvFile(*listen, *out, *code); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}

	default:
		usageAndExit()
	}
}

func usageAndExit() {
	fmt.Println("Usage:")
	fmt.Println("  go send -addr <host:port> -file <path> -code <code>")
	fmt.Println("  go recv -listen <:port> -out <folder> -code <code>")
	fmt.Println()
	fmt.Println("Examples (Windows PowerShell):")
	fmt.Println(`  .\go.exe send -addr "IP_OF_RECIVER:9000" -file "C:\Users\Name\README.md" -code "123ABC"`)
	fmt.Println(`  .\go.exe recv -listen ":9000" -out "C:\Users\OtherName\Downloads" -code "123ABC"`)
	os.Exit(1)
}
