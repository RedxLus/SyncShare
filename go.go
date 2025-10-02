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

func sendFile(addr, filePath, code, relName string) error {
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

	fmt.Fprintf(conn, "%s\n", relName)

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

func getAllFiles(root string) ([]string, error) {
	var files []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func sendPath(addr, path, code string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("error accessing path: %w", err)
	}

	if !info.IsDir() {
		relName := filepath.Base(path)
		fmt.Println("Sending file:", relName)
		return sendFile(addr, path, code, relName)
	}

	files, err := getAllFiles(path)
	if err != nil {
		return fmt.Errorf("error listing folder: %w", err)
	}

	for _, f := range files {
		relName, _ := filepath.Rel(path, f)
		fmt.Println("Sending file:", relName)
		if err := sendFile(addr, f, code, relName); err != nil {
			return err
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
	os.MkdirAll(filepath.Dir(outPath), os.ModePerm)

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
		addr := sendCmd.String("addr", "", "Ip address of receiver (e.g., 192.168.1.32:9000)")
		path := sendCmd.String("path", "", "Path to file or folder to send")
		code := sendCmd.String("code", "", "Shared secret code (e.g., 123ABC)")
		sendCmd.Parse(os.Args[2:])

		if *addr == "" || *path == "" || *code == "" {
			fmt.Println("send: missing parameters.")
			sendCmd.Usage()
			os.Exit(1)
		}

		fmt.Println("Sending path:", *path, "to", *addr)
		if err := sendPath(*addr, *path, *code); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}
		fmt.Println("Send completed")

	case "recv":
		recvCmd := flag.NewFlagSet("recv", flag.ExitOnError)
		listen := recvCmd.String("listen", ":9000", "Local address to listen (e.g., :9000)")
		out := recvCmd.String("out", ".", "Folder to save the received file(s)")
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
	fmt.Println("  go send -addr <host:port> -path <file|folder> -code <code>")
	fmt.Println("  go recv -listen <:port> -out <folder> -code <code>")
	fmt.Println()
	fmt.Println("Examples (Windows):")
	fmt.Println(`  .\go.exe send -addr "192.168.3.10:9000" -path "C:\Users\luisd\OneDrive\Desktop\github\SyncShare" -code "123ABC"`)
	fmt.Println(`  .\go.exe recv -listen ":9000" -out "C:\Users\OtherName\Downloads" -code "123ABC"`)
	os.Exit(1)
}
