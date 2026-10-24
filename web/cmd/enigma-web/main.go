// enigma-web serves the embedded interface on IPv4 loopback only.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"criptografia-enigma/web/internal/server"
)

func main() {
	port := flag.Int("port", 0, "loopback port (0 selects a free port)")
	noBrowser := flag.Bool("no-browser", false, "do not open the browser; print the URL only")
	flag.Parse()
	if *port < 0 || *port > 65535 || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: enigma-web [--port <0-65535>] [--no-browser]")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, *port, *noBrowser); err != nil {
		fmt.Fprintln(os.Stderr, "enigma-web:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, port int, noBrowser bool) error {
	listener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	defer listener.Close()
	var handler *server.Server
	// Test aid: avoid reading or writing the real user's engine configuration.
	if config := os.Getenv("ENIGMA_WEB_CONFIG"); config != "" {
		handler, err = server.NewWithConfig(listener.Addr().(*net.TCPAddr).Port, config)
	} else {
		handler, err = server.New(listener.Addr().(*net.TCPAddr).Port)
	}
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(listener) }()
	fmt.Println(handler.URL())
	if !noBrowser {
		go func() {
			if err := openBrowser(handler.URL()); err != nil {
				fmt.Fprintf(os.Stderr, "Could not open the browser; open this URL manually: %s\n", handler.URL())
			}
		}()
	}
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		fmt.Fprintln(os.Stderr, "Stopping enigma-web; waiting for any running attack to checkpoint and exit.")
		attackCtx, attackCancel := context.WithTimeout(context.Background(), 30*time.Second)
		attackErr := handler.Shutdown(attackCtx)
		attackCancel()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			_ = srv.Close()
			return err
		}
		if err := <-done; !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return attackErr
	}
}

func openBrowser(url string) error {
	switch runtime.GOOS {
	case "linux":
		return exec.Command("xdg-open", url).Run()
	case "darwin":
		return exec.Command("open", url).Run()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Run()
	default:
		return fmt.Errorf("unsupported browser launcher on %s", runtime.GOOS)
	}
}
