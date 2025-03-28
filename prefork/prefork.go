package prefork

import (
	"errors"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"

	"github.com/adhocore/fasthttp"
	"github.com/adhocore/fasthttp/reuseport"
)

const (
	preforkChildEnvVariable = "FASTHTTP_PREFORK_CHILD"
	defaultNetwork          = "tcp4"
)

var (
	defaultLogger = Logger(log.New(os.Stderr, "", log.LstdFlags))
	// ErrOverRecovery is returned when the times of starting over child prefork processes exceed
	// the threshold.
	ErrOverRecovery = errors.New("exceeding the value of RecoverThreshold")

	// ErrOnlyReuseportOnWindows is returned when Reuseport is false.
	ErrOnlyReuseportOnWindows = errors.New("windows only supports Reuseport = true")
)

// Logger is used for logging formatted messages.
type Logger interface {
	// Printf must have the same semantics as log.Printf.
	Printf(format string, args ...any)
}

// Prefork implements fasthttp server prefork.
//
// Preforks master process (with all cores) between several child processes
// increases performance significantly, because Go doesn't have to share
// and manage memory between cores.
//
// WARNING: using prefork prevents the use of any global state!
// Things like in-memory caches won't work.
type Prefork struct {

	// By default standard logger from log package is used.
	Logger Logger

	ln net.Listener

	ServeFunc func(ln net.Listener) error

	// The network must be "tcp", "tcp4" or "tcp6".
	//
	// By default is "tcp4"
	Network string

	files []*os.File

	// Child prefork processes may exit with failure and will be started over until the times reach
	// the value of RecoverThreshold, then it will return and terminate the server.
	RecoverThreshold int

	// Flag to use a listener with reuseport, if not a file Listener will be used
	// See: https://www.nginx.com/blog/socket-sharding-nginx-release-1-9-1/
	//
	// It's disabled by default
	Reuseport bool
}

// IsChild checks if the current thread/process is a child.
func IsChild() bool {
	return os.Getenv(preforkChildEnvVariable) == "1"
}

// New wraps the fasthttp server to run with preforked processes.
func New(s *fasthttp.Server) *Prefork {
	return &Prefork{
		Network:          defaultNetwork,
		RecoverThreshold: runtime.GOMAXPROCS(0) / 2,
		Logger:           s.Logger,
		ServeFunc:        s.Serve,
	}
}

// Serve serves the app with preforked processes.
func Serve(app *fasthttp.App, addr string) error {
	return New(app.ServerHandler()).ListenAndServe(addr)
}

func (p *Prefork) logger() Logger {
	if p.Logger != nil {
		return p.Logger
	}
	return defaultLogger
}

func (p *Prefork) listen(addr string) (net.Listener, error) {
	runtime.GOMAXPROCS(1)

	if p.Network == "" {
		p.Network = defaultNetwork
	}

	if p.Reuseport {
		return reuseport.Listen(p.Network, addr)
	}

	return net.FileListener(os.NewFile(3, ""))
}

func (p *Prefork) setTCPListenerFiles(addr string) error {
	if p.Network == "" {
		p.Network = defaultNetwork
	}

	tcpAddr, err := net.ResolveTCPAddr(p.Network, addr)
	if err != nil {
		return err
	}

	tcplistener, err := net.ListenTCP(p.Network, tcpAddr)
	if err != nil {
		return err
	}

	p.ln = tcplistener

	fl, err := tcplistener.File()
	if err != nil {
		return err
	}

	p.files = []*os.File{fl}

	return nil
}

func (p *Prefork) doCommand() (*exec.Cmd, error) {
	/* #nosec G204 */
	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), preforkChildEnvVariable+"=1")
	cmd.ExtraFiles = p.files
	err := cmd.Start()
	return cmd, err
}

func (p *Prefork) prefork(addr string) (err error) {
	if !p.Reuseport {
		if runtime.GOOS == "windows" {
			return ErrOnlyReuseportOnWindows
		}

		if err = p.setTCPListenerFiles(addr); err != nil {
			return
		}

		// defer for closing the net.Listener opened by setTCPListenerFiles.
		defer func() {
			e := p.ln.Close()
			if err == nil {
				err = e
			}
		}()
	}

	type procSig struct {
		err error
		pid int
	}

	goMaxProcs := runtime.GOMAXPROCS(0)
	sigCh := make(chan procSig, goMaxProcs)
	childProcs := make(map[int]*exec.Cmd)

	defer func() {
		for _, proc := range childProcs {
			_ = proc.Process.Kill()
		}
	}()

	for i := 0; i < goMaxProcs; i++ {
		var cmd *exec.Cmd
		if cmd, err = p.doCommand(); err != nil {
			p.logger().Printf("failed to start a child prefork process, error: %v\n", err)
			return
		}

		childProcs[cmd.Process.Pid] = cmd
		go func() {
			sigCh <- procSig{pid: cmd.Process.Pid, err: cmd.Wait()}
		}()
	}

	var exitedProcs int
	for sig := range sigCh {
		delete(childProcs, sig.pid)

		p.logger().Printf("one of the child prefork processes exited with "+
			"error: %v", sig.err)

		exitedProcs++
		if exitedProcs > p.RecoverThreshold {
			p.logger().Printf("child prefork processes exit too many times, "+
				"which exceeds the value of RecoverThreshold(%d), "+
				"exiting the master process.\n", exitedProcs)
			err = ErrOverRecovery
			break
		}

		var cmd *exec.Cmd
		if cmd, err = p.doCommand(); err != nil {
			break
		}
		childProcs[cmd.Process.Pid] = cmd
		go func() {
			sigCh <- procSig{pid: cmd.Process.Pid, err: cmd.Wait()}
		}()
	}

	return
}

// ListenAndServe serves HTTP requests from the given TCP addr.
func (p *Prefork) ListenAndServe(addr string) error {
	if IsChild() {
		ln, err := p.listen(addr)
		if err != nil {
			return err
		}

		p.ln = ln

		return p.ServeFunc(ln)
	}

	return p.prefork(addr)
}
