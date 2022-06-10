package trace

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unsafe"

	"github.com/iovisor/gobpf/bcc"
	"github.com/rakyll/statik/fs"

	// Load static assets
	_ "github.com/tarosky/gutenberg-phptrace/statik"
	"go.uber.org/zap"
)

//go:generate statik -src=c

var (
	log             *zap.Logger
	syscallHeaderRe = regexp.MustCompile(`#define\s+__NR_(\w+)\s+(\d+)`)
)

const (
	cTaskCommLen = 16
	cPathMax     = 4096
)

// Config configures parameters to filter what to be notified.
type Config struct {
	SyscallHeader string
	BpfDebug      uint
	Quit          bool
	Log           *zap.Logger
}

func unpackSource(name string) string {
	sfs, err := fs.New()
	if err != nil {
		log.Panic("embedded FS not found", zap.Error(err))
	}

	r, err := sfs.Open("/" + name)
	if err != nil {
		log.Panic("embedded file not found", zap.Error(err))
	}
	defer r.Close()

	contents, err := ioutil.ReadAll(r)
	if err != nil {
		log.Panic("failed to read embedded file", zap.Error(err))
	}

	return string(contents)
}

var source string = unpackSource("trace.c")

type eventCStruct struct {
	Syscall   uint32
	Debug     uint32
	Pid       uint64
	StartTime uint64
	EndTime   uint64
	Comm      [cTaskCommLen]byte
	Path      [cPathMax]byte
}

func configSyscallTrace(m *bcc.Module) error {
	names := []string{
		"chmod",
		"chown",
		"fchmod",
		"fchmodat",
		"fchown",
		"fchownat",
		"fdatasync",
		"fsync",
		"lchown",
		"link",
		"linkat",
		"rename",
		"renameat",
		"renameat2",
		"symlink",
		"symlinkat",
		"sync",
		"syncfs",
		"truncate",
		"unlink",
		"unlinkat",
	}

	for _, n := range names {
		kprobe, err := m.LoadKprobe("enter___syscall___" + n)
		if err != nil {
			return err
		}

		if err := m.AttachKprobe(bcc.GetSyscallFnName(n), kprobe, -1); err != nil {
			return err
		}

		kretprobe, err := m.LoadKprobe("return___syscall___" + n)
		if err != nil {
			return err
		}

		if err := m.AttachKretprobe(bcc.GetSyscallFnName(n), kretprobe, -1); err != nil {
			return err
		}
	}

	return nil
}

func configTrace(m *bcc.Module, receiverChan chan []byte) *bcc.PerfMap {
	if err := configSyscallTrace(m); err != nil {
		log.Panic("failed to config syscall trace", zap.Error(err))
	}

	table := bcc.NewTable(m.TableId("events"), m)

	perfMap, err := bcc.InitPerfMap(table, receiverChan, nil)
	if err != nil {
		log.Panic("Failed to init perf map", zap.Error(err))
	}

	return perfMap
}

func generateSource(config *Config) string {
	r := strings.NewReplacer()

	return r.Replace(source)
}

func parseSyscallHeader(headerFile string) map[uint32]string {
	hMap := make(map[uint32]string, 512)
	f, err := os.Open(headerFile)
	if err != nil {
		log.Panic("failed to open header file", zap.Error(err))
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		s := scanner.Text()
		if m := syscallHeaderRe.FindStringSubmatch(s); m != nil {
			name := m[1]
			idx, err := strconv.Atoi(m[2])
			if err != nil {
				log.Panic("failed to scan header line", zap.Error(err), zap.String("line", s))
			}
			hMap[uint32(idx)] = name
		}
	}
	return hMap
}

// Event tells the details of notification.
type Event struct {
	Syscall string
	Pid     uint32
	Comm    string
}

// Run starts compiling eBPF code and then notifying of file updates.
func Run(ctx context.Context, config *Config, eventCh chan<- *Event) {
	log = config.Log
	m := bcc.NewModule(generateSource(config), []string{}, config.BpfDebug)
	defer m.Close()

	syscallMap := parseSyscallHeader(config.SyscallHeader)

	if config.Quit {
		close(eventCh)
		return
	}

	channel := make(chan []byte, 8192)
	perfMap := configTrace(m, channel)

	go func() {
		log.Info("tracing started")
		for {
			select {
			case <-ctx.Done():
				close(eventCh)
				return
			case data := <-channel:
				var cEvent eventCStruct
				if err := binary.Read(bytes.NewBuffer(data), bcc.GetHostByteOrder(), &cEvent); err != nil {
					fmt.Printf("failed to decode received data: %s\n", err)
					continue
				}

				syscall, ok := syscallMap[cEvent.Syscall]
				if !ok {
					syscall = strconv.Itoa(int(cEvent.Syscall))
				}
				pid := uint32(cEvent.Pid)
				startTime := cEvent.StartTime
				endTime := cEvent.EndTime
				debug := cEvent.Debug
				comm := cPointerToString(unsafe.Pointer(&cEvent.Comm))

				log.Debug(
					"event",
					zap.String("syscall", syscall),
					zap.Uint32("pid", pid),
					zap.Uint64("starttime", startTime),
					zap.Uint64("endtime", endTime),
					zap.String("comm", comm),
					zap.Uint32("debug", debug),
				)

				eventCh <- &Event{
					Syscall: syscall,
					Comm:    comm,
					Pid:     pid,
				}
			}
		}
	}()

	perfMap.Start()
	<-ctx.Done()
	perfMap.Stop()
}
