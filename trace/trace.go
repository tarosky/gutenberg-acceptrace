//go:build linux
// +build linux

package trace

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"os"
	"reflect"
	"regexp"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" -type event bpf ../c/trace.c -- -I../c/headers -I/usr/include/x86_64-linux-gnu

var (
	syscallHeaderRe = regexp.MustCompile(`#define\s+__NR_(\w+)\s+(\d+)`)
)

// Config configures parameters to filter what to be notified.
type Config struct {
	SyscallHeader string
	Quit          bool
	Log           *zap.Logger
}

// Event tells the details of notification.
type Event struct {
	Syscall   string
	Pid       uint32
	FD        int32
	Ret       int32
	StartTime uint64
	EndTime   uint64
	Comm      string
	Path      string
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

func Run(ctx context.Context, config *Config, eventCh chan<- *Event) {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	syscallMap := parseSyscallHeader(config.SyscallHeader)

	resources := []io.Closer{}
	defer func() {
		for _, r := range resources {
			if err := r.Close(); err != nil {
				log.Fatal(err)
			}
		}
	}()

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	resources = append(resources, &objs)

	// Attach all fentry/fexit functions using reflection.
	fentV := reflect.ValueOf(objs.bpfPrograms)
	for i := 0; i < fentV.NumField(); i++ {
		p := fentV.Field(i).Interface().(*ebpf.Program)

		t, err := link.AttachTracing(link.TracingOptions{Program: p})
		if err != nil {
			log.Fatalf("opening fentry/fexit: %s", err)
		}
		resources = append(resources, t)
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}

	go func() {
		<-ctx.Done()

		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
	}()

	log.Println("Waiting for events..")

	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				close(eventCh)
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		// Parse the ringbuf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}

		syscall, ok := syscallMap[event.Syscall]
		if !ok {
			syscall = strconv.Itoa(int(event.Syscall))
		}

		eventCh <- &Event{
			Syscall:   syscall,
			Pid:       event.Pid,
			FD:        event.Fd,
			Ret:       event.Ret,
			StartTime: event.StartTime,
			EndTime:   event.EndTime,
			Comm:      unix.ByteSliceToString(event.Comm[:]),
			Path:      unix.ByteSliceToString(event.Path[:]),
		}
	}
}
