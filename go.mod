module github.com/tarosky/gutenberg-phptrace

go 1.18

require (
	github.com/cilium/ebpf v0.9.0
	github.com/urfave/cli/v2 v2.2.0
	go.uber.org/zap v1.15.0
	golang.org/x/sys v0.0.0-20210906170528-6f6e22806c34
)

require (
	github.com/cpuguy83/go-md2man/v2 v2.0.0-20190314233015-f79a8a8ca69d // indirect
	github.com/russross/blackfriday/v2 v2.0.1 // indirect
	github.com/shurcooL/sanitized_anchor_name v1.0.0 // indirect
	go.uber.org/atomic v1.6.0 // indirect
	go.uber.org/multierr v1.5.0 // indirect
)

replace github.com/iovisor/gobpf => github.com/harai/gobpf v0.2.1
