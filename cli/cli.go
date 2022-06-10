package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/tarosky/gutenberg-phptrace/trace"
	"github.com/urfave/cli/v2"
	"go.uber.org/zap"
)

func createLogger() *zap.Logger {
	log, err := zap.NewDevelopment(zap.WithCaller(false))
	if err != nil {
		panic("failed to initialize logger")
	}

	return log
}

func main() {
	app := cli.NewApp()
	app.Name = "phptrace"
	app.Usage = "trace php processes"

	app.Flags = []cli.Flag{
		&cli.PathFlag{
			Name:     "syscall-header",
			Aliases:  []string{"s"},
			Usage:    "Path to syscall header file <asm/unistd_64.h>.",
			Required: true,
		},
		&cli.IntFlag{
			Name:    "debug",
			Aliases: []string{"d"},
			Value:   0,
			Usage:   "Enable debug output: bcc.DEBUG_SOURCE: 8, bcc.DEBUG_PREPROCESSOR: 4.",
		},
		&cli.BoolFlag{
			Name:    "quit",
			Aliases: []string{"q"},
			Value:   false,
			Usage:   "Quit without tracing. This is mainly for debugging.",
		},
	}

	app.Action = func(c *cli.Context) error {
		log := createLogger()
		defer log.Sync()

		cfg := &trace.Config{
			SyscallHeader: c.Path("syscall-header"),
			BpfDebug:      c.Uint("debug"),
			Quit:          c.Bool("quit"),
			Log:           log,
		}

		eventCh := make(chan *trace.Event)
		ctx, cancel := context.WithCancel(context.Background())

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
		go func() {
			<-sig
			signal.Stop(sig)
			cancel()
		}()

		go func() {
			for {
				if _, ok := <-eventCh; !ok {
					return
				}
			}
		}()

		trace.Run(ctx, cfg, eventCh)

		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Panic("failed to run app", zap.Error(err))
	}
}
