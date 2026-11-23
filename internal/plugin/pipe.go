package plugin

import (
	"io"
	"os"
	"os/exec"
	"os/signal"
)

// Pipe runs the plugin as a child of rpt, with stdin and stderr given to
// it and its stdout handed to read. It returns the plugin's exit code once
// read has returned and the plugin has ended; a plugin killed by a signal
// gives 128 and the signal's number, as a shell does.
//
// The plugin stays in rpt's process group, the terminal's foreground one,
// so Ctrl-C at the terminal reaches it directly and it can still read
// /dev/tty. rpt ignores that interrupt while it waits, and hands on a
// termination signal sent to rpt alone.
func Pipe(p Plugin, args, env []string, stdin io.Reader, stderr io.Writer, read func(io.Reader)) (int, error) {
	cmd := exec.Command(p.Path, args...)
	cmd.Env, cmd.Stdin, cmd.Stderr = env, stdin, stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return 0, err
	}
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, relayed...)
	defer signal.Stop(sigs)
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case s := <-sigs:
				if s != os.Interrupt {
					cmd.Process.Signal(s)
				}
			case <-done:
				return
			}
		}
	}()
	read(out)
	io.Copy(io.Discard, out) // a reader that stopped early mustn't block the plugin
	err = cmd.Wait()
	close(done)
	return exitCode(err)
}
