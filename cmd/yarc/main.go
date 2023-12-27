package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	golog "log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/didi/yarc/internal/buildinfo"
	"github.com/didi/yarc/internal/log"
	"github.com/didi/yarc/internal/recorder"
	"github.com/didi/yarc/pkg/elf"
	"github.com/didi/yarc/pkg/pidfile"

	"github.com/spf13/viper"
)

// Flags flags
type Flags struct {
	pid1       int
	pid2       int
	configFile string
	bufSize    int
	rateLimit  float64
	logSize    int
}

var (
	flags     Flags
	logConfig log.Config
)

func parseFlags() {
	flag.IntVar(&flags.pid1, "p", -1, "pid1")
	flag.IntVar(&flags.pid2, "q", -1, "pid2")
	flag.StringVar(&flags.configFile, "c", "conf/yarc.toml", "config file path")
	flag.Float64Var(&flags.rateLimit, "rate", 1.0, "session dump limit per second")
	flag.IntVar(&flags.bufSize, "minEvent", 64, "min event count")
	flag.IntVar(&flags.logSize, "logSize", 0, "log buf size")
	flag.Parse()
}

func initViper(configFile string) error {
	viper.SetConfigFile(configFile)
	return viper.ReadInConfig()
}

func main() {
	fmt.Println("Version:", buildinfo.Version)
	fmt.Println("Git commit:", buildinfo.CommitID)
	fmt.Println("Build time:", buildinfo.BuildTime)
	fmt.Println()

	parseFlags()

	if flags.pid1 < 0 && flags.pid2 < 0 {
		flag.Usage()
		os.Exit(1)
	}

	golog.Println("config:", flags.configFile)
	err := initViper(flags.configFile)
	if err != nil {
		panic(err)
	}

	pidFile, err := pidfile.Open(viper.GetString("yarc.pid"))
	if err != nil {
		panic(err)
	}
	defer pidFile.Close()

	logConfig.LogPrefix = viper.GetString("log.file_prefix")
	logConfig.LogDir = viper.GetString("log.dir")
	logConfig.AutoClear = viper.GetBool("log.auto_clear")
	logConfig.ClearHours = viper.GetInt("log.clear_hours")
	logConfig.LogLevel = viper.GetString("log.level")
	log.InitLogger(&logConfig)

	go func() {
		addr := viper.GetString("yarc.listen_addr")
		err := http.ListenAndServe(addr, nil)
		if err != nil {
			fmt.Println("http.ListenAndServe", err)
		}
	}()

	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	controller := recorder.NewController(flags.logSize)
	err = controller.Start()
	if err != nil {
		golog.Println(err)
		return
	}

	golog.Println("Waiting for events...")

	opts := []recorder.Option{
		recorder.WithMinEventCount(flags.bufSize),
		recorder.WithRateLimit(flags.rateLimit),
	}

	if flags.pid1 > 0 {
		hostname, _ := getHostnameByPID(flags.pid1)
		opts1 := append(opts, recorder.WithHostname(hostname))
		exePath := fmt.Sprintf("/proc/%d/exe", flags.pid1)
		gover, err := elf.ParseGoVersion(exePath)
		if err == nil {
			opts1 = append(opts1, recorder.WithGoVersion(gover))
		}
		_ = controller.StartRecord(flags.pid1, opts1...)
	}
	if flags.pid2 > 0 {
		hostname, _ := getHostnameByPID(flags.pid2)
		opts2 := append(opts, recorder.WithHostname(hostname))
		exePath := fmt.Sprintf("/proc/%d/exe", flags.pid2)
		gover, err := elf.ParseGoVersion(exePath)
		if err == nil {
			opts2 = append(opts2, recorder.WithGoVersion(gover))
		}
		_ = controller.StartRecord(flags.pid2, opts2...)
	}

	<-stopper
	golog.Println("Exiting...")
	controller.Stop()
}

func getHostnameByPID(pid int) (string, error) {
	data, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/root/etc/hostname", pid))
	if err == nil {
		return "", err
	}

	hostname := string(data)
	hostname = strings.TrimSpace(hostname)
	return hostname, nil
}
