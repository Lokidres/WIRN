package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/sirupsen/logrus"
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
)

const (
	MaxCacheSize    = 10000
	CacheTTL        = 5 * time.Minute
	MinInterval     = 500 // minimum milliseconds
	ShutdownTimeout = 10 * time.Second
)

type Config struct {
	ProcScan       bool
	FileScan       bool
	NetworkScan    bool
	Interval       int
	OutputJSON     bool
	OutputFile     string
	FilterUser     string
	FilterCmd      string
	SuspiciousOnly bool
	Quiet          bool
	ShowTree       bool
	IncludeEnv     bool
	MaxEvents      int
	WatchDirs      []string
	LogLevel       string
}

type ProcessEvent struct {
	Timestamp   string            `json:"timestamp"`
	PID         int               `json:"pid"`
	PPID        int               `json:"ppid"`
	User        string            `json:"user"`
	Command     string            `json:"command"`
	CmdLine     string            `json:"cmdline"`
	Cwd         string            `json:"cwd,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	Suspicious  bool              `json:"suspicious"`
}

type FileEvent struct {
	Timestamp string `json:"timestamp"`
	Path      string `json:"path"`
	Event     string `json:"event"`
	Process   string `json:"process,omitempty"`
}

type NetworkEvent struct {
	Timestamp  string `json:"timestamp"`
	PID        int    `json:"pid"`
	Process    string `json:"process"`
	Protocol   string `json:"protocol"`
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
	State      string `json:"state"`
}

var (
	config             Config
	seenProcesses      *expirable.LRU[int, bool]
	seenConnections    *expirable.LRU[string, bool]
	outputMutex        sync.Mutex
	eventCount         atomic.Int64
	log                *logrus.Logger
	outputFile         *os.File
	suspiciousTerms    = []string{
		"nc ", "ncat", "netcat", "/dev/tcp", "/dev/udp",
		"bash -i", "sh -i", "/bin/sh", "/bin/bash",
		"python -c", "perl -e", "ruby -e",
		"wget ", "curl ", "base64 -d",
		"chmod +x", "chmod 777",
		"/tmp/", "/var/tmp/", "/dev/shm/",
		"sudo ", "su -", "passwd",
		"crontab", "at ", "systemctl",
	}
)

func main() {
	parseFlags()
	initLogger()

	if err := checkPrivileges(); err != nil {
		log.Fatal(err)
	}

	if !config.Quiet {
		printBanner()
	}

	if config.Interval < MinInterval {
		log.Warnf("Interval too low, setting to minimum: %dms", MinInterval)
		config.Interval = MinInterval
	}

	seenProcesses = expirable.NewLRU[int, bool](MaxCacheSize, nil, CacheTTL)
	seenConnections = expirable.NewLRU[string, bool](MaxCacheSize, nil, CacheTTL)

	if config.OutputFile != "" {
		var err error
		outputFile, err = os.OpenFile(config.OutputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("Failed to open output file: %v", err)
		}
		defer outputFile.Close()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	var wg sync.WaitGroup

	if !config.Quiet {
		log.Infof("Starting WIRN - Enhanced Process Monitor")
		log.Infof("Process Scan: %v | File Scan: %v | Network Scan: %v",
			config.ProcScan, config.FileScan, config.NetworkScan)
		if config.SuspiciousOnly {
			log.Warn("Suspicious Activity Detection: ENABLED")
		}
	}

	if config.ProcScan {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := monitorProcesses(ctx); err != nil {
				log.Errorf("Process monitoring error: %v", err)
			}
		}()
	}

	if config.FileScan {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := monitorFileSystem(ctx); err != nil {
				log.Errorf("File monitoring error: %v", err)
			}
		}()
	}

	if config.NetworkScan {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := monitorNetwork(ctx); err != nil {
				log.Errorf("Network monitoring error: %v", err)
			}
		}()
	}

	<-sigChan
	log.Info("Shutdown signal received, cleaning up...")
	cancel()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Info("Graceful shutdown complete")
	case <-time.After(ShutdownTimeout):
		log.Warn("Shutdown timeout reached, forcing exit")
	}
}

func parseFlags() {
	flag.BoolVar(&config.ProcScan, "proc", true, "Monitor processes")
	flag.BoolVar(&config.FileScan, "file", false, "Monitor file system events")
	flag.BoolVar(&config.NetworkScan, "net", false, "Monitor network connections")
	flag.IntVar(&config.Interval, "interval", 1000, "Scan interval in milliseconds")
	flag.BoolVar(&config.OutputJSON, "json", false, "Output in JSON format")
	flag.StringVar(&config.OutputFile, "output", "", "Output file path")
	flag.StringVar(&config.FilterUser, "user", "", "Filter by username")
	flag.StringVar(&config.FilterCmd, "cmd", "", "Filter by command pattern")
	flag.BoolVar(&config.SuspiciousOnly, "suspicious", false, "Show only suspicious activities")
	flag.BoolVar(&config.Quiet, "quiet", false, "Quiet mode - no banner")
	flag.BoolVar(&config.ShowTree, "tree", false, "Show process tree")
	flag.BoolVar(&config.IncludeEnv, "env", false, "Include environment variables")
	flag.IntVar(&config.MaxEvents, "max", 0, "Maximum events to capture (0 = unlimited)")
	flag.StringVar(&config.LogLevel, "loglevel", "info", "Log level (debug, info, warn, error)")

	watchDirsFlag := flag.String("watchdirs", "/tmp,/var/tmp,/dev/shm,/etc", "Comma-separated list of directories to watch")

	flag.Parse()

	config.WatchDirs = strings.Split(*watchDirsFlag, ",")
}

func initLogger() {
	log = logrus.New()
	log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
		ForceColors:   true,
	})

	level, err := logrus.ParseLevel(config.LogLevel)
	if err != nil {
		level = logrus.InfoLevel
	}
	log.SetLevel(level)
}

func checkPrivileges() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("this tool requires root privileges (run with sudo)")
	}
	return nil
}

func printBanner() {
	banner := `
██╗    ██╗██╗██████╗ ███╗   ██╗
██║    ██║██║██╔══██╗████╗  ██║
██║ █╗ ██║██║██████╔╝██╔██╗ ██║
██║███╗██║██║██╔══██╗██║╚██╗██║
╚███╔███╔╝██║██║  ██║██║ ╚████║
 ╚══╝╚══╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
                                
Watch Inspect Report Notify
Enhanced Process Monitoring Tool
Version 2.0.0 - Production Ready
`
	fmt.Printf("%s%s%s\n", ColorGreen, banner, ColorReset)
}

func monitorProcesses(ctx context.Context) error {
	ticker := time.NewTicker(time.Duration(config.Interval) * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if config.MaxEvents > 0 && eventCount.Load() >= int64(config.MaxEvents) {
				return nil
			}

			if err := scanProcesses(); err != nil {
				log.Debugf("Process scan error: %v", err)
			}
		}
	}
}

func scanProcesses() error {
	files, err := os.ReadDir("/proc")
	if err != nil {
		return fmt.Errorf("failed to read /proc: %w", err)
	}

	for _, f := range files {
		if !f.IsDir() {
			continue
		}

		var pid int
		if _, err := fmt.Sscanf(f.Name(), "%d", &pid); err != nil {
			continue
		}

		if seenProcesses.Contains(pid) {
			continue
		}

		event := getProcessInfo(pid)
		if event == nil {
			continue
		}

		if shouldFilterEvent(event) {
			continue
		}

		seenProcesses.Add(pid, true)
		outputEvent(event)
	}

	return nil
}

func getProcessInfo(pid int) *ProcessEvent {
	cmdlineBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return nil
	}

	cmdline := strings.ReplaceAll(string(cmdlineBytes), "\x00", " ")
	cmdline = strings.TrimSpace(cmdline)

	if cmdline == "" {
		return nil
	}

	statBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return nil
	}

	statFields := strings.Fields(string(statBytes))
	if len(statFields) < 4 {
		return nil
	}

	var ppid int
	fmt.Sscanf(statFields[3], "%d", &ppid)

	statusBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	var user string
	if err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(statusBytes)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "Uid:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					user = getUserName(fields[1])
				}
				break
			}
		}
	}

	var cwd string
	if cwdLink, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid)); err == nil {
		cwd = cwdLink
	}

	event := &ProcessEvent{
		Timestamp:  time.Now().Format(time.RFC3339),
		PID:        pid,
		PPID:       ppid,
		User:       user,
		Command:    filepath.Base(strings.Split(cmdline, " ")[0]),
		CmdLine:    cmdline,
		Cwd:        cwd,
		Suspicious: isSuspicious(cmdline),
	}

	if config.IncludeEnv {
		event.Environment = getEnvironment(pid)
	}

	return event
}

func getUserName(uid string) string {
	cmd := exec.Command("getent", "passwd", uid)
	output, err := cmd.Output()
	if err != nil {
		return uid
	}

	fields := strings.Split(strings.TrimSpace(string(output)), ":")
	if len(fields) > 0 {
		return fields[0]
	}

	return uid
}

func getEnvironment(pid int) map[string]string {
	env := make(map[string]string)
	envBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		return env
	}

	envVars := strings.Split(string(envBytes), "\x00")
	for _, e := range envVars {
		if e == "" {
			continue
		}
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			env[parts[0]] = parts[1]
		}
	}

	return env
}

func isSuspicious(cmdline string) bool {
	cmdlineLower := strings.ToLower(cmdline)
	for _, term := range suspiciousTerms {
		if strings.Contains(cmdlineLower, term) {
			return true
		}
	}
	return false
}

func shouldFilterEvent(event *ProcessEvent) bool {
	if config.SuspiciousOnly && !event.Suspicious {
		return true
	}

	if config.FilterUser != "" && event.User != config.FilterUser {
		return true
	}

	if config.FilterCmd != "" {
		matched, err := regexp.MatchString(config.FilterCmd, event.CmdLine)
		if err != nil {
			log.Debugf("Regex error: %v", err)
			return true
		}
		if !matched {
			return true
		}
	}

	return false
}

func outputEvent(event *ProcessEvent) {
	outputMutex.Lock()
	defer outputMutex.Unlock()

	eventCount.Add(1)

	if config.OutputJSON {
		jsonData, err := json.Marshal(event)
		if err != nil {
			log.Errorf("JSON marshal error: %v", err)
			return
		}
		output := string(jsonData)

		if outputFile != nil {
			fmt.Fprintln(outputFile, output)
		} else {
			fmt.Println(output)
		}
		return
	}

	color := ColorWhite
	if event.Suspicious {
		color = ColorRed
	}

	output := fmt.Sprintf("%s[%s] PID: %d | PPID: %d | User: %s%s\n",
		color, event.Timestamp, event.PID, event.PPID, event.User, ColorReset)
	output += fmt.Sprintf("%s  ↳ CMD: %s%s\n", color, event.CmdLine, ColorReset)

	if event.Cwd != "" {
		output += fmt.Sprintf("%s  ↳ CWD: %s%s\n", ColorCyan, event.Cwd, ColorReset)
	}

	if event.Suspicious {
		output += fmt.Sprintf("%s  ⚠ SUSPICIOUS ACTIVITY DETECTED!%s\n", ColorRed, ColorReset)
	}

	if outputFile != nil {
		fmt.Fprint(outputFile, output)
	} else {
		fmt.Print(output)
	}
}

func monitorFileSystem(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create watcher: %w", err)
	}
	defer watcher.Close()

	for _, dir := range config.WatchDirs {
		if err := watcher.Add(dir); err != nil {
			log.Warnf("Failed to watch %s: %v", dir, err)
			continue
		}
		log.Infof("Watching directory: %s", dir)
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}

			if config.MaxEvents > 0 && eventCount.Load() >= int64(config.MaxEvents) {
				return nil
			}

			fileEvent := &FileEvent{
				Timestamp: time.Now().Format(time.RFC3339),
				Path:      event.Name,
				Event:     event.Op.String(),
			}

			if config.OutputJSON {
				jsonData, _ := json.Marshal(fileEvent)
				fmt.Println(string(jsonData))
			} else {
				fmt.Printf("%s[%s] FILE: %s - %s%s\n",
					ColorYellow, fileEvent.Timestamp, fileEvent.Event, fileEvent.Path, ColorReset)
			}

			eventCount.Add(1)

		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			log.Errorf("Watcher error: %v", err)
		}
	}
}

func monitorNetwork(ctx context.Context) error {
	log.Info("Network monitoring started")

	ticker := time.NewTicker(time.Duration(config.Interval) * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if config.MaxEvents > 0 && eventCount.Load() >= int64(config.MaxEvents) {
				return nil
			}

			connections, err := getNetworkConnections()
			if err != nil {
				log.Debugf("Network scan error: %v", err)
				continue
			}

			for _, conn := range connections {
				key := fmt.Sprintf("%s:%s->%s", conn.Protocol, conn.LocalAddr, conn.RemoteAddr)
				
				if seenConnections.Contains(key) {
					continue
				}

				seenConnections.Add(key, true)

				if config.OutputJSON {
					jsonData, _ := json.Marshal(conn)
					fmt.Println(string(jsonData))
				} else {
					fmt.Printf("%s[%s] NET: %s | %s -> %s | State: %s | PID: %d (%s)%s\n",
						ColorBlue, conn.Timestamp, conn.Protocol, conn.LocalAddr,
						conn.RemoteAddr, conn.State, conn.PID, conn.Process, ColorReset)
				}

				eventCount.Add(1)
			}
		}
	}
}

func getNetworkConnections() ([]NetworkEvent, error) {
	var events []NetworkEvent

	tcpFile, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc/net/tcp: %w", err)
	}

	scanner := bufio.NewScanner(strings.NewReader(string(tcpFile)))
	scanner.Scan() // skip header

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}

		var pid int
		fmt.Sscanf(fields[9], "%d", &pid)

		event := NetworkEvent{
			Timestamp:  time.Now().Format(time.RFC3339),
			Protocol:   "TCP",
			LocalAddr:  parseAddr(fields[1]),
			RemoteAddr: parseAddr(fields[2]),
			State:      getTCPState(fields[3]),
			PID:        pid,
			Process:    getProcessName(pid),
		}

		events = append(events, event)
	}

	return events, nil
}

func parseAddr(addr string) string {
	parts := strings.Split(addr, ":")
	if len(parts) != 2 {
		return addr
	}

	ipHex := parts[0]
	portHex := parts[1]

	ipBytes, err := hex.DecodeString(ipHex)
	if err != nil || len(ipBytes) != 4 {
		return addr
	}

	ip := fmt.Sprintf("%d.%d.%d.%d", ipBytes[3], ipBytes[2], ipBytes[1], ipBytes[0])

	port, err := strconv.ParseInt(portHex, 16, 64)
	if err != nil {
		return addr
	}

	return fmt.Sprintf("%s:%d", ip, port)
}

func getTCPState(state string) string {
	states := map[string]string{
		"01": "ESTABLISHED",
		"02": "SYN_SENT",
		"03": "SYN_RECV",
		"04": "FIN_WAIT1",
		"05": "FIN_WAIT2",
		"06": "TIME_WAIT",
		"07": "CLOSE",
		"08": "CLOSE_WAIT",
		"09": "LAST_ACK",
		"0A": "LISTEN",
		"0B": "CLOSING",
	}

	if s, ok := states[state]; ok {
		return s
	}
	return "UNKNOWN"
}

func getProcessName(pid int) string {
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return "unknown"
	}

	name := strings.ReplaceAll(string(cmdline), "\x00", " ")
	name = strings.TrimSpace(name)

	if name == "" {
		return "unknown"
	}

	return filepath.Base(strings.Split(name, " ")[0])
}
