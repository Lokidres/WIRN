package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
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
	config          Config
	seenProcesses   = make(map[int]bool)
	processMutex    sync.Mutex
	outputMutex     sync.Mutex
	eventCount      int
	suspiciousTerms = []string{
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

	printBanner()

	if !config.Quiet {
		fmt.Printf("%s[*] Starting WIRN - Enhanced Process Monitor%s\n", ColorCyan, ColorReset)
		fmt.Printf("%s[*] Process Scan: %v | File Scan: %v | Network Scan: %v%s\n",
			ColorCyan, config.ProcScan, config.FileScan, config.NetworkScan, ColorReset)
		if config.SuspiciousOnly {
			fmt.Printf("%s[*] Suspicious Activity Detection: ENABLED%s\n", ColorYellow, ColorReset)
		}
		fmt.Println()
	}

	var wg sync.WaitGroup

	if config.ProcScan {
		wg.Add(1)
		go func() {
			defer wg.Done()
			monitorProcesses()
		}()
	}

	if config.FileScan {
		wg.Add(1)
		go func() {
			defer wg.Done()
			monitorFileSystem()
		}()
	}

	if config.NetworkScan {
		wg.Add(1)
		go func() {
			defer wg.Done()
			monitorNetwork()
		}()
	}

	wg.Wait()
}

func parseFlags() {
	flag.BoolVar(&config.ProcScan, "proc", true, "Monitor processes")
	flag.BoolVar(&config.FileScan, "file", false, "Monitor file system events")
	flag.BoolVar(&config.NetworkScan, "net", false, "Monitor network connections")
	flag.IntVar(&config.Interval, "interval", 100, "Scan interval in milliseconds")
	flag.BoolVar(&config.OutputJSON, "json", false, "Output in JSON format")
	flag.StringVar(&config.OutputFile, "output", "", "Output file path")
	flag.StringVar(&config.FilterUser, "user", "", "Filter by username")
	flag.StringVar(&config.FilterCmd, "cmd", "", "Filter by command pattern")
	flag.BoolVar(&config.SuspiciousOnly, "suspicious", false, "Show only suspicious activities")
	flag.BoolVar(&config.Quiet, "quiet", false, "Quiet mode - no banner")
	flag.BoolVar(&config.ShowTree, "tree", false, "Show process tree")
	flag.BoolVar(&config.IncludeEnv, "env", false, "Include environment variables")
	flag.IntVar(&config.MaxEvents, "max", 0, "Maximum events to capture (0 = unlimited)")

	flag.Parse()
}

func printBanner() {
	if config.Quiet {
		return
	}

	banner := `
██╗    ██╗██╗██████╗ ███╗   ██╗
██║    ██║██║██╔══██╗████╗  ██║
██║ █╗ ██║██║██████╔╝██╔██╗ ██║
██║███╗██║██║██╔══██╗██║╚██╗██║
╚███╔███╔╝██║██║  ██║██║ ╚████║
 ╚══╝╚══╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
                                
Watch Inspect Report Notify
Enhanced Process Monitoring Tool
Version 1.0.0
`
	fmt.Printf("%s%s%s\n", ColorGreen, banner, ColorReset)
}

func monitorProcesses() {
	for {
		if config.MaxEvents > 0 && eventCount >= config.MaxEvents {
			return
		}

		files, err := ioutil.ReadDir("/proc")
		if err != nil {
			continue
		}

		for _, f := range files {
			if !f.IsDir() {
				continue
			}

			var pid int
			if _, err := fmt.Sscanf(f.Name(), "%d", &pid); err != nil {
				continue
			}

			processMutex.Lock()
			if seenProcesses[pid] {
				processMutex.Unlock()
				continue
			}
			processMutex.Unlock()

			event := getProcessInfo(pid)
			if event == nil {
				continue
			}

			if shouldFilterEvent(event) {
				continue
			}

			processMutex.Lock()
			seenProcesses[pid] = true
			processMutex.Unlock()

			outputEvent(event)
		}

		time.Sleep(time.Duration(config.Interval) * time.Millisecond)
	}
}

func getProcessInfo(pid int) *ProcessEvent {
	cmdlineBytes, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return nil
	}

	cmdline := strings.ReplaceAll(string(cmdlineBytes), "\x00", " ")
	cmdline = strings.TrimSpace(cmdline)

	if cmdline == "" {
		return nil
	}

	statBytes, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return nil
	}

	statFields := strings.Fields(string(statBytes))
	if len(statFields) < 4 {
		return nil
	}

	var ppid int
	fmt.Sscanf(statFields[3], "%d", &ppid)

	statusBytes, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
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
		Timestamp:  time.Now().Format("2006-01-02 15:04:05"),
		PID:        pid,
		PPID:       ppid,
		User:       user,
		Command:    strings.Split(cmdline, " ")[0],
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

	fields := strings.Split(string(output), ":")
	if len(fields) > 0 {
		return fields[0]
	}

	return uid
}

func getEnvironment(pid int) map[string]string {
	env := make(map[string]string)
	envBytes, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		return env
	}

	envVars := strings.Split(string(envBytes), "\x00")
	for _, e := range envVars {
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
		matched, _ := regexp.MatchString(config.FilterCmd, event.CmdLine)
		if !matched {
			return true
		}
	}

	return false
}

func outputEvent(event *ProcessEvent) {
	outputMutex.Lock()
	defer outputMutex.Unlock()

	eventCount++

	if config.OutputJSON {
		jsonData, _ := json.Marshal(event)
		output := string(jsonData)

		if config.OutputFile != "" {
			appendToFile(output)
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

	if config.OutputFile != "" {
		appendToFile(output)
	} else {
		fmt.Print(output)
	}
}

func monitorFileSystem() {
	if !config.Quiet {
		fmt.Printf("%s[*] File system monitoring is experimental%s\n", ColorYellow, ColorReset)
	}

	watchDirs := []string{"/tmp", "/var/tmp", "/dev/shm", "/etc"}

	for {
		if config.MaxEvents > 0 && eventCount >= config.MaxEvents {
			return
		}

		for _, dir := range watchDirs {
			filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return nil
				}

				if info.ModTime().After(time.Now().Add(-time.Duration(config.Interval) * time.Millisecond)) {
					event := &FileEvent{
						Timestamp: time.Now().Format("2006-01-02 15:04:05"),
						Path:      path,
						Event:     "MODIFIED",
					}

					if config.OutputJSON {
						jsonData, _ := json.Marshal(event)
						fmt.Println(string(jsonData))
					} else {
						fmt.Printf("%s[%s] FILE: %s - %s%s\n",
							ColorYellow, event.Timestamp, event.Event, event.Path, ColorReset)
					}
				}

				return nil
			})
		}

		time.Sleep(time.Duration(config.Interval) * time.Millisecond)
	}
}

func monitorNetwork() {
	if !config.Quiet {
		fmt.Printf("%s[*] Network monitoring started%s\n", ColorCyan, ColorReset)
	}

	seenConnections := make(map[string]bool)

	for {
		if config.MaxEvents > 0 && eventCount >= config.MaxEvents {
			return
		}

		connections := getNetworkConnections()
		for _, conn := range connections {
			key := fmt.Sprintf("%s:%s->%s", conn.Protocol, conn.LocalAddr, conn.RemoteAddr)
			if !seenConnections[key] {
				seenConnections[key] = true

				if config.OutputJSON {
					jsonData, _ := json.Marshal(conn)
					fmt.Println(string(jsonData))
				} else {
					fmt.Printf("%s[%s] NET: %s | %s -> %s | State: %s | PID: %d (%s)%s\n",
						ColorBlue, conn.Timestamp, conn.Protocol, conn.LocalAddr,
						conn.RemoteAddr, conn.State, conn.PID, conn.Process, ColorReset)
				}
			}
		}

		time.Sleep(time.Duration(config.Interval) * time.Millisecond)
	}
}

func getNetworkConnections() []NetworkEvent {
	var events []NetworkEvent

	tcpFile, err := ioutil.ReadFile("/proc/net/tcp")
	if err != nil {
		return events
	}

	scanner := bufio.NewScanner(strings.NewReader(string(tcpFile)))
	scanner.Scan()

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}

		event := NetworkEvent{
			Timestamp:  time.Now().Format("2006-01-02 15:04:05"),
			Protocol:   "TCP",
			LocalAddr:  parseAddr(fields[1]),
			RemoteAddr: parseAddr(fields[2]),
			State:      getTCPState(fields[3]),
		}

		fmt.Sscanf(fields[9], "%d", &event.PID)
		event.Process = getProcessName(event.PID)

		events = append(events, event)
	}

	return events
}

func parseAddr(addr string) string {
	parts := strings.Split(addr, ":")
	if len(parts) != 2 {
		return addr
	}
	return addr
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
	cmdline, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return "unknown"
	}

	name := strings.ReplaceAll(string(cmdline), "\x00", " ")
	name = strings.TrimSpace(name)

	if name == "" {
		return "unknown"
	}

	return strings.Split(name, " ")[0]
}

func appendToFile(content string) {
	f, err := os.OpenFile(config.OutputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening output file: %v\n", err)
		return
	}
	defer f.Close()

	f.WriteString(content + "\n")
}
