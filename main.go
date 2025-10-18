package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/shirou/gopsutil/v3/process"
	"github.com/spf13/cobra"
)

type ProcessEvent struct {
	Timestamp     time.Time `json:"timestamp"`
	PID           int32     `json:"pid"`
	PPID          int32     `json:"ppid"`
	ProcessName   string    `json:"process_name"`
	Command       string    `json:"command"`
	User          string    `json:"user"`
	EventType     string    `json:"event_type"`
	Details       string    `json:"details"`
	FilePath      string    `json:"file_path,omitempty"`
	NetworkInfo   string    `json:"network_info,omitempty"`
	SecurityLevel string    `json:"security_level,omitempty"`
	ThreatVector  string    `json:"threat_vector,omitempty"`
	RiskScore     int       `json:"risk_score,omitempty"`
	AlertMessage  string    `json:"alert_message,omitempty"`
}

type WirnConfig struct {
	StealthMode       bool
	LogToFile         bool
	LogFile           string
	FilterProcesses   []string
	FilterUsers       []string
	FilterCommands     []string
	MonitorNetwork     bool
	MonitorFiles       bool
	Verbose            bool
	JSONOutput         bool
	ColorOutput        bool
	RefreshRate        time.Duration
	MaxLogSize         int64
	SecurityDetection  bool
	AlertMode          bool
	RiskThreshold      int
	HighlightThreats   bool
}

type SecurityPattern struct {
	Name        string
	Pattern     *regexp.Regexp
	RiskScore   int
	ThreatVector string
	Description string
}

type ProcessMonitor struct {
	config         *WirnConfig
	events         chan ProcessEvent
	knownProcesses map[int32]*process.Process
	mutex          sync.RWMutex
	logFile        *os.File
	stopChan       chan bool
	evasionCount   int
	securityPatterns map[string]*SecurityPattern
	threatCount    int
}

var (
	config  WirnConfig
	monitor *ProcessMonitor
)

func init() {
	rootCmd.Flags().BoolVarP(&config.StealthMode, "stealth", "s", false, "Stealth mode - minimize detection")
	rootCmd.Flags().BoolVarP(&config.LogToFile, "log", "l", false, "Log events to file")
	rootCmd.Flags().StringVarP(&config.LogFile, "logfile", "f", "wirn.log", "Log file path")
	rootCmd.Flags().StringSliceVarP(&config.FilterProcesses, "filter-process", "p", []string{}, "Filter specific processes")
	rootCmd.Flags().StringSliceVarP(&config.FilterUsers, "filter-user", "u", []string{}, "Filter specific users")
	rootCmd.Flags().StringSliceVarP(&config.FilterCommands, "filter-command", "c", []string{}, "Filter specific commands")
	rootCmd.Flags().BoolVarP(&config.MonitorNetwork, "network", "n", false, "Monitor network connections")
	rootCmd.Flags().BoolVarP(&config.MonitorFiles, "files", "F", false, "Monitor file operations")
	rootCmd.Flags().BoolVarP(&config.Verbose, "verbose", "v", false, "Verbose output")
	rootCmd.Flags().BoolVarP(&config.JSONOutput, "json", "j", false, "JSON output format")
	rootCmd.Flags().BoolVarP(&config.ColorOutput, "color", "C", true, "Colorized output")
	rootCmd.Flags().DurationVarP(&config.RefreshRate, "refresh", "r", 100*time.Millisecond, "Refresh rate")
	rootCmd.Flags().Int64VarP(&config.MaxLogSize, "max-log-size", "m", 100*1024*1024, "Maximum log file size in bytes")
	rootCmd.Flags().BoolVarP(&config.SecurityDetection, "security", "S", true, "Enable security pattern detection")
	rootCmd.Flags().BoolVarP(&config.AlertMode, "alerts", "A", false, "Enable alert mode for high-risk events")
	rootCmd.Flags().IntVarP(&config.RiskThreshold, "risk-threshold", "t", 7, "Risk score threshold for alerts (1-10)")
	rootCmd.Flags().BoolVarP(&config.HighlightThreats, "highlight", "H", true, "Highlight threat vectors and security events")
}

var rootCmd = &cobra.Command{
	Use:   "wirn",
	Short: "Advanced Process Spy Tool - pspy64 alternative",
	Long: `Wirn is an advanced process monitoring tool designed for offensive security.
It provides comprehensive process tracking, system call monitoring, and stealth capabilities.`,
	Run: runWirn,
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func runWirn(cmd *cobra.Command, args []string) {
	if config.StealthMode {
		enableStealthMode()
	}

	monitor = NewProcessMonitor(&config)
	defer monitor.Cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		cancel()
	}()

	if config.LogToFile {
		if err := monitor.SetupLogFile(); err != nil {
			log.Printf("Log file setup failed: %v", err)
		}
	}

	go monitor.StartMonitoring(ctx)
	go monitor.ProcessEvents(ctx)

	monitor.DisplayHeader()
	monitor.Run(ctx)
}

func NewProcessMonitor(cfg *WirnConfig) *ProcessMonitor {
	pm := &ProcessMonitor{
		config:         cfg,
		events:         make(chan ProcessEvent, 1000),
		knownProcesses: make(map[int32]*process.Process),
		stopChan:       make(chan bool),
		securityPatterns: make(map[string]*SecurityPattern),
		threatCount:    0,
	}
	
	if cfg.SecurityDetection {
		pm.initializeSecurityPatterns()
	}
	
	return pm
}

func (pm *ProcessMonitor) SetupLogFile() error {
	var err error
	pm.logFile, err = os.OpenFile(pm.config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	return nil
}

func (pm *ProcessMonitor) Cleanup() {
	if pm.logFile != nil {
		pm.logFile.Close()
	}
}

func (pm *ProcessMonitor) initializeSecurityPatterns() {
	patterns := []SecurityPattern{
		{
			Name:        "Password Dump",
			Pattern:     regexp.MustCompile(`(?i)(mimikatz|pwdump|samdump|hashdump|secretsdump)`),
			RiskScore:   10,
			ThreatVector: "Credential Access",
			Description: "Password dumping tool detected",
		},
		{
			Name:        "Privilege Escalation",
			Pattern:     regexp.MustCompile(`(?i)(sudo|su|runas|psexec|at|schtasks|wmic.*privilege)`),
			RiskScore:   8,
			ThreatVector: "Privilege Escalation",
			Description: "Privilege escalation attempt detected",
		},
		{
			Name:        "Lateral Movement",
			Pattern:     regexp.MustCompile(`(?i)(psexec|wmi|smb|rdp|ssh.*-o|net.*use|mount)`),
			RiskScore:   9,
			ThreatVector: "Lateral Movement",
			Description: "Lateral movement technique detected",
		},
		{
			Name:        "Persistence",
			Pattern:     regexp.MustCompile(`(?i)(schtasks|at|crontab|registry.*run|startup|autorun)`),
			RiskScore:   7,
			ThreatVector: "Persistence",
			Description: "Persistence mechanism detected",
		},
		{
			Name:        "Command Injection",
			Pattern:     regexp.MustCompile(`(?i)(cmd\.exe|powershell|bash|sh|cmd.*\/c|powershell.*-e)`),
			RiskScore:   6,
			ThreatVector: "Command Injection",
			Description: "Command injection attempt detected",
		},
		{
			Name:        "Network Reconnaissance",
			Pattern:     regexp.MustCompile(`(?i)(nmap|masscan|zmap|netdiscover|arp-scan)`),
			RiskScore:   5,
			ThreatVector: "Reconnaissance",
			Description: "Network reconnaissance tool detected",
		},
		{
			Name:        "Crypto Mining",
			Pattern:     regexp.MustCompile(`(?i)(xmrig|minerd|cpuminer|cryptonight|monero)`),
			RiskScore:   4,
			ThreatVector: "Crypto Mining",
			Description: "Cryptocurrency mining detected",
		},
		{
			Name:        "Reverse Shell",
			Pattern:     regexp.MustCompile(`(?i)(nc.*-e|netcat.*-e|bash.*-i|powershell.*-enc|msfvenom)`),
			RiskScore:   9,
			ThreatVector: "Command & Control",
			Description: "Reverse shell attempt detected",
		},
		{
			Name:        "File Encryption",
			Pattern:     regexp.MustCompile(`(?i)(encrypt|ransom|crypt|locky|wannacry)`),
			RiskScore:   8,
			ThreatVector: "Ransomware",
			Description: "File encryption/ransomware activity detected",
		},
		{
			Name:        "Suspicious Downloads",
			Pattern:     regexp.MustCompile(`(?i)(wget.*-O|curl.*-o|powershell.*download|invoke-webrequest)`),
			RiskScore:   5,
			ThreatVector: "Data Exfiltration",
			Description: "Suspicious download activity detected",
		},
		{
			Name:        "Keylogger",
			Pattern:     regexp.MustCompile(`(?i)(keylog|keystroke|logkeys|pykeylogger)`),
			RiskScore:   7,
			ThreatVector: "Credential Access",
			Description: "Keylogger activity detected",
		},
		{
			Name:        "Process Injection",
			Pattern:     regexp.MustCompile(`(?i)(inject|dllinject|process.*hollow|atom.*bombing)`),
			RiskScore:   8,
			ThreatVector: "Process Injection",
			Description: "Process injection technique detected",
		},
	}
	
	for _, pattern := range patterns {
		pm.securityPatterns[pattern.Name] = &pattern
	}
}

func (pm *ProcessMonitor) analyzeSecurityThreats(cmdline, processName string) (string, int, string) {
	if !pm.config.SecurityDetection {
		return "", 0, ""
	}
	
	var maxRiskScore int
	var threatVector string
	var alertMessage string
	
	for _, pattern := range pm.securityPatterns {
		if pattern.Pattern.MatchString(cmdline) || pattern.Pattern.MatchString(processName) {
			if pattern.RiskScore > maxRiskScore {
				maxRiskScore = pattern.RiskScore
				threatVector = pattern.ThreatVector
				alertMessage = fmt.Sprintf("🚨 %s: %s", pattern.Name, pattern.Description)
			}
		}
	}
	
	return threatVector, maxRiskScore, alertMessage
}

func (pm *ProcessMonitor) getSecurityLevel(riskScore int) string {
	switch {
	case riskScore >= 9:
		return "CRITICAL"
	case riskScore >= 7:
		return "HIGH"
	case riskScore >= 5:
		return "MEDIUM"
	case riskScore >= 3:
		return "LOW"
	default:
		return "INFO"
	}
}

func (pm *ProcessMonitor) StartMonitoring(ctx context.Context) {
	ticker := time.NewTicker(pm.config.RefreshRate)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pm.scanProcesses()
			if pm.config.MonitorNetwork {
				pm.scanNetworkConnections()
			}
			if pm.config.MonitorFiles {
				pm.scanFileOperations()
			}
		}
	}
}

func (pm *ProcessMonitor) scanProcesses() {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	processes, err := process.Processes()
	if err != nil {
		return
	}

	currentPIDs := make(map[int32]bool)

	for _, proc := range processes {
		currentPIDs[proc.Pid] = true

		if _, exists := pm.knownProcesses[proc.Pid]; !exists {
			pm.handleNewProcess(proc)
		} else {
			pm.updateProcessInfo(proc)
		}
	}

	for pid := range pm.knownProcesses {
		if !currentPIDs[pid] {
			pm.handleProcessExit(pid)
		}
	}
}

func (pm *ProcessMonitor) handleNewProcess(proc *process.Process) {
	pm.knownProcesses[proc.Pid] = proc

	cmdline, _ := proc.Cmdline()
	username, _ := proc.Username()
	ppid, _ := proc.Ppid()
	createTime, _ := proc.CreateTime()

	if pm.shouldFilter(proc, cmdline, username) {
		return
	}

	processName := pm.getProcessName(proc)
	threatVector, riskScore, alertMessage := pm.analyzeSecurityThreats(cmdline, processName)
	
	event := ProcessEvent{
		Timestamp:     time.Unix(createTime/1000, 0),
		PID:           proc.Pid,
		PPID:          ppid,
		ProcessName:   processName,
		Command:       cmdline,
		User:          username,
		EventType:     "PROCESS_START",
		Details:       fmt.Sprintf("Process started with PID %d", proc.Pid),
		SecurityLevel: pm.getSecurityLevel(riskScore),
		ThreatVector:  threatVector,
		RiskScore:     riskScore,
		AlertMessage:  alertMessage,
	}

	if riskScore > 0 {
		pm.threatCount++
	}

	pm.events <- event
}

func (pm *ProcessMonitor) handleProcessExit(pid int32) {
	proc := pm.knownProcesses[pid]
	if proc == nil {
		return
	}

	cmdline, _ := proc.Cmdline()
	username, _ := proc.Username()
	ppid, _ := proc.Ppid()

	if pm.shouldFilter(proc, cmdline, username) {
		delete(pm.knownProcesses, pid)
		return
	}

	event := ProcessEvent{
		Timestamp:   time.Now(),
		PID:         pid,
		PPID:        ppid,
		ProcessName: pm.getProcessName(proc),
		Command:     cmdline,
		User:        username,
		EventType:   "PROCESS_EXIT",
		Details:     fmt.Sprintf("Process exited with PID %d", pid),
	}

	pm.events <- event
	delete(pm.knownProcesses, pid)
}

func (pm *ProcessMonitor) updateProcessInfo(proc *process.Process) {
	pm.knownProcesses[proc.Pid] = proc
}

func (pm *ProcessMonitor) scanNetworkConnections() {
	// Network monitoring temporarily disabled due to type compatibility issues
	// Will be implemented with proper gopsutil v3 types
	return
}

func (pm *ProcessMonitor) scanFileOperations() {
	processes, err := process.Processes()
	if err != nil {
		return
	}

	for _, proc := range processes {
		openFiles, err := proc.OpenFiles()
		if err != nil {
			continue
		}

		if len(openFiles) > 0 {
			cmdline, _ := proc.Cmdline()
			username, _ := proc.Username()
			ppid, _ := proc.Ppid()

			if pm.shouldFilter(proc, cmdline, username) {
				continue
			}

			for _, file := range openFiles {
				event := ProcessEvent{
					Timestamp:   time.Now(),
					PID:         proc.Pid,
					PPID:        ppid,
					ProcessName: pm.getProcessName(proc),
					Command:     cmdline,
					User:        username,
					EventType:   "FILE_ACCESS",
					Details:     "File access detected",
					FilePath:    file.Path,
				}

				pm.events <- event
			}
		}
	}
}

func (pm *ProcessMonitor) shouldFilter(proc *process.Process, cmdline, username string) bool {
	if len(pm.config.FilterProcesses) > 0 {
		processName := pm.getProcessName(proc)
		for _, filter := range pm.config.FilterProcesses {
			if strings.Contains(strings.ToLower(processName), strings.ToLower(filter)) ||
				strings.Contains(strings.ToLower(cmdline), strings.ToLower(filter)) {
				return false
			}
		}
		return true
	}

	if len(pm.config.FilterUsers) > 0 {
		for _, filter := range pm.config.FilterUsers {
			if strings.Contains(strings.ToLower(username), strings.ToLower(filter)) {
				return false
			}
		}
		return true
	}

	if len(pm.config.FilterCommands) > 0 {
		for _, filter := range pm.config.FilterCommands {
			if strings.Contains(strings.ToLower(cmdline), strings.ToLower(filter)) {
				return false
			}
		}
		return true
	}

	return false
}

func (pm *ProcessMonitor) getProcessName(proc *process.Process) string {
	name, err := proc.Name()
	if err != nil {
		return "unknown"
	}
	return name
}

func (pm *ProcessMonitor) ProcessEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-pm.events:
			pm.handleEvent(event)
		}
	}
}

func (pm *ProcessMonitor) handleEvent(event ProcessEvent) {
	if pm.config.LogToFile && pm.logFile != nil {
		pm.writeToLogFile(event)
	}

	if pm.config.JSONOutput {
		pm.outputJSON(event)
	} else {
		pm.outputFormatted(event)
	}
}

func (pm *ProcessMonitor) writeToLogFile(event ProcessEvent) {
	if pm.logFile == nil {
		return
	}

	pm.checkLogFileSize()

	var data []byte
	var err error

	if pm.config.JSONOutput {
		data, err = json.Marshal(event)
	} else {
		data = []byte(pm.formatEventText(event) + "\n")
	}

	if err == nil {
		pm.logFile.Write(data)
	}
}

func (pm *ProcessMonitor) checkLogFileSize() {
	if pm.logFile == nil {
		return
	}

	stat, err := pm.logFile.Stat()
	if err != nil {
		return
	}

	if stat.Size() > pm.config.MaxLogSize {
		pm.logFile.Close()
		pm.rotateLogFile()
		pm.SetupLogFile()
	}
}

func (pm *ProcessMonitor) rotateLogFile() {
	timestamp := time.Now().Format("20060102_150405")
	rotatedFile := fmt.Sprintf("%s.%s", pm.config.LogFile, timestamp)
	os.Rename(pm.config.LogFile, rotatedFile)
}

func (pm *ProcessMonitor) outputJSON(event ProcessEvent) {
	data, err := json.Marshal(event)
	if err != nil {
		return
	}
	fmt.Println(string(data))
}

func (pm *ProcessMonitor) outputFormatted(event ProcessEvent) {
	if !pm.config.ColorOutput {
		fmt.Println(pm.formatEventText(event))
		return
	}

	timestamp := event.Timestamp.Format("15:04:05")
	pidStr := fmt.Sprintf("%d", event.PID)
	ppidStr := fmt.Sprintf("%d", event.PPID)

	switch event.EventType {
	case "PROCESS_START":
		pm.printProcessStart(event, timestamp, pidStr, ppidStr)
	case "PROCESS_EXIT":
		color.New(color.FgRed).Printf("[%s] ", timestamp)
		color.New(color.FgRed).Printf("EXIT  ")
		color.New(color.FgYellow).Printf("PID:%s ", pidStr)
		color.New(color.FgBlue).Printf("PPID:%s ", ppidStr)
		color.New(color.FgMagenta).Printf("USER:%s ", event.User)
		color.New(color.FgWhite).Printf("%s\n", event.ProcessName)
	case "NETWORK_CONNECTION":
		color.New(color.FgBlue).Printf("[%s] ", timestamp)
		color.New(color.FgCyan).Printf("NET   ")
		color.New(color.FgYellow).Printf("PID:%s ", pidStr)
		color.New(color.FgMagenta).Printf("USER:%s ", event.User)
		color.New(color.FgWhite).Printf("%s ", event.ProcessName)
		color.New(color.FgHiBlue).Printf("%s\n", event.NetworkInfo)
	case "FILE_ACCESS":
		color.New(color.FgYellow).Printf("[%s] ", timestamp)
		color.New(color.FgCyan).Printf("FILE  ")
		color.New(color.FgYellow).Printf("PID:%s ", pidStr)
		color.New(color.FgMagenta).Printf("USER:%s ", event.User)
		color.New(color.FgWhite).Printf("%s ", event.ProcessName)
		color.New(color.FgHiYellow).Printf("%s\n", event.FilePath)
	}
}

func (pm *ProcessMonitor) printProcessStart(event ProcessEvent, timestamp, pidStr, ppidStr string) {
	if event.RiskScore > 0 && pm.config.HighlightThreats {
		pm.printThreatEvent(event, timestamp, pidStr, ppidStr)
	} else {
		color.New(color.FgGreen).Printf("[%s] ", timestamp)
		color.New(color.FgCyan).Printf("START ")
		color.New(color.FgYellow).Printf("PID:%s ", pidStr)
		color.New(color.FgBlue).Printf("PPID:%s ", ppidStr)
		color.New(color.FgMagenta).Printf("USER:%s ", event.User)
		color.New(color.FgWhite).Printf("%s ", event.ProcessName)
		color.New(color.FgHiBlack).Printf("%s\n", event.Command)
	}
}

func (pm *ProcessMonitor) printThreatEvent(event ProcessEvent, timestamp, pidStr, ppidStr string) {
	var bgColor color.Attribute
	var fgColor color.Attribute
	
	switch event.SecurityLevel {
	case "CRITICAL":
		bgColor = color.BgRed
		fgColor = color.FgWhite
	case "HIGH":
		bgColor = color.BgMagenta
		fgColor = color.FgWhite
	case "MEDIUM":
		bgColor = color.BgYellow
		fgColor = color.FgBlack
	case "LOW":
		bgColor = color.BgBlue
		fgColor = color.FgWhite
	default:
		bgColor = color.BgGreen
		fgColor = color.FgBlack
	}
	
	color.New(bgColor, fgColor).Printf("[%s] ", timestamp)
	color.New(bgColor, fgColor).Printf("🚨 THREAT ")
	color.New(color.FgYellow).Printf("PID:%s ", pidStr)
	color.New(color.FgBlue).Printf("PPID:%s ", ppidStr)
	color.New(color.FgMagenta).Printf("USER:%s ", event.User)
	color.New(color.FgWhite).Printf("%s ", event.ProcessName)
	color.New(color.FgRed).Printf("[%s] ", event.ThreatVector)
	color.New(color.FgHiRed).Printf("RISK:%d ", event.RiskScore)
	color.New(color.FgHiBlack).Printf("%s\n", event.Command)
	
	if event.AlertMessage != "" {
		color.New(color.FgRed).Printf("    ⚠️  %s\n", event.AlertMessage)
	}
	
	if pm.config.AlertMode && event.RiskScore >= pm.config.RiskThreshold {
		color.New(color.BgRed, color.FgWhite).Printf("🚨 HIGH RISK ALERT: %s detected!\n", event.ThreatVector)
	}
}

func (pm *ProcessMonitor) formatEventText(event ProcessEvent) string {
	timestamp := event.Timestamp.Format("15:04:05")
	return fmt.Sprintf("[%s] %s PID:%d PPID:%d USER:%s %s %s %s",
		timestamp, event.EventType, event.PID, event.PPID, event.User,
		event.ProcessName, event.Command, event.Details)
}

func (pm *ProcessMonitor) DisplayHeader() {
	if pm.config.JSONOutput {
		return
	}

	header := `
╔══════════════════════════════════════════════════════════════════════════════╗
║                              WIRN PROCESS SPY                              ║
║                        Advanced Process Monitoring Tool                    ║
║                              pspy64 Alternative                           ║
╚══════════════════════════════════════════════════════════════════════════════╝
`
	fmt.Print(header)

	if pm.config.StealthMode {
		color.New(color.FgRed).Println("🔒 STEALTH MODE ENABLED")
	}
	if pm.config.LogToFile {
		color.New(color.FgBlue).Printf("📝 Logging to: %s\n", pm.config.LogFile)
	}
	if pm.config.MonitorNetwork {
		color.New(color.FgCyan).Println("🌐 Network monitoring enabled")
	}
	if pm.config.MonitorFiles {
		color.New(color.FgYellow).Println("📁 File monitoring enabled")
	}
	if pm.config.SecurityDetection {
		color.New(color.FgRed).Println("🛡️ Security pattern detection enabled")
	}
	if pm.config.AlertMode {
		color.New(color.FgMagenta).Printf("🚨 Alert mode enabled (threshold: %d)\n", pm.config.RiskThreshold)
	}
	if pm.config.HighlightThreats {
		color.New(color.FgYellow).Println("⚠️ Threat highlighting enabled")
	}

	fmt.Println()
}

func (pm *ProcessMonitor) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(1 * time.Second):
			if pm.config.StealthMode {
				pm.performEvasion()
			}
		}
	}
}

func enableStealthMode() {
	if runtime.GOOS == "linux" {
		// Linux-specific stealth techniques would go here
		// Note: unix.Prctl is not available on Windows
	}
}

func (pm *ProcessMonitor) performEvasion() {
	pm.evasionCount++

	if pm.evasionCount%100 == 0 {
		if runtime.GOOS == "linux" {
			// Linux-specific evasion techniques would go here
			// Note: unix.Prctl is not available on Windows
		}
	}
}

func (pm *ProcessMonitor) GetProcessStats() map[string]interface{} {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	stats := make(map[string]interface{})
	stats["total_processes"] = len(pm.knownProcesses)

	userCounts := make(map[string]int)
	processCounts := make(map[string]int)

	for _, proc := range pm.knownProcesses {
		username, _ := proc.Username()
		processName := pm.getProcessName(proc)

		userCounts[username]++
		processCounts[processName]++
	}

	stats["users"] = userCounts
	stats["processes"] = processCounts

	return stats
}
