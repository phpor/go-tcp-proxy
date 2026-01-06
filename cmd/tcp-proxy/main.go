package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	proxy "github.com/jpillora/go-tcp-proxy"
)

var (
	version = "0.0.0-src"
	matchid = uint64(0)
	connid  = uint64(0)
	logger  proxy.ColorLogger

	localAddr       = flag.String("l", ":9999", "local address")
	remoteAddr      = flag.String("r", "localhost:80", "remote address")
	verbose         = flag.Bool("v", false, "display server actions")
	veryverbose     = flag.Bool("vv", false, "display server actions and all tcp data")
	nagles          = flag.Bool("n", false, "disable nagles algorithm")
	hex             = flag.Bool("h", false, "output hex")
	colors          = flag.Bool("c", false, "output ansi colors")
	unwrapTLS       = flag.Bool("unwrap-tls", false, "remote connection with TLS exposed unencrypted locally")
	match           = flag.String("match", "", "match regex (in the form 'regex')")
	replace         = flag.String("replace", "", "replace regex (in the form 'regex~replacer')")
	whitelist       = flag.String("whitelist", os.Getenv("TCP_PROXY_IP_WHITELIST"), "IP whitelist (comma separated, supports CIDR, IPv4, IPv6)")
	ipWhitelistFile = flag.String("ip-whitelist-file", os.Getenv("TCP_PROXY_IP_WHITELIST_FILE"), "IP whitelist file path (one IP/CIDR per line)")
)

// IPWhitelistManager 管理IP白名单的加载和检查
type IPWhitelistManager struct {
	mu          sync.RWMutex
	networks    []*net.IPNet
	exactIPs    []net.IP
	filePath    string
	logger      proxy.Logger
	watcher     *fsnotify.Watcher
	watcherDone chan struct{}
	watching    bool
}

// NewIPWhitelistManager 创建新的IP白名单管理器
func NewIPWhitelistManager(filePath string, logger proxy.Logger) *IPWhitelistManager {
	return &IPWhitelistManager{
		filePath: filePath,
		logger:   logger,
	}
}

// LoadFromFile 从文件加载IP白名单
func (wm *IPWhitelistManager) LoadFromFile() error {
	if wm.filePath == "" {
		return nil
	}

	// 添加重试机制，处理文件暂时不存在的情况
	var file *os.File
	var err error
	for i := 0; i < 5; i++ {
		file, err = os.Open(wm.filePath)
		if err == nil {
			break
		}
		if i < 4 {
			time.Sleep(100 * time.Millisecond)
		}
	}

	if err != nil {
		return fmt.Errorf("failed to open whitelist file: %w", err)
	}
	defer file.Close()

	var networks []*net.IPNet
	var exactIPs []net.IP

	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 尝试解析为CIDR
		if strings.Contains(line, "/") {
			_, ipNet, err := net.ParseCIDR(line)
			if err != nil {
				wm.logger.Warn("Invalid CIDR at line %d: %s, error: %s", lineNum, line, err)
				continue
			}
			networks = append(networks, ipNet)
		} else {
			// 尝试解析为单个IP
			ip := net.ParseIP(line)
			if ip == nil {
				wm.logger.Warn("Invalid IP address at line %d: %s", lineNum, line)
				continue
			}
			exactIPs = append(exactIPs, ip)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading whitelist file: %w", err)
	}

	wm.mu.Lock()
	defer wm.mu.Unlock()
	wm.networks = networks
	wm.exactIPs = exactIPs

	wm.logger.Info("IP whitelist loaded from file: %d networks and %d exact IPs", len(networks), len(exactIPs))
	return nil
}

// IsAllowed 检查IP是否在白名单中
func (wm *IPWhitelistManager) IsAllowed(clientIP net.IP) bool {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	// 检查精确匹配
	for _, ip := range wm.exactIPs {
		if ip.Equal(clientIP) {
			return true
		}
	}

	// 检查CIDR匹配
	for _, network := range wm.networks {
		if network.Contains(clientIP) {
			return true
		}
	}

	return false
}

// StartFileWatcher 启动文件监控，在文件变化时自动重新加载白名单
// 只在 Linux 系统上启用此功能
func (wm *IPWhitelistManager) StartFileWatcher() error {
	if wm.filePath == "" {
		return fmt.Errorf("no file path configured")
	}

	// 只在 Linux 上启用文件监控
	if runtime.GOOS != "linux" {
		wm.logger.Info("File watching is only supported on Linux, current OS: %s", runtime.GOOS)
		return nil
	}

	if wm.watching {
		return fmt.Errorf("file watcher is already running")
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}

	// 监控文件所在目录
	dir := filepath.Dir(wm.filePath)
	if err := watcher.Add(dir); err != nil {
		watcher.Close()
		return fmt.Errorf("failed to watch directory %s: %w", dir, err)
	}

	// 监控文件本身
	if err := watcher.Add(wm.filePath); err != nil {
		watcher.Close()
		return fmt.Errorf("failed to watch file %s: %w", wm.filePath, err)
	}

	wm.watcher = watcher
	wm.watcherDone = make(chan struct{})
	wm.watching = true

	go func() {
		defer close(wm.watcherDone)

		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}

				// 检查是否是我们监控的文件或目录中的文件
				if event.Name == wm.filePath || event.Name == filepath.Dir(wm.filePath) {

					// 处理文件删除和重新创建的情况
					if event.Op&fsnotify.Remove == fsnotify.Remove && event.Name == wm.filePath {
						wm.logger.Info("IP whitelist file was removed, waiting for recreation...")
						// 文件被删除，我们需要等待它被重新创建
						continue
					}

					// 处理文件创建或重命名的情况
					if (event.Op&fsnotify.Create == fsnotify.Create || event.Op&fsnotify.Rename == fsnotify.Rename) && event.Name == wm.filePath {
						wm.logger.Info("IP whitelist file was created/renamed, re-adding to watcher...")
						// 重新添加文件到监控器
						if err := watcher.Add(wm.filePath); err != nil {
							wm.logger.Warn("Failed to re-add file to watcher: %s", err)
						}
						// 延迟一下再加载，确保文件写入完成
						time.Sleep(100 * time.Millisecond)
						wm.logger.Info("IP whitelist file changed, reloading...")
						if err := wm.LoadFromFile(); err != nil {
							wm.logger.Warn("Failed to reload IP whitelist file: %s", err)
						} else {
							wm.logger.Info("IP whitelist file reloaded successfully")
						}
						continue
					}

					// 处理文件写入和权限变更的情况
					if event.Op&fsnotify.Write == fsnotify.Write ||
						event.Op&fsnotify.Chmod == fsnotify.Chmod {

						// 检查是否是我们监控的文件
						if event.Name == wm.filePath {
							// 延迟一下再加载，确保文件写入完成
							time.Sleep(100 * time.Millisecond)
							wm.logger.Info("IP whitelist file changed, reloading...")
							if err := wm.LoadFromFile(); err != nil {
								wm.logger.Warn("Failed to reload IP whitelist file: %s", err)
							} else {
								wm.logger.Info("IP whitelist file reloaded successfully")
							}
						}
					}
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				wm.logger.Warn("File watcher error: %s", err)

			case <-wm.watcherDone:
				return
			}
		}
	}()

	wm.logger.Info("File watcher started for: %s", wm.filePath)
	return nil
}

// StopFileWatcher 停止文件监控
func (wm *IPWhitelistManager) StopFileWatcher() error {
	if !wm.watching {
		return nil
	}

	if wm.watcherDone != nil {
		close(wm.watcherDone)
	}

	if wm.watcher != nil {
		if err := wm.watcher.Close(); err != nil {
			return fmt.Errorf("failed to close file watcher: %w", err)
		}
	}

	wm.watching = false
	wm.watcher = nil
	wm.watcherDone = nil

	wm.logger.Info("File watcher stopped")
	return nil
}

func main() {
	flag.Parse()

	logger = proxy.ColorLogger{
		Verbose: *verbose,
		Color:   *colors,
		Prefix: func() string {
			return fmt.Sprintf("[%s] ", time.Now().Format("2006-01-02 15:04:05"))
		},
	}

	logger.Info("go-tcp-proxy (%s) proxing from %v to %v ", version, *localAddr, *remoteAddr)

	laddr, err := net.ResolveTCPAddr("tcp", *localAddr)
	if err != nil {
		logger.Warn("Failed to resolve local address: %s", err)
		os.Exit(1)
	}
	raddr, err := net.ResolveTCPAddr("tcp", *remoteAddr)
	if err != nil {
		logger.Warn("Failed to resolve remote address: %s", err)
		os.Exit(1)
	}
	listener, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		logger.Warn("Failed to open local port to listen: %s", err)
		os.Exit(1)
	}

	matcher := createMatcher(*match)
	replacer := createReplacer(*replace)
	ipWhitelist := createIPWhitelist(*whitelist)

	// 初始化IP白名单文件管理器
	var ipWhitelistManager *IPWhitelistManager
	if *ipWhitelistFile != "" {
		ipWhitelistManager = NewIPWhitelistManager(*ipWhitelistFile, logger)
		// 启动时自动加载白名单文件
		if err := ipWhitelistManager.LoadFromFile(); err != nil {
			logger.Warn("Failed to load IP whitelist file: %s", err)
		}
		// 启动文件监控
		if err := ipWhitelistManager.StartFileWatcher(); err != nil {
			logger.Warn("Failed to start file watcher: %s", err)
		}
	}

	// 设置信号处理，用于重新加载白名单文件
	setupSignalHandler(ipWhitelistManager, logger)

	if *veryverbose {
		*verbose = true
	}
	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			logger.Warn("Failed to accept connection '%s'", err)
			continue
		}

		// 获取客户端IP地址
		clientAddr := conn.RemoteAddr().String()
		clientIP := net.ParseIP(strings.Split(clientAddr, ":")[0])
		if clientIP == nil {
			logger.Warn("Failed to parse client IP address: %s", clientAddr)
			conn.Close()
			continue
		}

		// 检查IP白名单
		// 检查IP白名单
		allowed := false
		if ipWhitelistManager != nil {
			allowed = ipWhitelistManager.IsAllowed(clientIP)
		} else if ipWhitelist != nil {
			allowed = ipWhitelist(clientIP)
		} else {
			allowed = true // 如果没有配置白名单，允许所有连接
		}

		if !allowed {
			logger.Warn("Connection rejected: IP %s not in whitelist", clientIP.String())
			conn.Close()
			continue
		}
		connid++

		var p *proxy.Proxy
		if *unwrapTLS {
			logger.Info("Unwrapping TLS")
			p = proxy.NewTLSUnwrapped(conn, laddr, raddr, *remoteAddr)
		} else {
			p = proxy.New(conn, laddr, raddr)
		}

		p.Matcher = matcher
		p.Replacer = replacer

		p.Nagles = *nagles
		p.OutputHex = *hex
		p.Log = proxy.ColorLogger{
			Verbose:     *verbose,
			VeryVerbose: *veryverbose,
			Prefix: func() string {
				return fmt.Sprintf("[%s] Connection #%03d ", time.Now().Format("2006-01-02 15:04:05"), connid)
			},
			Color: *colors,
		}

		go p.Start()
	}
}

func createMatcher(match string) func([]byte) {
	if match == "" {
		return nil
	}
	re, err := regexp.Compile(match)
	if err != nil {
		logger.Warn("Invalid match regex: %s", err)
		return nil
	}

	logger.Info("Matching %s", re.String())
	return func(input []byte) {
		ms := re.FindAll(input, -1)
		for _, m := range ms {
			matchid++
			logger.Info("Match #%d: %s", matchid, string(m))
		}
	}
}

func createReplacer(replace string) func([]byte) []byte {
	if replace == "" {
		return nil
	}
	//split by / (TODO: allow slash escapes)
	parts := strings.Split(replace, "~")
	if len(parts) != 2 {
		logger.Warn("Invalid replace option")
		return nil
	}

	re, err := regexp.Compile(string(parts[0]))
	if err != nil {
		logger.Warn("Invalid replace regex: %s", err)
		return nil
	}

	repl := []byte(parts[1])

	logger.Info("Replacing %s with %s", re.String(), repl)
	return func(input []byte) []byte {
		return re.ReplaceAll(input, repl)
	}
}

// setupSignalHandler 设置信号处理器，用于重新加载白名单文件和优雅退出
func setupSignalHandler(ipWhitelistManager *IPWhitelistManager, logger proxy.Logger) {
	if ipWhitelistManager == nil {
		return
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for sig := range sigChan {
			switch sig {
			case syscall.SIGHUP:
				logger.Info("Received SIGHUP signal, reloading IP whitelist file...")
				if err := ipWhitelistManager.LoadFromFile(); err != nil {
					logger.Warn("Failed to reload IP whitelist file: %s", err)
				} else {
					logger.Info("IP whitelist file reloaded successfully")
				}
			case syscall.SIGINT, syscall.SIGTERM:
				logger.Info("Received %s signal, stopping file watcher and exiting...", sig)
				if err := ipWhitelistManager.StopFileWatcher(); err != nil {
					logger.Warn("Failed to stop file watcher: %s", err)
				}
				os.Exit(0)
			}
		}
	}()

	logger.Info("Signal handler setup complete. Send SIGHUP to reload IP whitelist file, SIGINT/SIGTERM to exit")
}

func createIPWhitelist(whitelist string) func(net.IP) bool {
	if whitelist == "" {
		return nil
	}

	ips := strings.Split(whitelist, ",")
	var networks []*net.IPNet
	var exactIPs []net.IP

	for _, ipStr := range ips {
		ipStr = strings.TrimSpace(ipStr)
		if ipStr == "" {
			continue
		}

		// 尝试解析为CIDR
		if strings.Contains(ipStr, "/") {
			_, ipNet, err := net.ParseCIDR(ipStr)
			if err != nil {
				logger.Warn("Invalid CIDR %s: %s", ipStr, err)
				continue
			}
			networks = append(networks, ipNet)
		} else {
			// 尝试解析为单个IP
			ip := net.ParseIP(ipStr)
			if ip == nil {
				logger.Warn("Invalid IP address %s", ipStr)
				continue
			}
			exactIPs = append(exactIPs, ip)
		}
	}

	logger.Info("IP whitelist configured with %d networks and %d exact IPs", len(networks), len(exactIPs))

	return func(clientIP net.IP) bool {
		// 检查精确匹配
		for _, ip := range exactIPs {
			if ip.Equal(clientIP) {
				return true
			}
		}

		// 检查CIDR匹配
		for _, network := range networks {
			if network.Contains(clientIP) {
				return true
			}
		}

		return false
	}
}
