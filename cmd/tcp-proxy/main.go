package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"

	proxy "github.com/jpillora/go-tcp-proxy"
)

var (
	version = "0.0.0-src"
	matchid = uint64(0)
	connid  = uint64(0)
	logger  proxy.ColorLogger

	localAddr   = flag.String("l", ":9999", "local address")
	remoteAddr  = flag.String("r", "localhost:80", "remote address")
	verbose     = flag.Bool("v", false, "display server actions")
	veryverbose = flag.Bool("vv", false, "display server actions and all tcp data")
	nagles      = flag.Bool("n", false, "disable nagles algorithm")
	hex         = flag.Bool("h", false, "output hex")
	colors      = flag.Bool("c", false, "output ansi colors")
	unwrapTLS   = flag.Bool("unwrap-tls", false, "remote connection with TLS exposed unencrypted locally")
	match       = flag.String("match", "", "match regex (in the form 'regex')")
	replace     = flag.String("replace", "", "replace regex (in the form 'regex~replacer')")
	whitelist   = flag.String("whitelist", os.Getenv("TCP_PROXY_IP_WHITELIST"), "IP whitelist (comma separated, supports CIDR, IPv4, IPv6)")
)

func main() {
	flag.Parse()

	logger := proxy.ColorLogger{
		Verbose: *verbose,
		Color:   *colors,
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
		if ipWhitelist != nil {
			if !ipWhitelist(clientIP) {
				logger.Warn("Connection rejected: IP %s not in whitelist", clientIP.String())
				conn.Close()
				continue
			}
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
			Prefix:      fmt.Sprintf("Connection #%03d ", connid),
			Color:       *colors,
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
