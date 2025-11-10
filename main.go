// Package main is the command-line tool that does DNS lookups using
// dnsproxy/upstream.  See README.md for more information.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/netutil/sysresolv"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

type jsonMsg struct {
	dns.Msg
	Elapsed time.Duration `json:"elapsed"`
}

type Flags struct {
	MachineReadable    string
	InsecureSkipVerify string
	TimeoutStr         string
	Http3Enabled       string
	Verbose            string
	Padding            string
	Do                 string
}

type SetFlags struct {
	MachineReadable    bool
	InsecureSkipVerify bool
	Timeout            int
	Http3Enabled       bool
	Verbose            bool
	Padding            bool
	Do                 bool
	Subnet             *dns.EDNS0_SUBNET
	EdnsOpt            *dns.EDNS0_LOCAL
	Question           dns.Question
	Server             string
}

// VersionString -- see the makefile
var VersionString = "master"

func main() {
	cmd := rootCommand()
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCommand() *cobra.Command {
	flags := Flags{}

	cmd := &cobra.Command{
		Use:   "dnslookup",
		Short: "A command-line tool for DNS lookups",
		Run: func(cmd *cobra.Command, args []string) {
			setFlags := getSetFlags(cmd, &flags)

			start(setFlags)
		},
	}

	return cmd
}

func getSetFlags(cmd *cobra.Command, flags *Flags) *SetFlags {
	machineReadable, err := cmd.Flags().GetBool("machine-readable")
	if err != nil {
		log.Fatalf("invalid boolean value for machine-readable: %s", err)
	}

	insecureSkipVerify, err := cmd.Flags().GetBool("insecure")
	if err != nil {
		log.Fatalf("invalid boolean value for insecure: %s", err)
	}

	timeout, err := cmd.Flags().GetInt("timeout")
	if err != nil {
		log.Fatalf("invalid integer value for timeout: %s", err)
	}

	http3Enabled, err := cmd.Flags().GetBool("http3")
	if err != nil {
		log.Fatalf("invalid boolean value for http3: %s", err)
	}

	verbose, err := cmd.Flags().GetBool("verbose")
	if err != nil {
		log.Fatalf("invalid boolean value for verbose: %s", err)
	}

	padding, err := cmd.Flags().GetBool("padding")
	if err != nil {
		log.Fatalf("invalid boolean value for padding: %s", err)
	}

	do, err := cmd.Flags().GetBool("do")
	if err != nil {
		log.Fatalf("invalid boolean value for do: %s", err)
	}

	subnetStr, err := cmd.Flags().GetString("subnet")
	if err != nil {
		log.Fatalf("invalid string value for subnet: %s", err)
	}

	ednsOptStr, err := cmd.Flags().GetString("edns-opt")
	if err != nil {
		log.Fatalf("invalid string value for edns-opt: %s", err)
	}

	domain, err := cmd.Flags().GetString("domain")
	if err != nil {
		log.Fatalf("invalid string value for domain: %s", err)
	}

	server, err := cmd.Flags().GetString("server")
	if err != nil {
		log.Fatalf("invalid string value for server: %s", err)
	}

	var subnetOpt *dns.EDNS0_SUBNET
	if subnetStr != "" {
		_, ipNet, err := net.ParseCIDR(subnetStr)
		if err != nil {
			log.Fatalf("invalid SUBNET %s: %v", subnetStr, err)
		}

		ones, _ := ipNet.Mask.Size()

		subnetOpt = &dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			Family:        1,
			SourceNetmask: uint8(ones),
			SourceScope:   0,
			Address:       ipNet.IP,
		}
	}

	var ednsOpt *dns.EDNS0_LOCAL
	if ednsOptStr != "" {
		parts := strings.Split(ednsOptStr, ":")
		code, err := strconv.Atoi(parts[0])
		if err != nil {
			log.Fatalf("invalid EDNSOPT %s: %v", ednsOptStr, err)
		}

		var value []byte
		if len(parts) > 1 {
			value, err = hex.DecodeString(parts[1])
			if err != nil {
				log.Fatalf("invalid EDNSOPT %s: %v", ednsOptStr, err)
			}
		}

		ednsOpt = &dns.EDNS0_LOCAL{
			Code: uint16(code),
			Data: value,
		}
	}

	rrTypeStr, err := cmd.Flags().GetString("type")
	if err != nil {
		log.Fatalf("invalid string value for type: %s", err)
	}

	classStr, err := cmd.Flags().GetString("class")
	if err != nil {
		log.Fatalf("invalid string value for class: %s", err)
	}

	var rrType uint16
	var ok bool
	rrType, ok = dns.StringToType[rrTypeStr]
	if !ok {
		if rrTypeStr != "" {
			log.Fatalf("Invalid RRTYPE: %q", rrTypeStr)
		}

		rrType = dns.TypeA
	}

	var qClass uint16
	qClass, ok = dns.StringToClass[classStr]
	if!ok {
		if classStr != "" {
			log.Fatalf("Invalid CLASS: %q", classStr)
		}

		qClass = dns.ClassINET
	}

	// If the user tries to query an IP address and does not specify any
	// query type, convert to PTR automatically.
	ip := net.ParseIP(domain)
	if rrTypeStr == "" && ip != nil {
		domain = ipToPtr(ip)
		rrType = dns.TypePTR
	}

	question := dns.Question{
		Name:  dns.Fqdn(domain),
		Qtype: rrType,
		Qclass: qClass,
	}

	return &SetFlags{
		MachineReadable:    machineReadable,
		InsecureSkipVerify: insecureSkipVerify,
		Timeout:            timeout,
		Http3Enabled:       http3Enabled,
		Verbose:            verbose,
		Padding:            padding,
		Do:                 do,
		Subnet:             subnetOpt,
		EdnsOpt:            ednsOpt,
		Question:           question,
		Server:             server,
	}
}

func start(flags *SetFlags) {
	if flags.Verbose {
		log.SetLevel(log.DEBUG)
	}

	if !flags.MachineReadable {
		_, _ = os.Stdout.WriteString(fmt.Sprintf("dnslookup %s\n", VersionString))
	}

	if flags.InsecureSkipVerify {
		_, _ = os.Stdout.WriteString("TLS verification has been disabled\n")
	}

	var server string
	if flags.Server != "" {
		server = flags.Server
	} else {
		sysr, err := sysresolv.NewSystemResolvers(nil, 53)
		if err != nil {
			log.Printf("Cannot get system resolvers: %v", err)
			os.Exit(1)
		}

		server = sysr.Addrs()[0].String()
	}

	var httpVersions []upstream.HTTPVersion
	if flags.Http3Enabled {
		httpVersions = []upstream.HTTPVersion{
			upstream.HTTPVersion3,
			upstream.HTTPVersion2,
			upstream.HTTPVersion11,
		}
	}

	opts := &upstream.Options{
		Timeout:            time.Duration(flags.Timeout) * time.Second,
		InsecureSkipVerify: flags.InsecureSkipVerify,
		HTTPVersions:       httpVersions,
	}

	u, err := upstream.AddressToUpstream(server, opts)
	if err != nil {
		log.Fatalf("Cannot create an upstream: %s", err)
	}

	req := &dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{flags.Question}

	if flags.Subnet != nil {
		opt := getOrCreateOpt(req, flags.Do)
		opt.Option = append(opt.Option, flags.Subnet)
	}

	if flags.EdnsOpt != nil {
		opt := getOrCreateOpt(req, flags.Do)
		opt.Option = append(opt.Option, flags.EdnsOpt)
	}

	if flags.Padding {
		opt := getOrCreateOpt(req, flags.Do)
		opt.Option = append(opt.Option, newEDNS0Padding(req))
	}

	startTime := time.Now()
	reply, err := u.Exchange(req)
	if err != nil {
		log.Fatalf("Cannot make the DNS request: %s", err)
	}

	if !flags.MachineReadable {
		msg := fmt.Sprintf("dnslookup result (elapsed %v):\n", time.Now().Sub(startTime))
		_, _ = os.Stdout.WriteString(fmt.Sprintf("Server: %s\n\n", server))
		_, _ = os.Stdout.WriteString(msg)
		_, _ = os.Stdout.WriteString(reply.String() + "\n")
	} else {
		// Prevent JSON parsing from skewing results
		endTime := time.Now()

		var JSONreply jsonMsg
		JSONreply.Msg = *reply
		JSONreply.Elapsed = endTime.Sub(startTime)

		var b []byte
		b, err = json.MarshalIndent(JSONreply, "", "  ")
		if err != nil {
			log.Fatalf("Cannotmarshal json: %s", err)
		}

		_, _ = os.Stdout.WriteString(string(b) + "\n")
	}
}

func init() {
	cmd := rootCommand()
	cmd.PersistentFlags().StringP("domain", "d", "", "domain name to lookup")
	_ = cmd.MarkPersistentFlagRequired("domain")
	cmd.PersistentFlags().StringP("server", "s", "", "server address. Supported: plain, tcp:// (TCP), tls:// (DOT), https:// (DOH), sdns:// (DNSCrypt), quic:// (DOQ)")
	cmd.PersistentFlags().String("type", "", "RR type (A, AAAA, PTR, etc.)")
	cmd.PersistentFlags().String("class", "", "RR class (INET, CH, HS)")
	cmd.PersistentFlags().String("subnet", "", "EDNS0 client subnet in 'ip/mask' format")
	cmd.PersistentFlags().String("edns-opt", "", "EDNS0 option in 'code:value' format (value is hex-encoded)")
	cmd.PersistentFlags().Bool("machine-readable", false, "output in JSON format")
	cmd.PersistentFlags().Bool("insecure", false, "skip TLS certificate verification")
	cmd.PersistentFlags().Int("timeout", 10, "timeout in seconds")
	cmd.PersistentFlags().Bool("http3", false, "enable HTTP/3 (for DoH)")
	cmd.PersistentFlags().BoolP("verbose", "v", false, "verbose output")
	cmd.PersistentFlags().Bool("padding", false, "enable EDNS0 padding")
	cmd.PersistentFlags().Bool("do", false, "set DNSSEC OK bit")

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func getOrCreateOpt(req *dns.Msg, do bool) (opt *dns.OPT) {
	opt = req.IsEdns0()
	if opt == nil {
		req.SetEdns0(udpBufferSize, do)
		opt = req.IsEdns0()
	}

	return opt
}

func getEDNSOpt() (option *dns.EDNS0_LOCAL) {
	ednsOpt := os.Getenv("EDNSOPT")
	if ednsOpt == "" {
		return nil
	}

	parts := strings.Split(ednsOpt, ":")
	code, err := strconv.Atoi(parts[0])
	if err != nil {
		log.Printf("invalid EDNSOPT %s: %v", ednsOpt, err)
		usage()

		os.Exit(1)
	}

	var value []byte
	if len(parts) > 1 {
		value, err = hex.DecodeString(parts[1])
		if err != nil {
			log.Printf("invalid EDNSOPT %s: %v", ednsOpt, err)
			usage()

			os.Exit(1)
		}
	}

	return &dns.EDNS0_LOCAL{
		Code: uint16(code),
		Data: value,
	}
}

// getQuestion returns a DNS question for the query.
func getQuestion() (q dns.Question) {
	domain := os.Args[1]
	rrType := getRRType()
	qClass := getClass()

	// If the user tries to query an IP address and does not specify any
	// query type, convert to PTR automatically.
	ip := net.ParseIP(domain)
	if os.Getenv("RRTYPE") == "" && ip != nil {
		domain = ipToPtr(ip)
		rrType = dns.TypePTR
	}

	q.Name = dns.Fqdn(domain)
	q.Qtype = rrType
	q.Qclass = qClass

	return q
}

func ipToPtr(ip net.IP) (ptr string) {
	if ip.To4() != nil {
		return ip4ToPtr(ip)
	}

	return ip6ToPtr(ip)
}

func ip4ToPtr(ip net.IP) (ptr string) {
	parts := strings.Split(ip.String(), ".")
	for i := range parts {
		ptr = parts[i] + "." + ptr
	}
	ptr = ptr + "in-addr.arpa."

	return
}

func ip6ToPtr(ip net.IP) (ptr string) {
	addr, _ := netip.ParseAddr(ip.String())
	str := addr.StringExpanded()

	// Remove colons and reverse the order of characters.
	str = strings.ReplaceAll(str, ":", "")
	reversed := ""
	for i := len(str) - 1; i >= 0; i-- {
		reversed += string(str[i])
		if i != 0 {
			reversed += "."
		}
	}

	ptr = reversed + ".ip6.arpa."

	return ptr
}

func getSubnet() (option *dns.EDNS0_SUBNET) {
	subnetStr := os.Getenv("SUBNET")
	if subnetStr == "" {
		return nil
	}

	_, ipNet, err := net.ParseCIDR(subnetStr)
	if err != nil {
		log.Printf("invalid SUBNET %s: %v", subnetStr, err)
		usage()

		os.Exit(1)
	}

	ones, _ := ipNet.Mask.Size()

	return &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,
		SourceNetmask: uint8(ones),
		SourceScope:   0,
		Address:       ipNet.IP,
	}
}

func getClass() (class uint16) {
	classStr := os.Getenv("CLASS")
	var ok bool
	class, ok = dns.StringToClass[classStr]
	if !ok {
		if classStr != "" {
			log.Printf("Invalid CLASS: %q", classStr)
			usage()

			os.Exit(1)
		}

		class = dns.ClassINET
	}
	return class
}

func getRRType() (rrType uint16) {
	rrTypeStr := os.Getenv("RRTYPE")
	var ok bool
	rrType, ok = dns.StringToType[rrTypeStr]
	if !ok {
		if rrTypeStr != "" {
			log.Printf("Invalid RRTYPE: %q", rrTypeStr)
			usage()

			os.Exit(1)
		}

		rrType = dns.TypeA
	}
	return rrType
}

func usage() {
	_, _ = os.Stdout.WriteString("Usage: dnslookup <domain> <server> [<providerName> <serverPk>]\n")
	_, _ = os.Stdout.WriteString("<domain>: mandatory, domain name to lookup\n")
	_, _ = os.Stdout.WriteString("<server>: mandatory, server address. Supported: plain, tcp:// (TCP), tls:// (DOT), https:// (DOH), sdns:// (DNSCrypt), quic:// (DOQ)\n")
	_, _ = os.Stdout.WriteString("<providerName>: optional, DNSCrypt provider name\n")
	_, _ = os.Stdout.WriteString("<serverPk>: optional, DNSCrypt server public key\n")
}

// requestPaddingBlockSize is used to pad responses over DoT and DoH according
// to RFC 8467.
const requestPaddingBlockSize = 128
const udpBufferSize = dns.DefaultMsgSize

// newEDNS0Padding constructs a new OPT RR EDNS0 Padding for the extra section.
func newEDNS0Padding(req *dns.Msg) (option *dns.EDNS0_PADDING) {
	msgLen := req.Len()
	padLen := requestPaddingBlockSize - msgLen%requestPaddingBlockSize

	// Truncate padding to fit in UDP buffer.
	if msgLen+padLen > udpBufferSize {
		padLen = udpBufferSize - msgLen
		if padLen < 0 {
			padLen = 0
		}
	}

	return &dns.EDNS0_PADDING{Padding: make([]byte, padLen)}
}

// singleIPResolver represents a resolver that resolves a single IP address.
// This type implements the upstream.Resolver interface.
type singleIPResolver struct {
	ip net.IP
}

// type check
var _ upstream.Resolver = (*singleIPResolver)(nil)

// LookupNetIP implements the upstream.Resolver interface for *singleIPResolver.
func (s *singleIPResolver) LookupNetIP(_ context.Context, _ string, _ string) (addrs []netip.Addr, err error) {
	ip, ok := netip.AddrFromSlice(s.ip)

	if !ok {
		return nil, fmt.Errorf("invalid IP: %s", s.ip)
	}

	return []netip.Addr{ip}, nil
}
