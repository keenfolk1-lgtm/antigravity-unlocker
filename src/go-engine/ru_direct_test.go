package main

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"strings"
	"testing"
)

func TestRUDirectSmartPACFailClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		setupCfg  func() *EngineConfig
		proxyHost string
		wantChain string
	}{
		{
			name: "default config merges RU ecosystem domains and omits DIRECT fallback",
			setupCfg: func() *EngineConfig {
				cfg := DefaultEngineConfig()
				cfg.DirectDomains = append(cfg.DirectDomains, "VK.COM", "userapi.com", "custom-direct.example")
				cfg.RebuildEffectiveRules()
				return cfg
			},
			proxyHost: "127.0.0.1",
			wantChain: "PROXY 127.0.0.1:17890; SOCKS5 127.0.0.1:17891",
		},
		{
			name: "nil config still produces valid arrays and fail-closed chain",
			setupCfg: func() *EngineConfig {
				return nil
			},
			proxyHost: "",
			wantChain: "PROXY 127.0.0.1:17890; SOCKS5 127.0.0.1:17891",
		},
		{
			name: "custom ports and WSL host fail-closed",
			setupCfg: func() *EngineConfig {
				cfg := DefaultEngineConfig()
				cfg.HTTPPort = 27890
				cfg.SOCKSPort = 27891
				cfg.RebuildEffectiveRules()
				return cfg
			},
			proxyHost: "172.20.0.1",
			wantChain: "PROXY 172.20.0.1:27890; SOCKS5 172.20.0.1:27891",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := tt.setupCfg()
			var origDirect []string
			if cfg != nil {
				origDirect = append([]string(nil), cfg.DirectDomains...)
			}

			pac := GenerateSmartPACJS(cfg, tt.proxyHost)

			if cfg != nil {
				if len(cfg.DirectDomains) != len(origDirect) {
					t.Fatalf("GenerateSmartPACJS mutated cfg.DirectDomains len: got %d, want %d", len(cfg.DirectDomains), len(origDirect))
				}
				for i := range origDirect {
					if cfg.DirectDomains[i] != origDirect[i] {
						t.Fatalf("GenerateSmartPACJS mutated cfg.DirectDomains[%d]: got %q, want %q", i, cfg.DirectDomains[i], origDirect[i])
					}
				}
			}

			if strings.Contains(pac, "dnsResolve") {
				t.Fatalf("PAC must never contain dnsResolve")
			}
			if !strings.Contains(pac, tt.wantChain) {
				t.Fatalf("PAC missing expected chain %q", tt.wantChain)
			}
			if strings.Contains(pac, tt.wantChain+"; DIRECT") {
				t.Fatalf("PAC must not fall back to DIRECT in PROXY_CHAIN")
			}

			directRules := extractPACJSONArray(t, pac, "var DIRECT_RULES = ")
			proxyRules := extractPACJSONArray(t, pac, "var PROXY_RULES = ")
			if proxyRules == nil {
				t.Fatalf("PROXY_RULES must be a JSON array, not null")
			}

			seen := make(map[string]int, len(directRules))
			for _, d := range directRules {
				seen[d]++
				if seen[d] > 1 {
					t.Fatalf("duplicate domain %q in PAC DIRECT_RULES", d)
				}
			}
			for _, ruDom := range RUEcosystemDomains {
				norm := normalizeDomainPattern(ruDom)
				if seen[norm] != 1 {
					t.Fatalf("RU ecosystem domain %q expected once in DIRECT_RULES, count=%d", norm, seen[norm])
				}
			}
		})
	}
}

func extractPACJSONArray(t *testing.T, pac, prefix string) []string {
	t.Helper()
	idx := strings.Index(pac, prefix)
	if idx < 0 {
		t.Fatalf("PAC missing prefix %q", prefix)
	}
	rest := pac[idx+len(prefix):]
	end := strings.Index(rest, ";\n")
	if end < 0 {
		t.Fatalf("PAC missing terminator after %q", prefix)
	}
	var out []string
	if err := json.Unmarshal([]byte(rest[:end]), &out); err != nil {
		t.Fatalf("unmarshal %q: %v (raw=%s)", prefix, err, rest[:end])
	}
	return out
}

func TestRUEcosystemDomain(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		host string
		want bool
	}{
		{name: "exact userapi.com", host: "userapi.com", want: true},
		{name: "subdomain userapi.com", host: "sun9-12.userapi.com", want: true},
		{name: "uppercase port trailing dot yastatic", host: "CDN.YASTATIC.NET:443.", want: true},
		{name: "yandexcloud subdomain", host: "storage.yandexcloud.net", want: true},
		{name: "yandex.net", host: "mc.yandex.net", want: true},
		{name: "ozonusercontent", host: "ir.ozonusercontent.com", want: true},
		{name: "ozon.com", host: "www.ozon.com", want: true},
		{name: "wbstatic.net", host: "basket-01.wbstatic.net", want: true},
		{name: "kinescope.io", host: "kinescope.io", want: true},
		{name: "2gis.com", host: "map.2gis.com", want: true},
		{name: "timeweb.cloud", host: "api.timeweb.cloud", want: true},
		{name: "selectel.org", host: "selectel.org", want: true},
		{name: "rutube.me", host: "rutube.me", want: true},
		{name: "vkvideo.ru", host: "vkvideo.ru", want: true},
		{name: "sberdevices.ru", host: "sberdevices.ru", want: true},
		{name: "tinkoff.com", host: "id.tinkoff.com", want: true},
		{name: "alfa.me", host: "alfa.me", want: true},
		{name: "ok.me", host: "ok.me", want: true},
		{name: "mail.ua", host: "e.mail.ua", want: true},
		{name: "cloud.mts.ru", host: "console.cloud.mts.ru", want: true},
		{name: "rt.ru", host: "lk.rt.ru", want: true},
		{name: "mycdn.me", host: "i.mycdn.me", want: true},
		{name: "vkuseraudio.net", host: "cs1.vkuseraudio.net", want: true},
		{name: "vkuservideo.net", host: "vd1.vkuservideo.net", want: true},
		{name: "vk-cdn.net", host: "cdn.vk-cdn.net", want: true},
		{name: "ru TLD", host: "gosuslugi.ru", want: true},
		{name: "punycode rf TLD", host: "xn--d1abbgf6aiiy.xn--p1ai", want: true},
		{name: "utf8 rf TLD", host: "президент.рф", want: true},
		{name: "su TLD", host: "lenta.su", want: true},
		{name: "by TLD", host: "onliner.by", want: true},
		{name: "suffix spoof userapi", host: "eviluserapi.com", want: false},
		{name: "suffix spoof ozon", host: "amazon.com", want: false},
		{name: "empty host", host: "", want: false},
		{name: "bare dot ru", host: ".ru", want: false},
		{name: "anthropic API", host: "api.anthropic.com", want: false},
		{name: "claude.ai", host: "claude.ai", want: false},
		{name: "chatgpt.com", host: "chatgpt.com", want: false},
		{name: "github.com", host: "api.github.com", want: false},
		{name: "google.com", host: "gemini.google.com", want: false},
		{name: "ipv4 literal", host: "77.88.55.55", want: false},
		{name: "ipv6 loopback literal", host: "[::1]:443", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsRUEcosystemDomain(tt.host); got != tt.want {
				t.Fatalf("IsRUEcosystemDomain(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestRUIPv4RangesInvariant(t *testing.T) {
	t.Parallel()

	if len(ruIPv4Ranges) < 33 {
		t.Fatalf("expected at least 33 RU IPv4 CIDR ranges, got %d", len(ruIPv4Ranges))
	}

	for i, r := range ruIPv4Ranges {
		if r.start > r.end {
			t.Fatalf("ruIPv4Ranges[%d] inverted: start=%#x > end=%#x", i, r.start, r.end)
		}
		if i > 0 && ruIPv4Ranges[i-1].end >= r.start {
			t.Fatalf("ruIPv4Ranges[%d] overlaps or is unsorted relative to [%d]: prevEnd=%#x curStart=%#x",
				i, i-1, ruIPv4Ranges[i-1].end, r.start)
		}
	}

	// Verify none of the critical proxy/DNS/AI CIDRs overlap ruIPv4Ranges.
	excludedCIDRs := []string{
		"185.103.103.162/32", // PixelTunnel cluster edge
		"201.34.152.97/32",   // Cluster host
		"147.45.135.71/32",   // Cluster host
		"1.1.1.1/32",         // Cloudflare DNS
		"104.16.0.0/12",      // Cloudflare
		"172.64.0.0/13",      // Cloudflare / OpenAI edge
		"8.8.8.8/32",         // Google DNS
		"142.250.0.0/15",     // Google
		"9.9.9.9/32",         // Quad9
		"160.79.104.0/23",    // Anthropic
		"23.98.142.176/28",   // OpenAI
	}
	for _, rawCIDR := range excludedCIDRs {
		_, netCIDR, err := net.ParseCIDR(rawCIDR)
		if err != nil {
			t.Fatalf("parse excluded CIDR %q: %v", rawCIDR, err)
		}
		ones, bits := netCIDR.Mask.Size()
		if bits != 32 {
			t.Fatalf("unexpected bits %d for %s", bits, rawCIDR)
		}
		exStart := binary.BigEndian.Uint32(netCIDR.IP.To4())
		var mask uint32
		if ones > 0 {
			mask = ^uint32(0) << (32 - ones)
		}
		exEnd := exStart | ^mask

		for i, r := range ruIPv4Ranges {
			if r.start <= exEnd && exStart <= r.end {
				t.Fatalf("ruIPv4Ranges[%d] (%#x..%#x) overlaps excluded CIDR %s (%#x..%#x)",
					i, r.start, r.end, rawCIDR, exStart, exEnd)
			}
		}
	}
}

func TestRUIsRussianIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ip   net.IP
		want bool
	}{
		// Yandex
		{name: "Yandex 5.45.192.1", ip: net.ParseIP("5.45.192.1"), want: true},
		{name: "Yandex 5.255.192.1", ip: net.ParseIP("5.255.192.1"), want: true},
		{name: "Yandex 77.88.55.55", ip: net.ParseIP("77.88.55.55"), want: true},
		{name: "Yandex 87.250.250.242", ip: net.ParseIP("87.250.250.242"), want: true},
		{name: "Yandex 93.158.134.3", ip: net.ParseIP("93.158.134.3"), want: true},
		{name: "Yandex 213.180.204.62", ip: net.ParseIP("213.180.204.62"), want: true},

		// VK
		{name: "VK 95.163.10.1", ip: net.ParseIP("95.163.10.1"), want: true},
		{name: "VK 185.16.148.10", ip: net.ParseIP("185.16.148.10"), want: true},
		{name: "VK 217.20.147.94", ip: net.ParseIP("217.20.147.94"), want: true},

		// Sber
		{name: "Sber 194.186.10.1", ip: net.ParseIP("194.186.10.1"), want: true},
		{name: "Sber 185.157.96.1", ip: net.ParseIP("185.157.96.1"), want: true},

		// Rostelecom
		{name: "Rostelecom 78.36.0.1", ip: net.ParseIP("78.36.0.1"), want: true},
		{name: "Rostelecom 85.140.10.1", ip: net.ParseIP("85.140.10.1"), want: true},
		{name: "Rostelecom 95.167.10.1", ip: net.ParseIP("95.167.10.1"), want: true},
		{name: "Rostelecom 109.184.10.1", ip: net.ParseIP("109.184.10.1"), want: true},
		{name: "Rostelecom 178.44.10.1", ip: net.ParseIP("178.44.10.1"), want: true},
		{name: "Rostelecom 188.168.10.1", ip: net.ParseIP("188.168.10.1"), want: true},
		{name: "Rostelecom 212.164.10.1", ip: net.ParseIP("212.164.10.1"), want: true},

		// MTS
		{name: "MTS 91.76.10.1", ip: net.ParseIP("91.76.10.1"), want: true},
		{name: "MTS 95.24.10.1", ip: net.ParseIP("95.24.10.1"), want: true},
		{name: "MTS 176.99.10.1", ip: net.ParseIP("176.99.10.1"), want: true},
		{name: "MTS 213.87.10.1", ip: net.ParseIP("213.87.10.1"), want: true},

		// Megafon
		{name: "Megafon 31.173.10.1", ip: net.ParseIP("31.173.10.1"), want: true},
		{name: "Megafon 83.149.10.1", ip: net.ParseIP("83.149.10.1"), want: true},
		{name: "Megafon 85.26.10.1", ip: net.ParseIP("85.26.10.1"), want: true},
		{name: "Megafon 178.176.10.1", ip: net.ParseIP("178.176.10.1"), want: true},

		// Beeline, Tele2, ER-Telecom, Selectel
		{name: "Beeline 89.178.10.1", ip: net.ParseIP("89.178.10.1"), want: true},
		{name: "Beeline 128.68.10.1", ip: net.ParseIP("128.68.10.1"), want: true},
		{name: "Tele2 176.59.10.1", ip: net.ParseIP("176.59.10.1"), want: true},
		{name: "ER-Telecom 109.194.10.1", ip: net.ParseIP("109.194.10.1"), want: true},
		{name: "ER-Telecom 188.232.10.1", ip: net.ParseIP("188.232.10.1"), want: true},
		{name: "Selectel 92.53.64.1", ip: net.ParseIP("92.53.64.1"), want: true},
		{name: "Selectel 188.93.16.1", ip: net.ParseIP("188.93.16.1"), want: true},

		// Boundary checks & IPv4-mapped IPv6
		{name: "range start boundary", ip: net.ParseIP("77.88.0.0"), want: true},
		{name: "range end boundary", ip: net.ParseIP("77.88.63.255"), want: true},
		{name: "IPv4-mapped IPv6 Yandex", ip: net.ParseIP("::ffff:77.88.55.55"), want: true},
		{name: "just before Yandex 77.88.0.0/18", ip: net.ParseIP("77.87.255.255"), want: false},
		{name: "just after Yandex 77.88.0.0/18", ip: net.ParseIP("77.88.64.0"), want: false},

		// Non-Russian / Critical exclusions
		{name: "PixelTunnel edge 185.103.103.162", ip: net.ParseIP("185.103.103.162"), want: false},
		{name: "Cloudflare 1.1.1.1", ip: net.ParseIP("1.1.1.1"), want: false},
		{name: "Google DNS 8.8.8.8", ip: net.ParseIP("8.8.8.8"), want: false},
		{name: "Quad9 9.9.9.9", ip: net.ParseIP("9.9.9.9"), want: false},
		{name: "Cloudflare 104.18.10.1", ip: net.ParseIP("104.18.10.1"), want: false},
		{name: "Anthropic 160.79.104.10", ip: net.ParseIP("160.79.104.10"), want: false},
		{name: "Google 142.250.74.14", ip: net.ParseIP("142.250.74.14"), want: false},
		{name: "Cloudflare/OpenAI 172.64.155.1", ip: net.ParseIP("172.64.155.1"), want: false},
		{name: "Loopback 127.0.0.1", ip: net.ParseIP("127.0.0.1"), want: false},
		{name: "Private 192.168.1.1", ip: net.ParseIP("192.168.1.1"), want: false},
		{name: "Pure IPv6 Google DNS", ip: net.ParseIP("2001:4860:4860::8888"), want: false},
		{name: "Nil IP", ip: nil, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsRussianIP(tt.ip); got != tt.want {
				t.Fatalf("IsRussianIP(%v) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}
