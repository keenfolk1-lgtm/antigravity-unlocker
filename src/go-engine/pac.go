package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// GenerateSmartPACJS generates a zero-DNS Smart PAC script with ZERO dnsResolve() calls.
// Matching rules:
//   - .ru, .рф (.xn--p1ai), .su, .by, RU ecosystem domains, localhost, private CIDRs, direct list -> DIRECT
//   - enabled proxy categories & custom proxy list (or proxy_all) -> PROXY <host>:<http>; SOCKS5 <host>:<socks>
func GenerateSmartPACJS(cfg *EngineConfig, proxyHost string) string {
	if proxyHost == "" {
		proxyHost = "127.0.0.1"
	}
	httpPort := DefaultHTTPPort
	socksPort := DefaultSOCKSPort
	var directList, proxyList []string
	var proxyAll bool

	if cfg != nil {
		if cfg.HTTPPort > 0 {
			httpPort = cfg.HTTPPort
		}
		if cfg.SOCKSPort > 0 {
			socksPort = cfg.SOCKSPort
		}
		directList = cfg.DirectDomains
		proxyList = cfg.ProxyDomains
		proxyAll = cfg.ProxyAll
	}

	mergedDirect := mergeUniquePACDomains(directList, RUEcosystemDomains)
	if proxyList == nil {
		proxyList = []string{}
	}

	routeTgDC := false
	if cfg != nil && (cfg.Categories["social"] || cfg.Categories["telegram"] || cfg.Categories["media"]) {
		routeTgDC = true
	}
	if !routeTgDC {
		for _, p := range proxyList {
			if normalizeDomainPattern(p) == "telegram.org" {
				routeTgDC = true
				break
			}
		}
	}

	directJSON, _ := json.Marshal(mergedDirect)
	proxyJSON, _ := json.Marshal(proxyList)
	proxyReturn := fmt.Sprintf("PROXY %s:%d; SOCKS5 %s:%d", proxyHost, httpPort, proxyHost, socksPort)

	var b strings.Builder
	b.WriteString("// PixelTunnel Smart PAC v2.1 (Zero local DNS queries)\n")
	b.WriteString("var DIRECT_RULES = ")
	b.Write(directJSON)
	b.WriteString(";\nvar PROXY_RULES = ")
	b.Write(proxyJSON)
	b.WriteString(";\nvar PROXY_ALL = ")
	if proxyAll {
		b.WriteString("true")
	} else {
		b.WriteString("false")
	}
	b.WriteString(";\nvar ROUTE_TG_DC = ")
	if routeTgDC {
		b.WriteString("true")
	} else {
		b.WriteString("false")
	}
	b.WriteString(";\nvar PROXY_CHAIN = ")
	chainJSON, _ := json.Marshal(proxyReturn)
	b.Write(chainJSON)
	b.WriteString(";\n\n")

	b.WriteString(`function _endsWith(str, suf) {
  return str.length >= suf.length && str.slice(str.length - suf.length) === suf;
}

function _matchRule(h, rule) {
  if (!rule) return false;
  if (rule.charAt(0) === '.') {
    return _endsWith(h, rule) || h === rule.slice(1);
  }
  return h === rule || _endsWith(h, '.' + rule);
}

function _isPrivateIPLiteral(h) {
  if (h === 'localhost' || h === '::1' || h === '[::1]' || h === '0.0.0.0') return true;
  if (/^127\./.test(h) || /^10\./.test(h) || /^192\.168\./.test(h) || /^169\.254\./.test(h)) return true;
  var m = /^172\.(\d+)\./.exec(h);
  if (m) {
    var sec = parseInt(m[1], 10);
    if (sec >= 16 && sec <= 31) return true;
  }
  if (/^(fc|fd|fe80)/i.test(h.replace(/^\[|\]$/g, ''))) return true;
  return false;
}

function _isTelegramDCIP(h) {
  var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (!m) return false;
  var a = parseInt(m[1], 10), b = parseInt(m[2], 10), c = parseInt(m[3], 10), d = parseInt(m[4], 10);
  if (a > 255 || b > 255 || c > 255 || d > 255) return false;
  if (a === 149 && b === 154 && (c & 240) === 160) return true;
  if (a === 91 && b === 108 && ((c & 252) === 4 || (c & 252) === 8 || (c & 252) === 12 || (c & 252) === 16 || (c & 252) === 20 || (c & 252) === 56)) return true;
  if (a === 91 && b === 105 && (c & 254) === 192) return true;
  if (a === 185 && b === 76 && c === 151) return true;
  return false;
}

function FindProxyForURL(url, host) {
  var h = (host || '').toLowerCase().replace(/\.$/, '');
  if (!h || isPlainHostName(h) || _isPrivateIPLiteral(h)) {
    return 'DIRECT';
  }
  if (_endsWith(h, '.ru') || _endsWith(h, '.рф') || _endsWith(h, '.xn--p1ai') || _endsWith(h, '.su') || _endsWith(h, '.by')) {
    return 'DIRECT';
  }
  for (var i = 0; i < DIRECT_RULES.length; i++) {
    if (_matchRule(h, DIRECT_RULES[i])) return 'DIRECT';
  }
  if (ROUTE_TG_DC && _isTelegramDCIP(h)) {
    return PROXY_CHAIN;
  }
  if (PROXY_ALL) {
    return PROXY_CHAIN;
  }
  for (var j = 0; j < PROXY_RULES.length; j++) {
    if (_matchRule(h, PROXY_RULES[j])) return PROXY_CHAIN;
  }
  return 'DIRECT';
}
`)
	return b.String()
}

func mergeUniquePACDomains(lists ...[]string) []string {
	total := 0
	for _, list := range lists {
		total += len(list)
	}
	seen := make(map[string]struct{}, total)
	out := make([]string, 0, total)
	for _, list := range lists {
		for _, raw := range list {
			norm := normalizeDomainPattern(raw)
			if norm == "" {
				continue
			}
			if _, ok := seen[norm]; ok {
				continue
			}
			seen[norm] = struct{}{}
			out = append(out, norm)
		}
	}
	return out
}

