package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// GenerateSmartPACJS generates a zero-DNS Smart PAC script with ZERO dnsResolve() calls
// implementing the unified 4-tier precedence:
// Tier 0 self-bypass -> Tier 1 custom/temporary proxy -> Tier 2 custom direct ->
// Tier 3 BUILTIN_DIRECT -> Tier 4 enabled categories / proxy_all -> DIRECT.
func GenerateSmartPACJS(cfg *EngineConfig, proxyHost string) string {
	if proxyHost == "" {
		proxyHost = "127.0.0.1"
	}
	httpPort := DefaultHTTPPort
	socksPort := DefaultSOCKSPort
	var proxyAll bool

	bypassInputs := []string{"localhost", "localhost.localdomain", "pixelstore.space", DefaultHost}
	var customProxyList, customDirectList, staticDirectList, categoryAndStaticProxy []string

	if cfg != nil {
		if cfg.HTTPPort > 0 {
			httpPort = cfg.HTTPPort
		}
		if cfg.SOCKSPort > 0 {
			socksPort = cfg.SOCKSPort
		}
		proxyAll = cfg.ProxyAll

		if cfg.ActiveNode.Host != "" {
			bypassInputs = append(bypassInputs, cfg.ActiveNode.Host)
		}
		if cfg.ActiveNode.SNI != "" {
			bypassInputs = append(bypassInputs, cfg.ActiveNode.SNI)
		}
		for _, n := range cfg.Nodes {
			if n.Host != "" {
				bypassInputs = append(bypassInputs, n.Host)
			}
			if n.SNI != "" {
				bypassInputs = append(bypassInputs, n.SNI)
			}
		}

		customProxyList = mergeUniquePACDomains(cfg.CustomProxy, cfg.ActiveTemporaryProxy(time.Now()))
		customDirectList = mergeUniquePACDomains(cfg.CustomDirect)
		staticDirectList = cfg.ConfigStaticDirect

		for cat, enabled := range cfg.Categories {
			if !enabled {
				continue
			}
			categoryAndStaticProxy = append(categoryAndStaticProxy, CategoryDomains[strings.ToLower(cat)]...)
		}
		categoryAndStaticProxy = append(categoryAndStaticProxy, cfg.ConfigStaticProxy...)
	}

	bypassRules := mergeUniquePACDomains(bypassInputs)
	if customProxyList == nil {
		customProxyList = []string{}
	}
	if customDirectList == nil {
		customDirectList = []string{}
	}
	mergedDirect := mergeUniquePACDomains(BuiltinDirectDomains, RUEcosystemDomains, staticDirectList)
	proxyList := mergeUniquePACDomains(categoryAndStaticProxy)

	routeTgDC := false
	if cfg != nil && (cfg.Categories["social"] || cfg.Categories["telegram"] || cfg.Categories["media"]) {
		routeTgDC = true
	}
	if !routeTgDC {
		for _, p := range customProxyList {
			if p == "telegram.org" {
				routeTgDC = true
				break
			}
		}
	}
	if !routeTgDC {
		for _, p := range proxyList {
			if p == "telegram.org" {
				routeTgDC = true
				break
			}
		}
	}

	bypassJSON, _ := json.Marshal(bypassRules)
	customProxyJSON, _ := json.Marshal(customProxyList)
	customDirectJSON, _ := json.Marshal(customDirectList)
	directJSON, _ := json.Marshal(mergedDirect)
	proxyJSON, _ := json.Marshal(proxyList)
	proxyReturn := fmt.Sprintf("PROXY %s:%d; SOCKS5 %s:%d", proxyHost, httpPort, proxyHost, socksPort)

	var b strings.Builder
	b.WriteString("// PixelTunnel Smart PAC v2.2 (Zero local DNS queries)\n")
	b.WriteString("var BYPASS_RULES = ")
	b.Write(bypassJSON)
	b.WriteString(";\nvar CUSTOM_PROXY_RULES = ")
	b.Write(customProxyJSON)
	b.WriteString(";\nvar CUSTOM_DIRECT_RULES = ")
	b.Write(customDirectJSON)
	b.WriteString(";\nvar DIRECT_RULES = ")
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
  var m172 = /^172\.(\d+)\./.exec(h);
  if (m172) {
    var sec = parseInt(m172[1], 10);
    if (sec >= 16 && sec <= 31) return true;
  }
  var m100 = /^100\.(\d+)\./.exec(h);
  if (m100) {
    var sec100 = parseInt(m100[1], 10);
    if (sec100 >= 64 && sec100 <= 127) return true;
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
  // Tier 0: Non-overridable self-bypass
  for (var b = 0; b < BYPASS_RULES.length; b++) {
    if (_matchRule(h, BYPASS_RULES[b])) return 'DIRECT';
  }
  // Tier 1: Custom & active temporary proxy overrides (beats .ru and built-in direct)
  for (var cp = 0; cp < CUSTOM_PROXY_RULES.length; cp++) {
    if (_matchRule(h, CUSTOM_PROXY_RULES[cp])) return PROXY_CHAIN;
  }
  // Tier 2: Custom direct rules (beats enabled categories)
  for (var cd = 0; cd < CUSTOM_DIRECT_RULES.length; cd++) {
    if (_matchRule(h, CUSTOM_DIRECT_RULES[cd])) return 'DIRECT';
  }
  // Tier 3: Built-in direct (.ru/.su/.by/.xn--p1ai + RU ecosystem + direct defaults)
  if (_endsWith(h, '.ru') || _endsWith(h, '.рф') || _endsWith(h, '.xn--p1ai') || _endsWith(h, '.su') || _endsWith(h, '.by')) {
    return 'DIRECT';
  }
  for (var i = 0; i < DIRECT_RULES.length; i++) {
    if (_matchRule(h, DIRECT_RULES[i])) return 'DIRECT';
  }
  // Tier 4: Enabled categories + Telegram DC + proxy_all
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

