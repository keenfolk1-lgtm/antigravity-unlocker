package main

import (
	"encoding/binary"
	"net"
	"strings"
)

// RUEcosystemDomains lists major non-.ru (plus key CDN/app) Russian ecosystem,
// video, cloud, and banking domains that must bypass the proxy and connect DIRECT.
var RUEcosystemDomains = []string{
	// VK / Mail.ru / OK ecosystem
	"vk.com",
	"vk.me",
	"vk.cc",
	"userapi.com",
	"vkuser.net",
	"vkuseraudio.net",
	"vkuservideo.net",
	"vk-cdn.net",
	"vkvideo.ru",
	"mycdn.me",
	"ok.me",
	"mail.ua",

	// Yandex ecosystem
	"yandex.com",
	"yandex.net",
	"yandex.cloud",
	"yandexcloud.net",
	"yastatic.net",
	"yandex.kz",

	// E-commerce & classifieds
	"ozon.com",
	"ozonusercontent.com",
	"wbstatic.net",
	"avito.st",

	// Video, streaming, maps & tech media
	"kinescope.io",
	"rutube.me",
	"2gis.com",
	"ivi.tv",
	"okko.tv",
	"premier.one",
	"habr.com",
	"habrastorage.org",

	// Cloud, hosting, telecom & security
	"timeweb.cloud",
	"timeweb.com",
	"selectel.org",
	"beget.com",
	"cloud.mts.ru",
	"rt.ru",
	"kaspersky.com",

	// Banking & devices
	"sberdevices.ru",
	"tinkoff.com",
	"alfa.me",
}

var ruDirectTLDs = []string{".ru", ".xn--p1ai", ".рф", ".su", ".by"}

type ipRange32 struct {
	start uint32
	end   uint32
}

// ruIPv4Ranges is a sorted, strictly non-overlapping table of genuine RIPE-allocated
// Russian ISP, cloud, and CDN IPv4 blocks.
// It excludes all proxy cluster nodes (e.g. 185.103.103.162), Cloudflare, Google, Quad9,
// Anthropic, and OpenAI ranges.
var ruIPv4Ranges = []ipRange32{
	cidrRange32(5, 45, 192, 0, 18),    // 5.45.192.0/18    Yandex
	cidrRange32(5, 255, 192, 0, 18),   // 5.255.192.0/18   Yandex
	cidrRange32(31, 173, 0, 0, 16),    // 31.173.0.0/16    Megafon
	cidrRange32(77, 88, 0, 0, 18),     // 77.88.0.0/18     Yandex
	cidrRange32(78, 36, 0, 0, 15),     // 78.36.0.0/15     Rostelecom
	cidrRange32(83, 149, 0, 0, 16),    // 83.149.0.0/16    Megafon
	cidrRange32(85, 26, 0, 0, 15),     // 85.26.0.0/15     Megafon
	cidrRange32(85, 140, 0, 0, 15),    // 85.140.0.0/15    Rostelecom
	cidrRange32(87, 250, 224, 0, 19),  // 87.250.224.0/19  Yandex
	cidrRange32(89, 178, 0, 0, 15),    // 89.178.0.0/15    Beeline
	cidrRange32(91, 76, 0, 0, 14),     // 91.76.0.0/14     MTS
	cidrRange32(92, 53, 64, 0, 18),    // 92.53.64.0/18    Selectel / EdgeCenter
	cidrRange32(93, 158, 128, 0, 18),  // 93.158.128.0/18  Yandex
	cidrRange32(95, 24, 0, 0, 13),     // 95.24.0.0/13     MTS
	cidrRange32(95, 163, 0, 0, 16),    // 95.163.0.0/16    VK
	cidrRange32(95, 167, 0, 0, 16),    // 95.167.0.0/16    Rostelecom
	cidrRange32(109, 184, 0, 0, 15),   // 109.184.0.0/15   Rostelecom
	cidrRange32(109, 194, 0, 0, 15),   // 109.194.0.0/15   ER-Telecom
	cidrRange32(128, 68, 0, 0, 14),    // 128.68.0.0/14    Beeline
	cidrRange32(176, 59, 0, 0, 16),    // 176.59.0.0/16    Tele2
	cidrRange32(176, 99, 0, 0, 16),    // 176.99.0.0/16    MTS
	cidrRange32(178, 44, 0, 0, 14),    // 178.44.0.0/14    Rostelecom
	cidrRange32(178, 176, 0, 0, 14),   // 178.176.0.0/14   Megafon
	cidrRange32(185, 16, 148, 0, 22),  // 185.16.148.0/22  VK
	cidrRange32(185, 157, 96, 0, 22),  // 185.157.96.0/22  Sber
	cidrRange32(188, 93, 16, 0, 20),   // 188.93.16.0/20   Selectel / EdgeCenter
	cidrRange32(188, 168, 0, 0, 14),   // 188.168.0.0/14   Rostelecom
	cidrRange32(188, 232, 0, 0, 14),   // 188.232.0.0/14   ER-Telecom
	cidrRange32(194, 186, 0, 0, 16),   // 194.186.0.0/16   Sber
	cidrRange32(212, 164, 0, 0, 16),   // 212.164.0.0/16   Rostelecom
	cidrRange32(213, 87, 0, 0, 16),    // 213.87.0.0/16    MTS
	cidrRange32(213, 180, 192, 0, 19), // 213.180.192.0/19 Yandex
	cidrRange32(217, 20, 144, 0, 20),  // 217.20.144.0/20  VK
}

func cidrRange32(a, b, c, d byte, prefix int) ipRange32 {
	base := uint32(a)<<24 | uint32(b)<<16 | uint32(c)<<8 | uint32(d)
	var mask uint32
	if prefix > 0 {
		mask = ^uint32(0) << (32 - prefix)
	}
	start := base & mask
	end := start | ^mask
	return ipRange32{start: start, end: end}
}

func matchDomainOrSubdomain(host, domain string) bool {
	if host == domain {
		return true
	}
	n := len(host)
	m := len(domain)
	return n > m+1 && host[n-m-1] == '.' && host[n-m:] == domain
}

// IsRUEcosystemDomain returns true if host (normalized, stripping optional port and
// trailing dot) matches a Russian/CIS TLD (.ru, .xn--p1ai, .рф, .su, .by) or is an exact
// or subdomain match for any domain in RUEcosystemDomains.
func IsRUEcosystemDomain(host string) bool {
	h := normalizeHostForMatch(host)
	if h == "" {
		return false
	}
	for _, tld := range ruDirectTLDs {
		if len(h) > len(tld) && strings.HasSuffix(h, tld) {
			return true
		}
	}
	for _, d := range RUEcosystemDomains {
		norm := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(d)), ".")
		if norm != "" && matchDomainOrSubdomain(h, norm) {
			return true
		}
	}
	return false
}

// IsRussianIP performs an O(log N) binary search over ruIPv4Ranges and returns true
// when ip is an IPv4 (or IPv4-mapped IPv6) address inside known Russian ISP/cloud/CDN blocks.
func IsRussianIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	target := binary.BigEndian.Uint32(v4)
	lo, hi := 0, len(ruIPv4Ranges)-1
	for lo <= hi {
		mid := int(uint(lo+hi) >> 1)
		r := ruIPv4Ranges[mid]
		if target < r.start {
			hi = mid - 1
		} else if target > r.end {
			lo = mid + 1
		} else {
			return true
		}
	}
	return false
}
