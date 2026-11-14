package session

import (
	"strings"
	"testing"
)

// File này kiểm chứng hành vi profile và các trường hợp lỗi liên quan.

// TestSessionsToKick kiểm chứng kịch bản SessionsToKick.
func TestSessionsToKick(t *testing.T) {
	tests := []struct {
		name     string
		active   int
		maximum  int
		expected int
	}{
		{name: "over cap", active: 15, maximum: 10, expected: 6},
		{name: "under cap", active: 5, maximum: 10, expected: 0},
		{name: "at cap", active: 10, maximum: 10, expected: 1},
		{name: "unlimited", active: 100, maximum: 0, expected: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := sessionsToKick(test.active, test.maximum); got != test.expected {
				t.Fatalf("sessionsToKick(%d, %d) = %d, want %d",
					test.active,
					test.maximum,
					got,
					test.expected,
				)
			}
		})
	}
}

// TestParseUserAgent kiểm chứng kịch bản ParseUserAgent.
func TestParseUserAgent(t *testing.T) {
	tests := []struct {
		name       string
		userAgent  string
		deviceType string
		osContains string
		uaContains string
	}{
		{
			name:       "Chrome on Windows",
			userAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
			deviceType: "desktop",
			osContains: "windows",
			uaContains: "chrome",
		},
		{
			name:       "iPhone",
			userAgent:  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
			deviceType: "mobile",
		},
		{
			name:       "empty",
			deviceType: "desktop",
			osContains: "unknown",
			uaContains: "unknown",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			osName, browser, deviceType := parseUserAgent(test.userAgent)
			if deviceType != test.deviceType {
				t.Fatalf("device type = %q, want %q", deviceType, test.deviceType)
			}
			if test.osContains != "" &&
				!strings.Contains(strings.ToLower(osName), test.osContains) {
				t.Fatalf("OS = %q, want substring %q", osName, test.osContains)
			}
			if test.uaContains != "" &&
				!strings.Contains(strings.ToLower(browser), test.uaContains) {
				t.Fatalf("browser = %q, want substring %q", browser, test.uaContains)
			}
		})
	}
}

// TestObservedProfileUsesFullUserAgent kiểm chứng kịch bản ObservedProfileUsesFullUserAgent.
func TestObservedProfileUsesFullUserAgent(t *testing.T) {
	userAgent := "Mozilla/5.0 Chrome/149.0.0.0"
	profile := observedClientProfile(42, "127.0.0.1", userAgent)
	if profile.DeviceName == nil || *profile.DeviceName != userAgent {
		t.Fatalf("device name = %v, want full observed user agent", profile.DeviceName)
	}
}
