package session

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/quocdev03/user-access-management/internal/mysqlstore"
	"github.com/ua-parser/uap-go/uaparser"
)

// File này chuẩn hóa observed client profile từ request metadata.

var userAgentParser = sync.OnceValue(func() *uaparser.Parser {
	return uaparser.NewFromSaved()
})

// ClientProfileView biểu diễn thông tin thiết bị đã đăng nhập khi hiển thị danh sách thiết bị cho người dùng.
type ClientProfileView struct {
	ID           uint64
	DeviceName   *string
	DeviceType   *string
	OS           *string
	Browser      *string
	IPAddress    *string
	LastActiveAt *time.Time
}

// NormalizeRequestMeta giới hạn IP và user-agent trước khi lưu observed client data.
func NormalizeRequestMeta(ipAddress, userAgent string) (string, string) {
	if len(ipAddress) > 45 {
		ipAddress = ipAddress[:45]
	}
	if len(userAgent) > 500 {
		userAgent = userAgent[:500]
	}
	return ipAddress, userAgent
}

// ListClientProfiles liệt kê client hồ sơ trong vòng đời session.
func (m *Manager) ListClientProfiles(
	ctx context.Context,
	userID uint64,
) ([]ClientProfileView, error) {
	profiles, err := m.profiles.FindByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	result := make([]ClientProfileView, 0, len(profiles))
	for _, profile := range profiles {
		result = append(result, ClientProfileView{
			ID:           profile.ID,
			DeviceName:   profile.DeviceName,
			DeviceType:   profile.DeviceType,
			OS:           profile.OS,
			Browser:      profile.Browser,
			IPAddress:    profile.IPAddress,
			LastActiveAt: profile.LastActiveAt,
		})
	}
	return result, nil
}

// observedClientProfile tạo fingerprint ổn định từ metadata client đã chuẩn hóa.
func observedClientProfile(
	userID uint64,
	ipAddress string,
	userAgent string,
) mysqlstore.ClientProfile {
	osName, browser, deviceType := parseUserAgent(userAgent)
	profile := mysqlstore.ClientProfile{
		UserID:     userID,
		DeviceType: &deviceType,
		OS:         &osName,
		Browser:    &browser,
		IPAddress:  &ipAddress,
	}
	if userAgent != "" {
		profile.DeviceName = &userAgent
	}
	return profile
}

// parseUserAgent suy ra browser, OS và device class từ user-agent đã giới hạn.
func parseUserAgent(userAgent string) (osName, browser, deviceType string) {
	if strings.TrimSpace(userAgent) == "" {
		return "Unknown", "Unknown", "desktop"
	}
	client := userAgentParser().Parse(userAgent)

	osName = "Unknown"
	if client.Os != nil && client.Os.Family != "" {
		osName = client.Os.Family
	}
	browser = "Unknown"
	if client.UserAgent != nil && client.UserAgent.Family != "" {
		browser = client.UserAgent.Family
	}
	return osName, browser, mapDeviceType(client)
}

// mapDeviceType gom user-agent device class về tập giá trị persistence cho phép.
func mapDeviceType(client *uaparser.Client) string {
	if client == nil || client.Device == nil {
		return "desktop"
	}
	family := strings.TrimSpace(client.Device.Family)
	if family == "" || strings.EqualFold(family, "Other") || strings.EqualFold(family, "Spider") {
		return "desktop"
	}
	lower := strings.ToLower(family)
	switch {
	case strings.Contains(lower, "ipad"),
		strings.Contains(lower, "tablet"),
		strings.Contains(lower, "kindle"),
		strings.Contains(lower, "playbook"):
		return "tablet"
	case strings.Contains(lower, "iphone"),
		strings.Contains(lower, "phone"),
		strings.Contains(lower, "mobile"),
		strings.Contains(lower, "android"),
		strings.Contains(lower, "ipod"),
		strings.Contains(lower, "nokia"),
		strings.Contains(lower, "blackberry"):
		return "mobile"
	default:
		return "mobile"
	}
}
