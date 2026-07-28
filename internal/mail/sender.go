package mail

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	netmail "net/mail"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/quocdev03/user-access-management/internal/config"
)

type transport interface {
	SendEmail(to, subject, body string) error
}

type Sender struct {
	sender transport
	cfg    *config.Config
}

func NewSender(cfg *config.Config, logger *zap.Logger) *Sender {
	host := strings.TrimSpace(cfg.Mail.Host)
	from := strings.TrimSpace(cfg.Mail.From)
	if from == "" {
		from = "noreply@localhost"
	}

	var sender transport
	switch {
	case host == "":
		logger.Warn("SMTP_HOST trống — mail sẽ chỉ được log, không gửi thật")
		sender = &logOnlyMail{logger: logger}
	case host == "smtp.resend.com":
		logger.Info("Mail via Resend HTTP API", zap.String("from", from))
		sender = &resendHTTPMail{apiKey: cfg.Mail.Password, from: from, logger: logger}
	default:
		// Mailpit hoặc bất kỳ plain SMTP local nào
		logger.Info("Mail local/Mailpit",
			zap.String("host", host),
			zap.Int("port", cfg.Mail.Port),
		)
		sender = &localMail{host: host, port: cfg.Mail.Port, from: from, logger: logger}
	}

	return &Sender{sender: sender, cfg: cfg}
}

func (s *Sender) SendEmail(to, subject, body string) error {
	if strings.ContainsAny(to, "\r\n") || strings.ContainsAny(subject, "\r\n") {
		return fmt.Errorf("mail header contains a line break")
	}
	address, err := netmail.ParseAddress(strings.TrimSpace(to))
	if err != nil || address.Address != strings.TrimSpace(to) {
		return fmt.Errorf("invalid recipient address")
	}
	if len([]byte(subject)) > 998 {
		return fmt.Errorf("mail subject is too long")
	}
	return s.sender.SendEmail(to, subject, body)
}

func (s *Sender) SendVerificationEmail(to, otp string) error {
	body := fmt.Sprintf(`
		<h2>Xác thực tài khoản</h2>
		<p>Chào bạn,</p>
		<p>Mã OTP để xác thực tài khoản của bạn là: <strong>%s</strong></p>
		<p>Mã này có hiệu lực trong vòng %s.</p>
		<p>Nếu bạn không thực hiện yêu cầu này, vui lòng bỏ qua email này.</p>
	`, html.EscapeString(otp), expiryText(s.cfg.Security.OTPExpiry))
	return s.SendEmail(to, "Xác thực tài khoản UAM", body)
}

func (s *Sender) SendPasswordResetEmail(to, token string) error {
	frontendURL := s.cfg.App.FrontendURL
	if frontendURL == "" {
		frontendURL = "http://localhost:3000"
	}
	resetURL, err := url.Parse(strings.TrimRight(frontendURL, "/") + "/reset-password")
	if err != nil {
		return fmt.Errorf("build password reset URL: %w", err)
	}
	query := resetURL.Query()
	query.Set("token", token)
	resetURL.RawQuery = query.Encode()
	escapedURL := html.EscapeString(resetURL.String())
	body := fmt.Sprintf(`
		<h2>Khôi phục mật khẩu</h2>
		<p>Chào bạn,</p>
		<p>Bạn đã yêu cầu đặt lại mật khẩu. Vui lòng click vào link dưới đây để tiếp tục:</p>
		<p><a href="%s">Đặt lại mật khẩu</a></p>
		<p>Hoặc copy link này dán vào trình duyệt: <br/> %s</p>
		<p>Link này có hiệu lực trong vòng %s.</p>
		<p>Nếu bạn không yêu cầu, vui lòng bỏ qua email này.</p>
	`, escapedURL, escapedURL, expiryText(s.cfg.Security.PasswordResetExpiry))
	return s.SendEmail(to, "Khôi phục mật khẩu UAM", body)
}

func (s *Sender) SendEmailChangeVerification(to, otp string) error {
	body := fmt.Sprintf(`
		<h2>Xác nhận thay đổi Email</h2>
		<p>Mã OTP xác nhận thay đổi email của bạn là: <strong>%s</strong></p>
		<p>Mã này có hiệu lực trong vòng %s.</p>
		<p>Nếu bạn không thực hiện yêu cầu này, hãy đổi mật khẩu và liên hệ hỗ trợ.</p>
	`, html.EscapeString(otp), expiryText(s.cfg.Security.EmailChangeExpiry))
	return s.SendEmail(to, "Xác nhận thay đổi Email UAM", body)
}

func (s *Sender) SendEmailChangeNotification(oldEmail, newEmail string) error {
	body := fmt.Sprintf(`
		<h2>Thông báo thay đổi Email</h2>
		<p>Chào bạn,</p>
		<p>Chúng tôi thông báo rằng địa chỉ email liên kết với tài khoản UAM của bạn đã được thay đổi thành công.</p>
		<p><strong>Email cũ:</strong> %s</p>
		<p><strong>Email mới:</strong> %s</p>
		<p>Nếu bạn không thực hiện thay đổi này, tài khoản của bạn có thể đã bị xâm nhập trái phép. Vui lòng liên hệ với bộ phận hỗ trợ khách hàng của chúng tôi ngay lập tức để được hỗ trợ bảo mật.</p>
	`, html.EscapeString(oldEmail), html.EscapeString(newEmail))
	subject := "Cảnh báo bảo mật: Địa chỉ Email của tài khoản đã thay đổi"
	if err := s.SendEmail(oldEmail, subject, body); err != nil {
		return err
	}
	return s.SendEmail(newEmail, subject, body)
}

func (s *Sender) SendAdminNotification(to, subject, message string) error {
	body := fmt.Sprintf(`
		<h2>Thông báo từ Hệ thống</h2>
		<p>Chào bạn,</p>
		<p>%s</p>
	`, html.EscapeString(message))
	return s.SendEmail(to, html.EscapeString(subject), body)
}

// --- transport ---

// logOnlyMail: fallback khi SMTP_HOST trống — chỉ log, không gửi thật.
type logOnlyMail struct{ logger *zap.Logger }

func (s *logOnlyMail) SendEmail(to, subject, _ string) error {
	s.logger.Info(
		"[LOG ONLY MAIL — không gửi thật]",
		zap.String("recipient_domain", recipientDomain(to)),
	)
	return nil
}

// localMail: plain SMTP (no STARTTLS) cho Mailpit. Host port 1026 trên Windows Docker.
type localMail struct {
	host, from string
	port       int
	logger     *zap.Logger
}

func (s *localMail) SendEmail(to, subject, body string) error {
	addr := net.JoinHostPort(s.host, strconv.Itoa(s.port))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		s.logger.Error("SMTP local dial failed", zap.String("addr", addr), zap.Error(err))
		return fmt.Errorf("dial smtp %s: %w", addr, err)
	}
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		if closeErr := conn.Close(); closeErr != nil {
			s.logger.Warn("SMTP connection close failed", zap.Error(closeErr))
		}
		return fmt.Errorf("set SMTP deadline: %w", err)
	}

	c, err := smtp.NewClient(conn, s.host)
	if err != nil {
		if closeErr := conn.Close(); closeErr != nil {
			s.logger.Warn("SMTP connection close failed", zap.Error(closeErr))
		}
		return fmt.Errorf("smtp client: %w", err)
	}
	quit := false
	defer func() {
		if !quit {
			if err := c.Close(); err != nil {
				s.logger.Warn("SMTP client close failed", zap.Error(err))
			}
		}
	}()

	if err := c.Mail(s.from); err != nil {
		return fmt.Errorf("smtp MAIL: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("smtp RCPT: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		s.from, to, subject, body)
	if _, err := w.Write([]byte(msg)); err != nil {
		if closeErr := w.Close(); closeErr != nil {
			s.logger.Warn("SMTP data close after write failure", zap.Error(closeErr))
		}
		return fmt.Errorf("write SMTP DATA: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("close SMTP DATA: %w", err)
	}
	if err := c.Quit(); err != nil {
		return fmt.Errorf("smtp QUIT: %w", err)
	}
	quit = true

	s.logger.Info(
		"Mail sent (local)",
		zap.String("recipient_domain", recipientDomain(to)),
	)
	return nil
}

// resendHTTPMail gửi email qua Resend REST API (HTTPS port 443).
// Dùng cho production trên PaaS (Render, Railway…) nơi outbound SMTP bị chặn.
type resendHTTPMail struct {
	apiKey string
	from   string
	logger *zap.Logger
}

func (s *resendHTTPMail) SendEmail(to, subject, body string) error {
	payload := map[string]interface{}{
		"from":    s.from,
		"to":      []string{to},
		"subject": subject,
		"html":    body,
	}
	jsonBody, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal resend payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, "https://api.resend.com/emails", bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("create resend request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		s.logger.Error(
			"Resend HTTP API failed",
			zap.String("recipient_domain", recipientDomain(to)),
			zap.Error(err),
		)
		return fmt.Errorf("resend API call: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			s.logger.Warn("Resend response close failed", zap.Error(err))
		}
	}()

	if resp.StatusCode >= 400 {
		if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10)); err != nil {
			s.logger.Warn("Resend error response drain failed", zap.Error(err))
		}
		s.logger.Error("Resend API error",
			zap.Int("status", resp.StatusCode),
			zap.String("recipient_domain", recipientDomain(to)),
		)
		return fmt.Errorf("resend API status %d", resp.StatusCode)
	}

	s.logger.Info(
		"Mail sent (Resend API)",
		zap.String("recipient_domain", recipientDomain(to)),
	)
	return nil
}

func expiryText(duration time.Duration) string {
	if duration%time.Hour == 0 {
		return fmt.Sprintf("%d giờ", int(duration/time.Hour))
	}
	if duration%time.Minute == 0 {
		return fmt.Sprintf("%d phút", int(duration/time.Minute))
	}
	return duration.String()
}

func recipientDomain(address string) string {
	at := strings.LastIndexByte(address, '@')
	if at < 0 || at == len(address)-1 {
		return "invalid"
	}
	return address[at+1:]
}
