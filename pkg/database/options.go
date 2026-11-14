package database

import "time"

// File này định nghĩa các struct cấu hình kết nối độc lập cho MySQL và Redis.

// MySQLOptions chứa các tùy chọn kết nối, TLS và connection pool của MySQL.
type MySQLOptions struct {
	Host             string
	Port             string
	Name             string
	User             string
	Password         string
	TLSMode          string
	TLSCAFile        string
	TLSAllowInsecure bool
	MaxOpenConns     int
	MaxIdleConns     int
	ConnMaxLifetime  time.Duration
	ConnMaxIdleTime  time.Duration
}

// RedisOptions chứa các tùy chọn kết nối và connection pool của Redis.
type RedisOptions struct {
	Host         string
	Port         string
	Password     string
	PoolSize     int
	MinIdleConns int
}
