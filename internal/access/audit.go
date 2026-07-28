package access

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"

	"github.com/quocdev03/user-access-management/internal/mysqlstore"
)

type Metadata struct {
	IPAddress string
	UserAgent string
}

type AuditFilter struct {
	UserID    *uint64
	Action    *string
	StartDate *string
	EndDate   *string
}

type Audit struct {
	store *mysqlstore.AuditStore
}

func NewAudit(store *mysqlstore.AuditStore) *Audit {
	return &Audit{store: store}
}

func (a *Audit) Export(ctx context.Context, filter AuditFilter) ([]byte, error) {
	logs, err := a.store.FindAllWithFilters(
		ctx,
		filter.UserID,
		filter.Action,
		filter.StartDate,
		filter.EndDate,
	)
	if err != nil {
		return nil, err
	}

	var buffer bytes.Buffer
	buffer.WriteString("\xEF\xBB\xBF")
	writer := csv.NewWriter(&buffer)
	if err := writer.Write([]string{
		"ID",
		"UserID",
		"Action",
		"Resource",
		"ResourceID",
		"IPAddress",
		"Status",
		"CreatedAt",
	}); err != nil {
		return nil, fmt.Errorf("write audit CSV header: %w", err)
	}
	for _, log := range logs {
		userID := ""
		if log.UserID != nil {
			userID = fmt.Sprint(*log.UserID)
		}
		resource := ""
		if log.Resource != nil {
			resource = *log.Resource
		}
		resourceID := ""
		if log.ResourceID != nil {
			resourceID = *log.ResourceID
		}
		ipAddress := ""
		if log.IPAddress != nil {
			ipAddress = *log.IPAddress
		}
		if err := writer.Write([]string{
			fmt.Sprint(log.ID),
			userID,
			log.Action,
			resource,
			resourceID,
			ipAddress,
			log.Status,
			log.CreatedAt.Format("2006-01-02 15:04:05"),
		}); err != nil {
			return nil, fmt.Errorf("write audit CSV row: %w", err)
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("flush audit CSV: %w", err)
	}
	return buffer.Bytes(), nil
}

func writeAudit(
	ctx context.Context,
	store *mysqlstore.AuditStore,
	actorID uint64,
	action string,
	resource string,
	resourceID string,
	metadata Metadata,
) error {
	ipAddress := metadata.IPAddress
	userAgent := metadata.UserAgent
	return store.Create(ctx, &mysqlstore.AuditLog{
		UserID:     &actorID,
		Action:     action,
		Resource:   &resource,
		ResourceID: &resourceID,
		IPAddress:  &ipAddress,
		UserAgent:  &userAgent,
		Status:     "success",
	})
}
