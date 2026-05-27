package warehouse

// RedshiftLoader implements Loader for Amazon Redshift. The path used
// is the standard "stage on S3 + COPY" pattern: build per-table NDJSON
// in memory, upload to a sub-key of StageS3URI, issue a COPY via the
// Redshift Data API (no in-cluster driver needed; the API runs the
// SQL inside the cluster on the operator's behalf).
//
// Auth: standard AWS SDK chain (env / AWS_PROFILE / AWS_ROLE_ARN /
// IMDS). The Data API authenticates with --secret-arn or with the
// cluster's IAM role; we use --secret-arn here for the canonical
// shape.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/redshiftdata"
	rstypes "github.com/aws/aws-sdk-go-v2/service/redshiftdata/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// RedshiftConfig captures the per-loader knobs.
type RedshiftConfig struct {
	ClusterID  string
	Database   string
	SecretARN  string // Secrets Manager ARN with the Redshift credentials
	StageS3URI string // e.g. s3://acme-warehouse-stage/compliancekit/
}

// RedshiftLoader is the concrete Loader. Construct via
// NewRedshiftLoader.
type RedshiftLoader struct {
	cfg    RedshiftConfig
	rsd    *redshiftdata.Client
	s3     *s3.Client
	bucket string
	prefix string
}

// NewRedshiftLoader returns a Loader configured against cfg. AWS
// clients are lazy — initialized on first Connect call.
func NewRedshiftLoader(cfg RedshiftConfig) *RedshiftLoader {
	return &RedshiftLoader{cfg: cfg}
}

func (r *RedshiftLoader) Connect(ctx context.Context) error {
	if r.cfg.ClusterID == "" || r.cfg.Database == "" || r.cfg.StageS3URI == "" {
		return fmt.Errorf("redshift loader: ClusterID, Database, StageS3URI required")
	}
	if r.rsd != nil {
		return nil
	}
	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("aws load default config: %w", err)
	}
	r.rsd = redshiftdata.NewFromConfig(awsCfg)
	r.s3 = s3.NewFromConfig(awsCfg)
	bucket, prefix, err := parseS3URI(r.cfg.StageS3URI)
	if err != nil {
		return err
	}
	r.bucket = bucket
	r.prefix = prefix
	return nil
}

func (r *RedshiftLoader) Load(ctx context.Context, schema Schema, rows <-chan Row) error {
	if r.rsd == nil {
		return fmt.Errorf("redshift loader: not connected")
	}
	// Ensure destination table exists.
	if err := r.ensureTable(ctx, schema); err != nil {
		return err
	}
	// Buffer NDJSON in memory + push to S3 as a single object per
	// table. Future v1.17.x optimization could split into N-sized
	// chunks for parallel COPY.
	var buf bytes.Buffer
	count := 0
	for row := range rows {
		out := map[string]any{}
		for _, c := range schema.Columns {
			v, ok := row[c.Name]
			if !ok {
				if c.Nullable {
					continue
				}
				v = nil
			}
			out[c.Name] = redshiftValue(c.Type, v)
		}
		if err := json.NewEncoder(&buf).Encode(out); err != nil {
			return fmt.Errorf("encode row %d for %s: %w", count, schema.Table, err)
		}
		count++
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
	if count == 0 {
		return nil
	}
	key := fmt.Sprintf("%s/%s_%d.ndjson", strings.TrimSuffix(r.prefix, "/"), schema.Table, time.Now().UnixNano())
	if _, err := r.s3.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(r.bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(buf.Bytes()),
		ContentType: aws.String("application/x-ndjson"),
	}); err != nil {
		return fmt.Errorf("s3 PutObject %s/%s: %w", r.bucket, key, err)
	}
	// Issue COPY via Redshift Data API. JSON 'auto' lets Redshift map
	// keys → columns by name (case-insensitive); requires the
	// destination table to have the matching column names — handled
	// by ensureTable via schema_for(t).
	copySQL := fmt.Sprintf(
		`COPY %s FROM 's3://%s/%s' IAM_ROLE default FORMAT AS JSON 'auto'`,
		string(schema.Table), r.bucket, key)
	out, err := r.rsd.ExecuteStatement(ctx, &redshiftdata.ExecuteStatementInput{
		ClusterIdentifier: aws.String(r.cfg.ClusterID),
		Database:          aws.String(r.cfg.Database),
		SecretArn:         aws.String(r.cfg.SecretARN),
		Sql:               aws.String(copySQL),
	})
	if err != nil {
		return fmt.Errorf("redshift COPY %s: %w", schema.Table, err)
	}
	// Poll for completion.
	return r.waitForStatement(ctx, *out.Id)
}

func (r *RedshiftLoader) Close() error {
	r.rsd = nil
	r.s3 = nil
	return nil
}

func (r *RedshiftLoader) ensureTable(ctx context.Context, schema Schema) error {
	cols := make([]string, len(schema.Columns))
	for i, c := range schema.Columns {
		nullness := "NOT NULL"
		if c.Nullable {
			nullness = ""
		}
		cols[i] = fmt.Sprintf("%s %s %s", c.Name, redshiftColumnType(c.Type), nullness)
	}
	q := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (%s)`,
		string(schema.Table), strings.Join(cols, ", "))
	out, err := r.rsd.ExecuteStatement(ctx, &redshiftdata.ExecuteStatementInput{
		ClusterIdentifier: aws.String(r.cfg.ClusterID),
		Database:          aws.String(r.cfg.Database),
		SecretArn:         aws.String(r.cfg.SecretARN),
		Sql:               aws.String(q),
	})
	if err != nil {
		return fmt.Errorf("redshift create %s: %w", schema.Table, err)
	}
	return r.waitForStatement(ctx, *out.Id)
}

// waitForStatement polls DescribeStatement until the statement
// finishes or fails. Redshift Data API is async, but warehouse loads
// are operator-driven — we block until done.
func (r *RedshiftLoader) waitForStatement(ctx context.Context, id string) error {
	for {
		desc, err := r.rsd.DescribeStatement(ctx, &redshiftdata.DescribeStatementInput{Id: aws.String(id)})
		if err != nil {
			return fmt.Errorf("describe statement %s: %w", id, err)
		}
		switch desc.Status {
		case rstypes.StatusStringFinished:
			return nil
		case rstypes.StatusStringFailed, rstypes.StatusStringAborted:
			return fmt.Errorf("redshift statement %s status=%s err=%s",
				id, desc.Status, aws.ToString(desc.Error))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(750 * time.Millisecond):
		}
	}
}

func redshiftColumnType(t ColumnType) string {
	switch t {
	case TypeString, TypeJSON:
		return "VARCHAR(65535)"
	case TypeInt:
		return "BIGINT"
	case TypeFloat:
		return "DOUBLE PRECISION"
	case TypeBool:
		return "BOOLEAN"
	case TypeTimestamp:
		return "TIMESTAMPTZ"
	}
	return "VARCHAR(65535)"
}

func redshiftValue(t ColumnType, v any) any {
	if v == nil {
		return nil
	}
	switch t {
	case TypeTimestamp:
		if ts, err := toTimestampMicros(v); err == nil {
			return time.UnixMicro(ts).UTC().Format(time.RFC3339)
		}
		return nil
	case TypeJSON:
		return toStringValue(v)
	}
	return v
}

// parseS3URI splits an s3://bucket/prefix URI into bucket + prefix.
func parseS3URI(uri string) (bucket, prefix string, err error) {
	if !strings.HasPrefix(uri, "s3://") {
		return "", "", fmt.Errorf("not an s3:// URI: %s", uri)
	}
	rest := strings.TrimPrefix(uri, "s3://")
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return rest, "", nil
	}
	return rest[:slash], rest[slash+1:], nil
}
