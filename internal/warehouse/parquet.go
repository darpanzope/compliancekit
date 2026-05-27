package warehouse

// ParquetWriter implements Writer over the Apache Arrow Go Parquet
// library. One ParquetWriter writes one Table — open it, push rows,
// close it. Buffered internally (per-column-chunk flushing handled
// by the Arrow library); Close() flushes the trailing chunk + the
// Parquet file footer.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/apache/arrow-go/v18/arrow"
	"github.com/apache/arrow-go/v18/arrow/array"
	"github.com/apache/arrow-go/v18/arrow/memory"
	"github.com/apache/arrow-go/v18/parquet"
	"github.com/apache/arrow-go/v18/parquet/compress"
	"github.com/apache/arrow-go/v18/parquet/pqarrow"
)

const parquetRowGroupSize int64 = 8192

// ParquetWriter is the Writer impl for the parquet format. Construct
// with NewParquetWriter(io.Writer) — caller owns the underlying writer
// (typically *os.File) and closes it AFTER ParquetWriter.Close()
// flushes the footer.
type ParquetWriter struct {
	w        io.Writer
	pool     memory.Allocator
	schema   *arrow.Schema
	arrowFW  *pqarrow.FileWriter
	builders []array.Builder
	rows     int
	logical  Schema
}

// NewParquetWriter returns a ParquetWriter that will write into w.
// The caller retains ownership of w — close it AFTER calling
// ParquetWriter.Close (which flushes the parquet footer).
func NewParquetWriter(w io.Writer) *ParquetWriter {
	return &ParquetWriter{w: w, pool: memory.NewGoAllocator()}
}

func (p *ParquetWriter) Open(_ context.Context, s Schema) error {
	if p.arrowFW != nil {
		return fmt.Errorf("parquet writer: already open")
	}
	fields := make([]arrow.Field, len(s.Columns))
	for i, c := range s.Columns {
		fields[i] = arrow.Field{
			Name:     c.Name,
			Type:     arrowType(c.Type),
			Nullable: c.Nullable,
			Metadata: arrow.NewMetadata([]string{"compliancekit.type"}, []string{string(c.Type)}),
		}
	}
	md := arrow.NewMetadata(
		[]string{"compliancekit.schema_version", "compliancekit.table"},
		[]string{fmt.Sprintf("%d", SchemaVersion), string(s.Table)},
	)
	p.schema = arrow.NewSchema(fields, &md)
	p.logical = s

	props := parquet.NewWriterProperties(
		parquet.WithCompression(compress.Codecs.Snappy),
		parquet.WithBatchSize(parquetRowGroupSize),
	)
	arrowProps := pqarrow.DefaultWriterProps()
	fw, err := pqarrow.NewFileWriter(p.schema, p.w, props, arrowProps)
	if err != nil {
		return fmt.Errorf("parquet new file writer: %w", err)
	}
	p.arrowFW = fw
	p.builders = make([]array.Builder, len(s.Columns))
	for i, f := range fields {
		p.builders[i] = array.NewBuilder(p.pool, f.Type)
	}
	return nil
}

func (p *ParquetWriter) Write(_ context.Context, row Row) error {
	if p.arrowFW == nil {
		return fmt.Errorf("parquet writer: not open")
	}
	for i, c := range p.logical.Columns {
		v, ok := row[c.Name]
		if !ok || v == nil {
			p.builders[i].AppendNull()
			continue
		}
		if err := appendValue(p.builders[i], c.Type, v); err != nil {
			return fmt.Errorf("parquet write %s.%s: %w", p.logical.Table, c.Name, err)
		}
	}
	p.rows++
	if p.rows >= int(parquetRowGroupSize) {
		if err := p.flushBatch(); err != nil {
			return err
		}
	}
	return nil
}

func (p *ParquetWriter) Close() error {
	if p.arrowFW == nil {
		return nil
	}
	if p.rows > 0 {
		if err := p.flushBatch(); err != nil {
			_ = p.arrowFW.Close()
			p.arrowFW = nil
			return err
		}
	}
	err := p.arrowFW.Close()
	p.arrowFW = nil
	for _, b := range p.builders {
		b.Release()
	}
	p.builders = nil
	return err
}

func (p *ParquetWriter) flushBatch() error {
	cols := make([]arrow.Array, len(p.builders))
	for i, b := range p.builders {
		cols[i] = b.NewArray()
	}
	rec := array.NewRecordBatch(p.schema, cols, int64(p.rows))
	defer rec.Release()
	for _, c := range cols {
		c.Release()
	}
	if err := p.arrowFW.WriteBuffered(rec); err != nil {
		return fmt.Errorf("parquet write record: %w", err)
	}
	p.rows = 0
	// Builders are reset via NewArray() emptying them; re-allocate
	// fresh ones so subsequent Append calls land in clean buffers.
	for i, f := range p.schema.Fields() {
		p.builders[i] = array.NewBuilder(p.pool, f.Type)
	}
	return nil
}

func arrowType(t ColumnType) arrow.DataType {
	switch t {
	case TypeString, TypeJSON:
		return arrow.BinaryTypes.String
	case TypeInt:
		return arrow.PrimitiveTypes.Int64
	case TypeFloat:
		return arrow.PrimitiveTypes.Float64
	case TypeBool:
		return arrow.FixedWidthTypes.Boolean
	case TypeTimestamp:
		return &arrow.TimestampType{Unit: arrow.Microsecond, TimeZone: "UTC"}
	default:
		return arrow.BinaryTypes.String
	}
}

func appendValue(b array.Builder, t ColumnType, v any) error {
	switch t {
	case TypeString, TypeJSON:
		sb := b.(*array.StringBuilder)
		sb.Append(toStringValue(v))
	case TypeInt:
		ib := b.(*array.Int64Builder)
		n, err := toInt64(v)
		if err != nil {
			return err
		}
		ib.Append(n)
	case TypeFloat:
		fb := b.(*array.Float64Builder)
		f, err := toFloat64(v)
		if err != nil {
			return err
		}
		fb.Append(f)
	case TypeBool:
		bb := b.(*array.BooleanBuilder)
		boolVal, err := toBool(v)
		if err != nil {
			return err
		}
		bb.Append(boolVal)
	case TypeTimestamp:
		tb := b.(*array.TimestampBuilder)
		ts, err := toTimestampMicros(v)
		if err != nil {
			return err
		}
		tb.Append(arrow.Timestamp(ts))
	default:
		return fmt.Errorf("unknown column type %q", t)
	}
	return nil
}

func toStringValue(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case []byte:
		return string(x)
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

func toInt64(v any) (int64, error) {
	switch x := v.(type) {
	case int:
		return int64(x), nil
	case int32:
		return int64(x), nil
	case int64:
		return x, nil
	case uint32:
		return int64(x), nil
	case uint64:
		if x > 1<<63-1 {
			return 0, fmt.Errorf("uint64 %d overflows int64", x)
		}
		return int64(x), nil //nolint:gosec // bounds-checked above
	case uint:
		if uint64(x) > 1<<63-1 {
			return 0, fmt.Errorf("uint %d overflows int64", x)
		}
		return int64(x), nil //nolint:gosec // bounds-checked above
	case float64:
		return int64(x), nil
	case float32:
		return int64(x), nil
	}
	return 0, fmt.Errorf("not numeric: %T", v)
}

func toFloat64(v any) (float64, error) {
	switch x := v.(type) {
	case float64:
		return x, nil
	case float32:
		return float64(x), nil
	case int64:
		return float64(x), nil
	case int:
		return float64(x), nil
	}
	return 0, fmt.Errorf("not float: %T", v)
}

func toBool(v any) (bool, error) {
	switch x := v.(type) {
	case bool:
		return x, nil
	case int64:
		return x != 0, nil
	case int:
		return x != 0, nil
	}
	return false, fmt.Errorf("not bool: %T", v)
}
