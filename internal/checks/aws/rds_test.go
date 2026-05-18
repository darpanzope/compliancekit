package aws

import (
	"context"
	"testing"

	awscol "github.com/darpanzope/compliancekit/internal/collectors/aws"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func newDB(name string, attrs map[string]any) compliancekit.Resource {
	return compliancekit.Resource{
		ID: "aws.rds.instance.test." + name, Type: awscol.RDSInstanceType, Name: name, Provider: "aws", Region: "us-east-1",
		Attributes: attrs,
	}
}

func TestRDSEncrypted(t *testing.T) {
	enc := newDB("db1", map[string]any{"storage_encrypted": true})
	unenc := newDB("db2", map[string]any{"storage_encrypted": false})
	g := newGraphWith(enc, unenc)
	findings, _ := RDSEncrypted(context.Background(), g)
	for _, f := range findings {
		want := compliancekit.StatusPass
		if f.Resource.Name == "db2" {
			want = compliancekit.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v, want %v", f.Resource.Name, f.Status, want)
		}
	}
}

func TestRDSNotPublic(t *testing.T) {
	priv := newDB("db-priv", map[string]any{"publicly_accessible": false})
	pub := newDB("db-pub", map[string]any{"publicly_accessible": true})
	g := newGraphWith(priv, pub)
	findings, _ := RDSNotPublic(context.Background(), g)
	for _, f := range findings {
		want := compliancekit.StatusPass
		if f.Resource.Name == "db-pub" {
			want = compliancekit.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}

func TestRDSBackupRetention(t *testing.T) {
	cases := []struct {
		days int
		want compliancekit.Status
	}{
		{0, compliancekit.StatusFail},
		{6, compliancekit.StatusFail},
		{7, compliancekit.StatusPass},
		{30, compliancekit.StatusPass},
	}
	for _, c := range cases {
		g := newGraphWith(newDB("db", map[string]any{"backup_retention_period": c.days}))
		findings, _ := RDSBackupRetention(context.Background(), g)
		if findings[0].Status != c.want {
			t.Errorf("days=%d: got %v, want %v", c.days, findings[0].Status, c.want)
		}
	}
}

func TestRDSDeletionProtection(t *testing.T) {
	protected := newDB("db-p", map[string]any{"deletion_protection": true})
	unprotected := newDB("db-u", map[string]any{"deletion_protection": false})
	g := newGraphWith(protected, unprotected)
	findings, _ := RDSDeletionProtection(context.Background(), g)
	for _, f := range findings {
		want := compliancekit.StatusPass
		if f.Resource.Name == "db-u" {
			want = compliancekit.StatusFail
		}
		if f.Status != want {
			t.Errorf("%s: got %v", f.Resource.Name, f.Status)
		}
	}
}
