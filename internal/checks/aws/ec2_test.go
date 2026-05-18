package aws

import (
	"context"
	"testing"

	awscol "github.com/darpanzope/compliancekit/internal/collectors/aws"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

func newGraphWith(resources ...compliancekit.Resource) *compliancekit.ResourceGraph {
	g := compliancekit.NewResourceGraph()
	for _, r := range resources {
		g.Add(r)
	}
	return g
}

func mkSG(name string, openV4, openV6 bool, ingress []map[string]any) compliancekit.Resource {
	return compliancekit.Resource{
		ID: "aws.ec2.sg." + name, Type: awscol.EC2SGType, Name: name, Provider: "aws",
		Attributes: map[string]any{
			"open_to_any_v4": openV4,
			"open_to_any_v6": openV6,
			"ingress_rules":  ingress,
		},
	}
}

func TestEC2SGNoIngressFromAny_AllClosed(t *testing.T) {
	g := newGraphWith(mkSG("sg-a", false, false, nil))
	findings, _ := EC2SGNoIngressFromAny(context.Background(), g)
	if findings[0].Status != compliancekit.StatusPass {
		t.Errorf("got %v", findings[0].Status)
	}
}

func TestEC2SGNoIngressFromAny_HTTPSOnly(t *testing.T) {
	g := newGraphWith(mkSG("sg-web", true, false, []map[string]any{
		{"protocol": "tcp", "from_port": 443, "to_port": 443, "ipv4_cidrs": []string{"0.0.0.0/0"}, "ipv6_cidrs": []string{}},
	}))
	findings, _ := EC2SGNoIngressFromAny(context.Background(), g)
	if findings[0].Status != compliancekit.StatusPass {
		t.Errorf("expected pass on 443-only, got %v: %s", findings[0].Status, findings[0].Message)
	}
}

func TestEC2SGNoIngressFromAny_SSHOpen(t *testing.T) {
	g := newGraphWith(mkSG("sg-bad", true, false, []map[string]any{
		{"protocol": "tcp", "from_port": 22, "to_port": 22, "ipv4_cidrs": []string{"0.0.0.0/0"}, "ipv6_cidrs": []string{}},
	}))
	findings, _ := EC2SGNoIngressFromAny(context.Background(), g)
	if findings[0].Status != compliancekit.StatusFail {
		t.Errorf("expected fail on SSH-from-any, got %v", findings[0].Status)
	}
}

func TestEC2NoDefaultVPCInUse(t *testing.T) {
	defaultVPC := compliancekit.Resource{
		ID: "aws.ec2.vpc.vpc-default", Type: awscol.EC2VPCType, Name: "vpc-default", Provider: "aws",
		Attributes: map[string]any{"vpc_id": "vpc-default", "is_default": true},
	}
	customVPC := compliancekit.Resource{
		ID: "aws.ec2.vpc.vpc-custom", Type: awscol.EC2VPCType, Name: "vpc-custom", Provider: "aws",
		Attributes: map[string]any{"vpc_id": "vpc-custom", "is_default": false},
	}
	instInDefault := compliancekit.Resource{
		ID: "aws.ec2.instance.i-1", Type: awscol.EC2InstanceType, Name: "i-1", Provider: "aws",
		Attributes: map[string]any{"vpc_id": "vpc-default", "state": "running"},
	}
	instInCustom := compliancekit.Resource{
		ID: "aws.ec2.instance.i-2", Type: awscol.EC2InstanceType, Name: "i-2", Provider: "aws",
		Attributes: map[string]any{"vpc_id": "vpc-custom", "state": "running"},
	}
	g := newGraphWith(defaultVPC, customVPC, instInDefault, instInCustom)
	findings, _ := EC2NoDefaultVPCInUse(context.Background(), g)
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
	// findings[0] is i-1 (in default VPC); but byType order isn't
	// guaranteed -- check by content.
	var defaultFinding, customFinding compliancekit.Status
	for _, f := range findings {
		if f.Resource.Name == "i-1" {
			defaultFinding = f.Status
		}
		if f.Resource.Name == "i-2" {
			customFinding = f.Status
		}
	}
	if defaultFinding != compliancekit.StatusFail {
		t.Errorf("i-1 in default VPC should fail, got %v", defaultFinding)
	}
	if customFinding != compliancekit.StatusPass {
		t.Errorf("i-2 in custom VPC should pass, got %v", customFinding)
	}
}

func TestEC2NoDefaultVPCInUse_StoppedInstanceIgnored(t *testing.T) {
	defaultVPC := compliancekit.Resource{
		ID: "aws.ec2.vpc.vpc-default", Type: awscol.EC2VPCType, Name: "vpc-default", Provider: "aws",
		Attributes: map[string]any{"vpc_id": "vpc-default", "is_default": true},
	}
	stopped := compliancekit.Resource{
		ID: "aws.ec2.instance.i-stopped", Type: awscol.EC2InstanceType, Name: "i-stopped", Provider: "aws",
		Attributes: map[string]any{"vpc_id": "vpc-default", "state": "stopped"},
	}
	g := newGraphWith(defaultVPC, stopped)
	findings, _ := EC2NoDefaultVPCInUse(context.Background(), g)
	if len(findings) != 0 {
		t.Errorf("stopped instances should be skipped, got %d findings", len(findings))
	}
}

func TestEC2IMDSv2Required(t *testing.T) {
	cases := []struct {
		name     string
		state    string
		required bool
		want     int // expected finding count
		wantSt   compliancekit.Status
	}{
		{"running v2 required", "running", true, 1, compliancekit.StatusPass},
		{"running v2 not required", "running", false, 1, compliancekit.StatusFail},
		{"stopped is skipped", "stopped", false, 0, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			inst := compliancekit.Resource{
				ID: "aws.ec2.instance.i-x", Type: awscol.EC2InstanceType, Name: "i-x", Provider: "aws",
				Attributes: map[string]any{"state": c.state, "imdsv2_required": c.required},
			}
			g := newGraphWith(inst)
			findings, _ := EC2IMDSv2Required(context.Background(), g)
			if len(findings) != c.want {
				t.Fatalf("got %d findings, want %d", len(findings), c.want)
			}
			if c.want > 0 && findings[0].Status != c.wantSt {
				t.Errorf("got %v, want %v", findings[0].Status, c.wantSt)
			}
		})
	}
}

func TestEC2EBSEncrypted(t *testing.T) {
	enc := compliancekit.Resource{
		ID: "aws.ec2.volume.vol-1", Type: awscol.EC2VolumeType, Name: "vol-1", Provider: "aws",
		Attributes: map[string]any{"encrypted": true},
	}
	unenc := compliancekit.Resource{
		ID: "aws.ec2.volume.vol-2", Type: awscol.EC2VolumeType, Name: "vol-2", Provider: "aws",
		Attributes: map[string]any{"encrypted": false},
	}
	g := newGraphWith(enc, unenc)
	findings, _ := EC2EBSEncrypted(context.Background(), g)
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
	for _, f := range findings {
		switch f.Resource.Name {
		case "vol-1":
			if f.Status != compliancekit.StatusPass {
				t.Errorf("vol-1 should pass, got %v", f.Status)
			}
		case "vol-2":
			if f.Status != compliancekit.StatusFail {
				t.Errorf("vol-2 should fail, got %v", f.Status)
			}
		}
	}
}

func TestEC2NoPublicAMIs(t *testing.T) {
	pub := compliancekit.Resource{
		ID: "aws.ec2.ami.ami-pub", Type: awscol.EC2AMIType, Name: "ami-pub", Provider: "aws",
		Attributes: map[string]any{"public": true},
	}
	priv := compliancekit.Resource{
		ID: "aws.ec2.ami.ami-priv", Type: awscol.EC2AMIType, Name: "ami-priv", Provider: "aws",
		Attributes: map[string]any{"public": false},
	}
	g := newGraphWith(pub, priv)
	findings, _ := EC2NoPublicAMIs(context.Background(), g)
	for _, f := range findings {
		if f.Resource.Name == "ami-pub" && f.Status != compliancekit.StatusFail {
			t.Errorf("public AMI should fail, got %v", f.Status)
		}
		if f.Resource.Name == "ami-priv" && f.Status != compliancekit.StatusPass {
			t.Errorf("private AMI should pass, got %v", f.Status)
		}
	}
}
