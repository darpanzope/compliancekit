// Package azcli implements remediate.Strategy renderers for the
// FormatAzureCLI output. Azure findings flow into compliancekit via
// the OCSF ingest adapter (Microsoft Defender for Cloud) at v0.13;
// CheckIDs are namespaced as `ingest.defender-for-cloud.<RULE_ID>`.
// This package emits `az <service> ...` commands keyed off those
// rule IDs.
//
// Coverage at v0.15: the Defender rules already mapped in
// internal/ingest/ocsf/mappings/defender-for-cloud.yaml (Storage,
// SQL, RBAC). Operators can layer their own strategies against
// additional rule IDs by registering against this package's
// Strategy interface.
package azcli

import (
	"fmt"

	"github.com/darpanzope/compliancekit/internal/remediate"
	"github.com/darpanzope/compliancekit/internal/remediate/render"
	"github.com/darpanzope/compliancekit/pkg/compliancekit"
)

type strategyFunc func(compliancekit.Finding) (remediate.Snippet, error)

type strategy struct {
	name string
	ids  []string
	fn   strategyFunc
}

func (s *strategy) Name() string                { return s.name }
func (s *strategy) CheckIDs() []string          { return s.ids }
func (s *strategy) Formats() []remediate.Format { return []remediate.Format{remediate.FormatAzureCLI} }
func (s *strategy) Render(f compliancekit.Finding, format remediate.Format) (remediate.Snippet, error) {
	if format != remediate.FormatAzureCLI {
		return remediate.Snippet{}, remediate.ErrFormatUnsupported
	}
	return s.fn(f)
}

func register(name string, ids []string, fn strategyFunc) {
	remediate.Register(&strategy{name: name, ids: ids, fn: fn})
}

func init() {
	register("az-storage-no-public-blob",
		[]string{"ingest.defender-for-cloud.STORAGE_ACCOUNT_PUBLIC_ACCESS"}, renderStorageNoPublic)
	register("az-storage-encryption-at-rest",
		[]string{"ingest.defender-for-cloud.STORAGE_ENCRYPTION_AT_REST"}, renderStorageEncryption)
	register("az-sql-tde",
		[]string{"ingest.defender-for-cloud.SQL_TDE_ENABLED"}, renderSQLTDE)
	register("az-sql-auditing",
		[]string{"ingest.defender-for-cloud.SQL_AUDITING_ENABLED"}, renderSQLAuditing)
	register("az-sql-firewall-allow-all",
		[]string{"ingest.defender-for-cloud.SQL_FIREWALL_ALLOW_ALL"}, renderSQLFirewallTighten)
	register("az-rbac-owner-manual",
		[]string{"ingest.defender-for-cloud.RBAC_BUILT_IN_OWNER"}, renderRBACOwnerManual)
}

func renderStorageNoPublic(f compliancekit.Finding) (remediate.Snippet, error) {
	acct := accountName(f)
	cmd := fmt.Sprintf(
		"az storage account update --name %s --allow-blob-public-access false",
		render.ShellQuote(acct))
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: cmd,
		VerifyCmd:   fmt.Sprintf("az storage account show --name %s --query allowBlobPublicAccess", render.ShellQuote(acct)),
		RollbackCmd: fmt.Sprintf("az storage account update --name %s --allow-blob-public-access true", render.ShellQuote(acct)),
		Notes:       "Disables public-blob-anonymous-read at the account level. Per-container public-access flags remain but new public reads return 403.",
	}, nil
}

func renderStorageEncryption(f compliancekit.Finding) (remediate.Snippet, error) {
	acct := accountName(f)
	cmd := fmt.Sprintf(
		`# Verify encryption-at-rest is on (Microsoft-managed keys default).
az storage account show --name %s --query encryption
# To switch to customer-managed keys (CMK):
# az storage account update --name %s --encryption-key-source Microsoft.Keyvault \
#   --encryption-key-vault https://VAULT.vault.azure.net/ --encryption-key-name KEY --encryption-key-version VERSION`,
		render.ShellQuote(acct), render.ShellQuote(acct))
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: cmd,
		Notes: "Azure storage encryption-at-rest is on by default with Microsoft-managed keys; the finding usually means the operator wants CMK control. Provision Key Vault + key first.",
	}, nil
}

func renderSQLTDE(f compliancekit.Finding) (remediate.Snippet, error) {
	srv := serverName(f)
	cmd := fmt.Sprintf(
		"az sql db tde set --resource-group $RG --server %s --database $DB --status Enabled",
		render.ShellQuote(srv))
	return remediate.Snippet{
		Risk: remediate.RiskSafe, Idempotent: true, Content: cmd,
		VerifyCmd: fmt.Sprintf("az sql db tde show --resource-group $RG --server %s --database $DB --query status", render.ShellQuote(srv)),
		Notes:     "Transparent Data Encryption. New databases default to Enabled in recent Azure SQL; older instances may still report disabled. Replace $RG and $DB.",
	}, nil
}

func renderSQLAuditing(f compliancekit.Finding) (remediate.Snippet, error) {
	srv := serverName(f)
	cmd := fmt.Sprintf(
		`az sql server audit-policy update --resource-group $RG --name %s --state Enabled \
  --storage-account $STORAGE_ACCOUNT --retention-days 90`,
		render.ShellQuote(srv))
	return remediate.Snippet{
		Risk: remediate.RiskReview, Idempotent: true, Content: cmd,
		VerifyCmd: fmt.Sprintf("az sql server audit-policy show --resource-group $RG --name %s --query state", render.ShellQuote(srv)),
		Notes:     "Server-level audit policy applies to every database. Requires a storage account destination — pre-provision one or use Log Analytics workspace via --log-analytics-target-state.",
	}, nil
}

func renderSQLFirewallTighten(f compliancekit.Finding) (remediate.Snippet, error) {
	srv := serverName(f)
	cmd := fmt.Sprintf(
		`# Inspect existing rules (look for 0.0.0.0 - 255.255.255.255).
az sql server firewall-rule list --resource-group $RG --server %s

# Replace the AllowAll rule with a tight CIDR (here 10.0.0.0/8 example).
# az sql server firewall-rule delete --resource-group $RG --server %s --name AllowAll
# az sql server firewall-rule create --resource-group $RG --server %s --name corp-only \
#   --start-ip-address 10.0.0.1 --end-ip-address 10.255.255.254`,
		render.ShellQuote(srv), render.ShellQuote(srv), render.ShellQuote(srv))
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false, Content: cmd,
		Notes: "0.0.0.0/0 SQL firewall is the highest-risk Defender finding (data exfiltration vector). Inspect-then-replace; never blindly delete because legitimate consumers may have IPs in the open range.",
	}, nil
}

func renderRBACOwnerManual(f compliancekit.Finding) (remediate.Snippet, error) {
	return remediate.Snippet{
		Risk: remediate.RiskManual, Idempotent: false,
		Content: fmt.Sprintf(
			"# List Owner role assignments at subscription scope.\naz role assignment list --role Owner --scope /subscriptions/$SUB_ID\n"+
				"# For each principal, decide a least-privilege replacement (Contributor + Resource-specific roles), then:\n"+
				"# az role assignment delete --role Owner --assignee PRINCIPAL --scope /subscriptions/$SUB_ID\n"+
				"# az role assignment create --role 'Contributor' --assignee PRINCIPAL --scope /subscriptions/$SUB_ID\n"+
				"# Finding %q.",
			f.CheckID),
		Notes: "Built-in Owner role grants full management + delegation rights. Replace with Contributor (no delegation) + targeted resource roles unless the principal genuinely needs to manage IAM.",
	}, nil
}

// accountName extracts the storage account name from the finding's
// resource. OCSF Defender findings encode the Azure resource path
// in Resource.Name when produced by the ingest adapter.
func accountName(f compliancekit.Finding) string {
	if f.Resource.Name != "" {
		return f.Resource.Name
	}
	return "REPLACE_STORAGE_ACCOUNT"
}

// serverName extracts a SQL server name analogously.
func serverName(f compliancekit.Finding) string {
	if f.Resource.Name != "" {
		return f.Resource.Name
	}
	return "REPLACE_SQL_SERVER"
}
