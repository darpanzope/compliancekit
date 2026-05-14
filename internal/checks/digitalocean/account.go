package digitalocean

import (
	"context"
	"fmt"

	docol "github.com/darpanzope/compliancekit/internal/collectors/digitalocean"
	"github.com/darpanzope/compliancekit/internal/core"
)

// CheckAccountStatusActive flags any account whose status is not
// "active". DO uses status to surface billing failures (warning),
// ToS holds (locked), and account suspension (suspended). A non-
// active account cannot reliably scale, snapshot, or recover.
var CheckAccountStatusActive = core.Check{
	ID:           "do-account-status-active",
	Title:        "DigitalOcean account must be in 'active' status",
	Severity:     core.SeverityHigh,
	Provider:     "digitalocean",
	Service:      "account",
	ResourceType: docol.AccountType,
	Description: "DigitalOcean's account.status field surfaces billing " +
		"failures, ToS holds, and suspensions. A 'warning' or 'locked' " +
		"account loses access to new droplet creation, snapshot " +
		"restoration, and any recovery flow that depends on billing " +
		"being current. Continuous compliance evidence becomes " +
		"impossible to collect from a non-active account.",
	Remediation: "Check the DO control panel for the operative warning. " +
		"Common causes: expired payment method, exceeded prepaid " +
		"balance, ToS dispute. Resolve before any subsequent " +
		"compliance-relevant change; everything else in this report " +
		"depends on the platform being responsive.",
	Frameworks: map[string][]string{
		"soc2":     {"A1.2", "CC9.1"},
		"iso27001": {"A.5.30", "A.8.6"},
		"cis-v8":   {"11.1"},
	},
	Tags:    []string{"account", "platform-health"},
	Scanner: "account.StatusActive",
}

func AccountStatusActive(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, a := range g.ByType(docol.AccountType) {
		status, _ := a.Attributes["status"].(string)
		msg, _ := a.Attributes["status_message"].(string)
		f := core.Finding{
			CheckID:  CheckAccountStatusActive.ID,
			Severity: CheckAccountStatusActive.Severity,
			Resource: a.Ref(),
			Tags:     CheckAccountStatusActive.Tags,
		}
		if status == "active" {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("account %q: active", a.Name)
		} else {
			f.Status = core.StatusFail
			if msg != "" {
				f.Message = fmt.Sprintf("account %q: status=%q (%s)", a.Name, status, msg)
			} else {
				f.Message = fmt.Sprintf("account %q: status=%q", a.Name, status)
			}
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckAccountEmailVerified requires the account's primary email be
// verified with DO. An unverified email blocks billing alerts,
// password reset, and 2FA recovery flows.
var CheckAccountEmailVerified = core.Check{
	ID:           "do-account-email-verified",
	Title:        "DigitalOcean account email must be verified",
	Severity:     core.SeverityMedium,
	Provider:     "digitalocean",
	Service:      "account",
	ResourceType: docol.AccountType,
	Description: "Email verification is the prerequisite for billing " +
		"alerts, password-reset flows, and 2FA recovery codes being " +
		"delivered to the right inbox. An unverified email means " +
		"every account-recovery story falls back to support tickets, " +
		"which is too slow for incident response.",
	Remediation: "Open the verification email DO sent at signup. If " +
		"missing, log in and request a fresh one from Settings > " +
		"Account. Change the address first if the current one is " +
		"compromised or a personal inbox -- production accounts " +
		"should point at a role-based address (eg. ops@example.com) " +
		"with at least two readers.",
	Frameworks: map[string][]string{
		"soc2":     {"CC6.1", "CC6.7"},
		"iso27001": {"A.5.16", "A.5.17"},
		"cis-v8":   {"6.1", "6.7"},
	},
	Tags:    []string{"account", "identity"},
	Scanner: "account.EmailVerified",
}

func AccountEmailVerified(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, a := range g.ByType(docol.AccountType) {
		verified, _ := a.Attributes["email_verified"].(bool)
		f := core.Finding{
			CheckID:  CheckAccountEmailVerified.ID,
			Severity: CheckAccountEmailVerified.Severity,
			Resource: a.Ref(),
			Tags:     CheckAccountEmailVerified.Tags,
		}
		if verified {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("account %q: email verified", a.Name)
		} else {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("account %q: email NOT verified", a.Name)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// CheckAccountUsesNamedTeam requires the account belong to a named
// (i.e. multi-user) team rather than the implicit single-user
// "Personal" team DO creates for new accounts. Single-user prod
// accounts have no continuity if the human is unavailable.
var CheckAccountUsesNamedTeam = core.Check{
	ID:           "do-account-uses-named-team",
	Title:        "Production DigitalOcean accounts should use a named team",
	Severity:     core.SeverityLow,
	Provider:     "digitalocean",
	Service:      "account",
	ResourceType: docol.AccountType,
	Description: "DigitalOcean creates an implicit 'Personal' team for " +
		"every new account. Running production workloads under the " +
		"Personal team is single-user by definition -- if the operator " +
		"is unavailable (sick, on leave, departed) there is no second " +
		"party authorized to issue tokens, manage billing, or rotate " +
		"credentials. A named team with at least two members is the " +
		"minimum bus-factor.",
	Remediation: "Create a team via 'doctl invoice list --team <name>' " +
		"workflow or the Settings > Team UI. Move resources by " +
		"transferring projects under the new team. Add at least one " +
		"co-administrator. The Personal team can stay for non-prod " +
		"experiments; the audit-relevant workloads belong on a real " +
		"team.",
	Frameworks: map[string][]string{
		"soc2":     {"CC1.4", "CC6.3"},
		"iso27001": {"A.5.2", "A.5.15"},
		"cis-v8":   {"6.7", "6.8"},
	},
	Tags:    []string{"account", "bus-factor"},
	Scanner: "account.UsesNamedTeam",
}

func AccountUsesNamedTeam(_ context.Context, g *core.ResourceGraph) ([]core.Finding, error) {
	findings := []core.Finding{}
	for _, a := range g.ByType(docol.AccountType) {
		teamName, _ := a.Attributes["team_name"].(string)
		f := core.Finding{
			CheckID:  CheckAccountUsesNamedTeam.ID,
			Severity: CheckAccountUsesNamedTeam.Severity,
			Resource: a.Ref(),
			Tags:     CheckAccountUsesNamedTeam.Tags,
		}
		// "Personal" is DO's literal default team name for solo
		// accounts; an empty string means godo couldn't read the
		// team relation, which is also a fail.
		if teamName == "" || teamName == "Personal" {
			f.Status = core.StatusFail
			f.Message = fmt.Sprintf("account %q: team=%q (default single-user team)", a.Name, teamName)
		} else {
			f.Status = core.StatusPass
			f.Message = fmt.Sprintf("account %q: named team %q", a.Name, teamName)
		}
		findings = append(findings, f)
	}
	return findings, nil
}

func init() {
	core.Register(CheckAccountStatusActive, AccountStatusActive)
	core.Register(CheckAccountEmailVerified, AccountEmailVerified)
	core.Register(CheckAccountUsesNamedTeam, AccountUsesNamedTeam)
}
