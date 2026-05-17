package linux

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// v0.20 phase 5 — /etc/login.defs collection for the password-age +
// umask + encryption checks. Single SSH probe; missing file → error.

// LoginDefs captures the integer + string fields v0.20 checks consult.
type LoginDefs struct {
	PassMaxDays    int    // PASS_MAX_DAYS
	PassMinDays    int    // PASS_MIN_DAYS
	PassWarnAge    int    // PASS_WARN_AGE
	EncryptMethod  string // ENCRYPT_METHOD (SHA512 / YESCRYPT / DES / MD5 / ...)
	Umask          string // UMASK (octal, possibly with leading 0)
	HasPassMaxDays bool   // distinguishes "absent" from "= 0"
	HasPassMinDays bool
	HasPassWarnAge bool
	HasUmask       bool
}

const loginDefsCommand = "cat /etc/login.defs 2>/dev/null"

// gatherLoginDefs reads /etc/login.defs over SSH and parses it.
// An empty result means the file was unreadable (rare) — return an
// error so the per-key checks emit StatusError.
func gatherLoginDefs(ctx context.Context, client *ssh.Client) (LoginDefs, error) {
	output, _, err := RunCommand(ctx, client, loginDefsCommand)
	if err != nil {
		return LoginDefs{}, fmt.Errorf("login.defs probe: %w", err)
	}
	parsed := ParseLoginDefs(output)
	if !parsed.HasPassMaxDays && !parsed.HasUmask && parsed.EncryptMethod == "" {
		return LoginDefs{}, fmt.Errorf("login.defs returned no recognizable directives")
	}
	return parsed, nil
}

// ParseLoginDefs converts /etc/login.defs body into the typed struct.
// Format per login.defs(5): whitespace-separated key value pairs, one
// per line; lines starting with # are comments; blank lines ignored.
func ParseLoginDefs(body string) LoginDefs {
	out := LoginDefs{}
	for _, raw := range strings.Split(body, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.ToUpper(fields[0])
		val := fields[1]
		switch key {
		case "PASS_MAX_DAYS":
			if v, err := strconv.Atoi(val); err == nil {
				out.PassMaxDays = v
				out.HasPassMaxDays = true
			}
		case "PASS_MIN_DAYS":
			if v, err := strconv.Atoi(val); err == nil {
				out.PassMinDays = v
				out.HasPassMinDays = true
			}
		case "PASS_WARN_AGE":
			if v, err := strconv.Atoi(val); err == nil {
				out.PassWarnAge = v
				out.HasPassWarnAge = true
			}
		case "ENCRYPT_METHOD":
			out.EncryptMethod = val
		case "UMASK":
			out.Umask = val
			out.HasUmask = true
		}
	}
	return out
}
