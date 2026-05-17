package linux

import "testing"

// v0.20 phase 11 — coverage for aaStatusProfileCount across real
// aa-status output shapes (Ubuntu 22.04 default, RHEL with no
// AppArmor, empty input).

func TestAAStatusProfileCount(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int
	}{
		{
			name: "ubuntu default — 42 profiles",
			body: `apparmor module is loaded.
42 profiles are loaded.
40 profiles are in enforce mode.
2 profiles are in complain mode.
8 processes have profiles defined.
`,
			want: 42,
		},
		{
			name: "indented count line",
			body: `apparmor module is loaded.
   13 profiles are loaded.
`,
			want: 13,
		},
		{
			name: "no profiles loaded — count line absent",
			body: `apparmor module is loaded.
0 processes have profiles defined.
`,
			want: 0,
		},
		{
			name: "empty output (apparmor not installed)",
			body: ``,
			want: 0,
		},
		{
			name: "non-numeric count token — returns 0",
			body: `many profiles are loaded.`,
			want: 0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := aaStatusProfileCount(c.body); got != c.want {
				t.Errorf("got %d, want %d", got, c.want)
			}
		})
	}
}
