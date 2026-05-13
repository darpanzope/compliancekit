package core

import "testing"

func TestStatus_IsActionable(t *testing.T) {
	cases := map[Status]bool{
		StatusPass:  false,
		StatusFail:  true,
		StatusSkip:  false,
		StatusError: true,
	}
	for s, want := range cases {
		if got := s.IsActionable(); got != want {
			t.Errorf("%s.IsActionable() = %v, want %v", s, got, want)
		}
	}
}
