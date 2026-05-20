package comments

import (
	"reflect"
	"testing"
)

func TestExtractMentions(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"single", "Hey @alice, please look at this", []string{"alice"}},
		{"multiple_unique", "@alice + @bob both look", []string{"alice", "bob"}},
		{"dedup", "@alice mentioned with @bob and again @alice", []string{"alice", "bob"}},
		{"email_localpart", "Send to @first.last about it", []string{"first.last"}},
		{"team", "cc @team-backend, decide later", []string{"team-backend"}},
		{"middle_of_word", "user@host should not match", nil},
		{"too_short", "@a means nothing", nil},
		{"leading_dot", "@.weird drop this", nil},
		{"trailing_punct", "hi @alice.", []string{"alice"}},
		{"paren_prefix", "(@alice) for context", []string{"alice"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractMentions(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ExtractMentions(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
