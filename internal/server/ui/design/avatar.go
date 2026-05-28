package design

import (
	"fmt"
	"hash/fnv"
	"html/template"
)

// avatarHues is the palette the deterministic avatar gradient picks
// from — 12 evenly-spread hues so two different names rarely collide on
// color. Each entry is the base hue; the gradient runs from it to a
// hue +40° around the wheel (Linear-style two-tone diagonal).
var avatarHues = []int{262, 217, 189, 142, 38, 25, 0, 330, 291, 160, 200, 95}

// AvatarGradient returns a deterministic linear-gradient for a name, so
// the same person always renders the same avatar color across sessions
// and pages. Empty name → the brand gradient. The output is typed CSS
// (trusted, derived from a hash — never raw user input in a way that
// could break out of the value) so html/template keeps it intact.
func AvatarGradient(name string) template.CSS {
	if name == "" {
		return template.CSS("var(--gradient-primary)")
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	sum := h.Sum32()
	hue := avatarHues[int(sum)%len(avatarHues)]
	hue2 := (hue + 40) % 360
	//nolint:gosec // value derived from a name hash into a fixed format, not raw input
	return template.CSS(fmt.Sprintf(
		"linear-gradient(135deg, hsl(%d 70%% 55%%), hsl(%d 70%% 45%%))", hue, hue2))
}
