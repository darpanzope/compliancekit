package evidence

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// manifestName is the filename used for the integrity manifest at the
// pack root. The sha256 suffix matches the convention auditors
// recognize from sha256sum(1)-style files.
const manifestName = "MANIFEST.sha256"

// WriteManifest walks dir, hashes every regular file inside it
// (excluding the manifest itself), and writes the result to
// <dir>/MANIFEST.sha256 in the canonical sha256sum format:
//
//	<hex-digest>  <relative/path>
//
// The relative path uses forward slashes and is rooted at dir so the
// manifest is portable across filesystems. Lines are sorted by path so
// a re-run over identical content produces a byte-stable manifest --
// useful both for diffing packs across periods and for letting an
// auditor verify integrity with:
//
//	cd <pack-root> && sha256sum -c MANIFEST.sha256
//
// Returns the absolute path of the manifest file written.
func WriteManifest(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", dir, err)
	}

	type entry struct {
		rel  string // forward-slash relative path
		hash string // hex sha256 digest
	}
	var entries []entry

	err = filepath.WalkDir(abs, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		// Skip the manifest itself so the file we are writing right
		// now does not appear as a self-reference.
		if filepath.Base(path) == manifestName && filepath.Dir(path) == abs {
			return nil
		}
		h, err := hashFile(path)
		if err != nil {
			return fmt.Errorf("hash %s: %w", path, err)
		}
		rel, err := filepath.Rel(abs, path)
		if err != nil {
			return fmt.Errorf("rel %s: %w", path, err)
		}
		entries = append(entries, entry{
			rel:  filepath.ToSlash(rel),
			hash: h,
		})
		return nil
	})
	if err != nil {
		return "", err
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].rel < entries[j].rel
	})

	var b strings.Builder
	for _, e := range entries {
		// Two-space separator matches GNU coreutils sha256sum so an
		// auditor can verify with `sha256sum -c MANIFEST.sha256`
		// from inside the pack directory.
		fmt.Fprintf(&b, "%s  %s\n", e.hash, e.rel)
	}

	manifestPath := filepath.Join(abs, manifestName)
	if err := os.WriteFile(manifestPath, []byte(b.String()), 0o600); err != nil {
		return "", fmt.Errorf("write %s: %w", manifestPath, err)
	}
	return manifestPath, nil
}

// hashFile streams the file at path through SHA-256 and returns the
// lowercase hex digest. Files are streamed rather than slurped so a
// future evidence pack with multi-megabyte raw captures does not need
// a memory bump.
func hashFile(path string) (string, error) {
	// G304: path is built by filepath.WalkDir from a directory the
	// operator just asked us to write into; no user-controlled
	// component reaches here.
	//nolint:gosec // operator-controlled output path
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
