package generic

import (
	"bytes"
	"io/fs"
	"os"
	"sort"
	"testing"

	"github.com/pmezard/go-difflib/difflib"
	"github.com/stretchr/testify/require"
)

// Walk traverses a directory tree and returns the list of files discovered.
func Walk(t *testing.T, root string) []string {
	fileSystem := os.DirFS(root)

	var files []string
	err := fs.WalkDir(fileSystem, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		files = append(files, path)
		return nil
	})
	require.NoError(t, err)
	sort.Strings(files)
	return files
}

// FilesEqual compares the contents of two files to see if they're equal. If not,
// a unified diff is displayed showing the differences.
func FilesEqual(t *testing.T, expected, actual string) {
	expectedBytes, err := os.ReadFile(expected)
	require.NoError(t, err)

	actualBytes, err := os.ReadFile(actual)
	require.NoError(t, err)

	if bytes.Equal(expectedBytes, actualBytes) {
		return
	}

	diff, err := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A:        difflib.SplitLines(string(expectedBytes)),
		B:        difflib.SplitLines(string(actualBytes)),
		FromFile: "Expected",
		ToFile:   "Actual",
		Context:  1,
	})
	require.NoError(t, err)
	t.Fatal("\n" + diff)
}
