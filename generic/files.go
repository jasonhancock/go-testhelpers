package generic

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"os/user"
	"sort"
	"strconv"
	"syscall"
	"testing"

	"github.com/pmezard/go-difflib/difflib"
	"github.com/stretchr/testify/require"
)

// Walk traverses a directory tree and returns the list of files discovered.
func Walk(t *testing.T, root string) []string {
	t.Helper()
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
	t.Helper()
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

func RequirePerms(t *testing.T, path string, perms fs.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, perms, info.Mode().Perm())
}

func RequireOwner(t *testing.T, path string, username string) {
	t.Helper()

	u, err := user.Lookup(username)
	require.NoError(t, err)

	uid, err := strconv.Atoi(u.Uid)
	require.NoError(t, err)

	RequireUID(t, path, uid)
}

func RequireGroup(t *testing.T, path string, groupName string) {
	t.Helper()

	g, err := user.LookupGroup(groupName)
	require.NoError(t, err)

	gid, err := strconv.Atoi(g.Gid)
	require.NoError(t, err)

	RequireGID(t, path, gid)
}

func RequireUID(t *testing.T, path string, owner int) {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)

	stat, ok := info.Sys().(*syscall.Stat_t)
	require.True(t, ok)

	require.Equal(t, owner, int(stat.Uid))
}

func RequireGID(t *testing.T, path string, group int) {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)

	stat, ok := info.Sys().(*syscall.Stat_t)
	require.True(t, ok)

	require.Equal(t, group, int(stat.Gid))
}

// CopyFile copies src to dest atomically by creating an intermediate temporary
// file and then doing an atomic rename.
func CopyFile(t *testing.T, src, dest string) {
	t.Helper()
	fSrc, err := os.Open(src)
	require.NoError(t, err)
	defer fSrc.Close()

	temp := dest + ".temp"
	fDest, err := os.Create(temp)
	require.NoError(t, err)

	_, err = io.Copy(fDest, fSrc)
	require.NoError(t, err)
	require.NoError(t, fDest.Close())

	require.NoError(t, os.Rename(temp, dest))
}
