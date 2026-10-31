package sso

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPackageDoesNotDependOnHost(t *testing.T) {
	paths, err := filepath.Glob("*.go")
	require.NoError(t, err)
	for _, path := range paths {
		file, e := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		require.NoError(t, e)
		for _, imp := range file.Imports {
			name, importErr := strconv.Unquote(imp.Path.Value)
			require.NoError(t, importErr)
			require.False(t, strings.HasPrefix(name, "github.com/AdguardTeam/AdGuardHome/internal/"), "SSO must not depend on host packages: %s", name)
		}
	}
}
