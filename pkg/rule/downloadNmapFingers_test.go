package rule

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDownloadNmapFingers(t *testing.T) {
	require.NoError(t, DownloadNmapFingers())
}
