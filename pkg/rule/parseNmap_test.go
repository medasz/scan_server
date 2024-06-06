package rule

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseNmap(t *testing.T) {
	ParseNmap()
	require.NotEmpty(t, Fingers)
}
