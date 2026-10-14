package review_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/spec"
	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
	"github.com/dagucloud/dagu/v2/internal/txe/review"
)

// The reviewer's runs carry each review's packet and decision as artifacts,
// and the decision DAG's runs carry the person's answers. Both DAGs declare
// TXE's run history, so neither gets Dagu's 30-day default, and a base
// configuration that sets days or runs for every DAG does not replace it.
func TestReviewDAGsKeepRunHistory(t *testing.T) {
	dags, err := review.RenderDAGs(review.DAGConfig{MachineID: "mch_0000000000000000000F1XT001", StateDir: "/var/lib/txe/state"})
	require.NoError(t, err)

	for name, data := range map[string]string{"reviewer": dags.Reviewer, "decide": dags.Decide} {
		for _, base := range []string{"", "hist_retention_days: 1\n", "hist_retention_runs: 2\n"} {
			var opts []spec.LoadOption
			if base != "" {
				opts = append(opts, spec.WithBaseConfigContent([]byte(base)))
			}
			dag, err := spec.LoadYAML(context.Background(), []byte(data), opts...)
			require.NoError(t, err, name)
			assert.Equal(t, txepkg.HistRetentionDays, dag.HistRetentionDays, "%s over base %q", name, base)
			assert.Zero(t, dag.HistRetentionRuns, "%s over base %q", name, base)
		}
	}
}
