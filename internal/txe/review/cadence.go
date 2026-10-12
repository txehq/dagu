package review

import (
	"fmt"
	"strings"
	"time"

	"github.com/dagucloud/dagu/v2/internal/ir"
)

// ReadCadence reads a job's declared review cadence. A job declares it as a
// cron expression, read in the timezone of the job's own schedule (UTC when
// that is not given); an expression that names its own zone with a TZ= or
// CRON_TZ= prefix keeps it. A plain duration such as "1h" is accepted too,
// as jobs registered before the cadence was read as a cron carry one.
//
// Exactly one of the results is set, or none when no cadence is declared:
// seconds for a duration, the cron expression with its zone, or the reason
// the declared text is neither.
func ReadCadence(declared, timezone string) (seconds int, cron, reason string) {
	text := strings.Join(strings.Fields(declared), " ")
	if text == "" {
		return 0, "", ""
	}
	if d, err := time.ParseDuration(text); err == nil {
		if d < time.Second {
			return 0, "", fmt.Sprintf("review_policy.cadence %q is not a positive duration", declared)
		}
		return int(d / time.Second), "", ""
	}
	expr := text
	if !strings.HasPrefix(text, "TZ=") && !strings.HasPrefix(text, "CRON_TZ=") && !strings.HasPrefix(text, "@every ") {
		zone := strings.TrimSpace(timezone)
		if zone == "" {
			zone = "UTC"
		}
		if _, err := time.LoadLocation(zone); err != nil {
			return 0, "", fmt.Sprintf("review_policy.cadence %q cannot be read in the schedule's timezone %q: %v", declared, timezone, err)
		}
		expr = "CRON_TZ=" + zone + " " + text
	}
	if _, err := ir.NewCronSchedule(expr); err != nil {
		return 0, "", fmt.Sprintf("review_policy.cadence %q is neither a cron expression nor a duration: %v", declared, err)
	}
	return 0, expr, ""
}

// nextReview is when the policy's cadence next asks for a review after
// from. A cron cadence gives its next occurrence, a duration gives from
// plus the duration, and a policy with no readable cadence gives the
// default interval: the reviewer says so to the owner where it reads the
// job (see ExceptionCadenceInvalid), so that default is never silent.
func (p ReviewPolicy) nextReview(from time.Time) time.Time {
	if p.Cadence != "" {
		if s, err := ir.NewCronSchedule(p.Cadence); err == nil {
			if next := s.Next(from); next.After(from) {
				return next
			}
		}
	}
	if p.CadenceSec > 0 {
		return from.Add(time.Duration(p.CadenceSec) * time.Second)
	}
	return from.Add(defaultCadence)
}
