package review

import (
	"fmt"
	"strings"
	"time"

	"github.com/dagucloud/dagu/v2/internal/ir"
)

const (
	// maxCadenceBytes bounds the declared cadence and the zone it is read
	// in; cadenceShownBytes is how much of a longer one is quoted back.
	maxCadenceBytes   = 256
	cadenceShownBytes = 64
)

// ReadCadence reads a job's declared review cadence. A job declares it as a
// cron expression, and it is read in the timezone of the job's own schedule
// (UTC when that is not given): the cadence does not name a zone of its own.
// A plain duration such as "1h" is accepted too, as jobs registered before
// the cadence was read as a cron carry one.
//
// Exactly one of the results is set, or none when no cadence is declared:
// seconds for a duration, the cron expression with its zone, or the reason
// the declared text is neither.
func ReadCadence(declared, timezone string) (seconds int, cron, reason string) {
	// Both texts come from the registry's record. Nothing a person would
	// write as a cadence or a zone is this long, and a longer one is not
	// read at all: reading it costs time and memory in proportion.
	if len(declared) > maxCadenceBytes {
		return 0, "", fmt.Sprintf("review_policy.cadence is %d bytes long, more than the %d a cadence may be; it starts %q", len(declared), maxCadenceBytes, declared[:cadenceShownBytes])
	}
	if len(timezone) > maxCadenceBytes {
		return 0, "", fmt.Sprintf("review_policy.cadence %q cannot be read: the schedule's timezone is %d bytes long, more than the %d a zone name may be", declared, len(timezone), maxCadenceBytes)
	}
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
	if strings.HasPrefix(text, "TZ=") || strings.HasPrefix(text, "CRON_TZ=") {
		return 0, "", fmt.Sprintf("review_policy.cadence %q names a timezone of its own; it is read in the job's schedule.timezone", declared)
	}
	if err := wholeFields(text); err != nil {
		return 0, "", fmt.Sprintf("review_policy.cadence %q is neither a cron expression nor a duration: %v", declared, err)
	}
	expr := text
	// "@every" is an interval on a fixed grid and takes no zone.
	if !strings.HasPrefix(text, "@every ") {
		zone := strings.TrimSpace(timezone)
		if zone == "" {
			zone = "UTC"
		}
		if _, err := time.LoadLocation(zone); err != nil {
			return 0, "", fmt.Sprintf("review_policy.cadence %q cannot be read in the schedule's timezone %q: %v", declared, timezone, err)
		}
		expr = "CRON_TZ=" + zone + " " + text
	}
	schedule, err := parseCron(expr)
	if err != nil {
		return 0, "", fmt.Sprintf("review_policy.cadence %q is neither a cron expression nor a duration: %v", declared, err)
	}
	// An expression can be well formed and name no instant at all, such as
	// 31 February. That is not a cadence either.
	if !schedule.Next(time.Now()).After(time.Time{}) {
		return 0, "", fmt.Sprintf("review_policy.cadence %q never occurs", declared)
	}
	return 0, expr, ""
}

// wholeFields refuses a cron expression with a field that lists nothing,
// such as "," or "1,,2". The cron library reads a field of only commas as a
// field no value satisfies, without an error, and looking for the next
// occurrence of such an expression walks minute by minute through years.
// The text comes from the registry's record, so it is refused before then.
func wholeFields(expr string) error {
	if strings.HasPrefix(expr, "@") {
		return nil
	}
	for field := range strings.FieldsSeq(expr) {
		for item := range strings.SplitSeq(field, ",") {
			if item == "" {
				return fmt.Errorf("the field %q lists an empty value", field)
			}
		}
	}
	return nil
}

// parseCron reads a cron expression with the scheduler's parser. The text
// comes from the registry's record of a job, which is not this machine's:
// the cron library indexes past the end of a zone prefix that is not
// followed by an expression ("TZ=UTC"), so that shape is refused here, and
// any other fault inside the parser is returned as an error instead of
// ending the review process for every job.
func parseCron(expr string) (schedule ir.Schedule, err error) {
	if strings.HasPrefix(expr, "TZ=") || strings.HasPrefix(expr, "CRON_TZ=") {
		if _, rest, found := strings.Cut(expr, " "); !found || strings.TrimSpace(rest) == "" {
			return ir.Schedule{}, fmt.Errorf("a timezone prefix with no expression after it")
		}
	}
	defer func() {
		if r := recover(); r != nil {
			schedule, err = ir.Schedule{}, fmt.Errorf("the cron parser could not read it: %v", r)
		}
	}()
	return ir.NewCronSchedule(expr)
}

// nextReview is when the policy's cadence next asks for a review after
// from. A cron cadence gives its next occurrence, a duration gives from
// plus the duration, and a policy with no readable cadence gives the
// default interval: the reviewer says so to the owner where it reads the
// job (see ExceptionCadenceInvalid), so that default is never silent.
func (p ReviewPolicy) nextReview(from time.Time) time.Time {
	if p.Cadence != "" {
		if s, err := parseCron(p.Cadence); err == nil {
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

// putOff is when a job that could not be reviewed now is looked at again:
// at its cadence, and never less than the minimum interval ahead.
func (p ReviewPolicy) putOff(now time.Time) time.Time {
	return notBefore(p.nextReview(now), now.Add(minReviewInterval))
}

func notBefore(t, floor time.Time) time.Time {
	if t.Before(floor) {
		return floor
	}
	return t
}
