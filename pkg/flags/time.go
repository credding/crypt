package flags

import (
	"errors"
	"strconv"
	pkgtime "time"
)

type Time int64

func (t *Time) String() string {
	if *t == 0 {
		return ""
	}
	return strconv.FormatInt(int64(*t), 10)
}

func (t *Time) Set(value string) error {
	val, err := parseTime(value)
	if err != nil {
		return err
	}
	*t = Time(val)
	return nil
}

func (t *Time) Type() string {
	return "duration, or timestamp"
}

func parseTime(value string) (int64, error) {
	time := tryParseDuration(value)
	if time > 0 {
		return time, nil
	}
	time = tryParseRFC3339(value)
	if time > 0 {
		return time, nil
	}
	time = tryParseInt(value)
	if time > 0 {
		return time, nil
	}
	return 0, errors.New("expected duration, rfc3339 timestamp, or unix timestamp")
}

func tryParseDuration(value string) int64 {
	duration, err := pkgtime.ParseDuration(value)
	if err != nil {
		return 0
	}
	return pkgtime.Now().Add(duration).Unix()
}

func tryParseRFC3339(value string) int64 {
	time, err := pkgtime.Parse(pkgtime.RFC3339, value)
	if err != nil {
		return 0
	}
	return time.Unix()
}

func tryParseInt(value string) int64 {
	i, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0
	}
	return i
}
