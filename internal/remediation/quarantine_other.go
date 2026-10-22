//go:build !linux

package remediation

import (
	"context"
	"errors"

	"github.com/ErzenXz/aegis/internal/model"
	"github.com/ErzenXz/aegis/internal/sensors"
)

func (*Quarantine) apply(context.Context, model.SecurityEvent, string) (sensors.Observation, error) {
	return sensors.Observation{}, errors.New("quarantine requires Linux directory-FD containment support")
}

func (*Quarantine) replay(context.Context, func(sensors.Observation) error) error {
	return errors.New("quarantine receipt replay requires Linux directory-FD containment support")
}
