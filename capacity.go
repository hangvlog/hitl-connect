package main

import "errors"

// Bounds are local resource budgets, never authorization grants. Active streams
// retain their slot until closed; reducing demand only retires idle channels.
type capacitySettings struct {
	CallerConnections   int `json:"callerConnections,omitempty"`
	CallerQueue         int `json:"callerQueue,omitempty"`
	ProviderConnections int `json:"providerConnections,omitempty"`
	MaxIdleChannels     int `json:"maxIdleChannels,omitempty"`
}

func (c *Config) capacity() capacitySettings {
	v := c.Capacity
	if v.CallerConnections == 0 {
		v.CallerConnections = 32
	}
	if v.CallerQueue == 0 {
		v.CallerQueue = 128
	}
	if v.ProviderConnections == 0 {
		v.ProviderConnections = 64
	}
	if v.MaxIdleChannels == 0 {
		v.MaxIdleChannels = 16
	}
	return v
}

func (c *Config) validateCapacity() error {
	v := c.capacity()
	if v.CallerConnections < 1 || v.CallerConnections > 128 || v.CallerQueue < 1 || v.CallerQueue > 256 ||
		v.ProviderConnections < 1 || v.ProviderConnections > 128 || v.MaxIdleChannels < 1 || v.MaxIdleChannels > 16 ||
		(c.IdleChannels > 0 && c.IdleChannels > v.MaxIdleChannels) {
		return errors.New("invalid capacity: connections 1-128, queue 1-256, idle channels 1-16")
	}
	return nil
}

func desiredIdle(base, maximum, active int) int { return min(maximum, base+active/4) }
