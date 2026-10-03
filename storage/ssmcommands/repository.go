// Package ssmcommands exposes service-owned managed-node and Run Command storage contracts.
package ssmcommands

import (
	domain "stackd/internal/services/ssmcommands"
	"stackd/storage/memory"
)

type (
	Repository         = domain.Repository
	Reader             = domain.Reader
	Transaction        = domain.Transaction
	Scope              = domain.Scope
	Key                = domain.Key
	InvocationKey      = domain.InvocationKey
	Node               = domain.Node
	Command            = domain.Command
	Target             = domain.Target
	Invocation         = domain.Invocation
	Plugin             = domain.Plugin
	Notification       = domain.Notification
	AlarmConfiguration = domain.AlarmConfiguration
	AlarmPoll          = domain.AlarmPoll
)

var ErrNotFound = domain.ErrNotFound

func NewMemory(d *memory.Domain) Repository { return domain.NewMemoryRepository(d) }
