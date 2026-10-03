// Package codepipeline exposes the typed CodePipeline repository contract.
package codepipeline

import service "stackd/internal/services/codepipeline"

type Scope = service.Scope
type Pipeline = service.Pipeline
type Definition = service.Definition
type Transition = service.Transition
type Execution = service.Execution
type ActionExecution = service.ActionExecution
type Artifact = service.Artifact
type SourceRevision = service.SourceRevision
type SourcePoll = service.SourcePoll
type InvocationJob = service.InvocationJob
type Reader = service.Reader
type Transaction = service.Transaction
type Repository = service.Repository
type MemoryRepository = service.MemoryRepository

var NewMemory = service.NewMemoryRepository
