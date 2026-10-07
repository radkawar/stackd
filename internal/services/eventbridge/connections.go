package eventbridge

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"stackd/internal/apievents"
	"stackd/internal/authorization"
	api "stackd/internal/awsapi/eventbridge"
	"stackd/internal/awswire"
)

func (s *Service) registerConnections() {
	register(s, "CreateConnection", s.createConnection)
	register(s, "UpdateConnection", s.updateConnection)
	register(s, "DescribeConnection", s.describeConnection)
	register(s, "ListConnections", s.listConnections)
	register(s, "DeleteConnection", s.deleteConnection)
	register(s, "DeauthorizeConnection", s.deauthorizeConnection)
}
func connectionMutationError(ctx context.Context, err error) *awswire.Error {
	var dependency interface{ RecordRejection(context.Context) error }
	if errors.As(err, &dependency) {
		completion, cancel := apievents.CompletionContext(ctx)
		defer cancel()
		if rejected := dependency.RecordRejection(completion); rejected != nil {
			return wireError(rejected)
		}
	}
	return wireError(err)
}
func connectionMissing(k ConnectionKey) *awswire.Error {
	return failure("ResourceNotFoundException", "Failed to describe the connection(s). Connection '"+k.Name+"' does not exist.")
}
func readConnection(r Reader, k ConnectionKey) (ConnectionRecord, error) {
	v, err := r.Connection(k)
	if errors.Is(err, ErrNotFound) {
		return v, connectionMissing(k)
	}
	if err == nil {
		err = cloudFormationCheck(r.Context(), "Connection", v.CFNOwner)
	}
	return v, err
}
func (s *Service) authorizeConnection(r Reader, action string, v ConnectionRecord) error {
	return s.authorize(r, action, v.ARN(), nil, nil, authorization.BoundPolicy{})
}
func connectionTime(v time.Time) *api.Timestamp {
	if v.IsZero() {
		return nil
	}
	return ptr(api.Timestamp(v))
}
func connectionSummary(v ConnectionRecord) api.Connection {
	out := api.Connection{ConnectionArn: str[api.ConnectionArn](v.ARN()), Name: str[api.ConnectionName](v.Key.Name), AuthorizationType: str[api.ConnectionAuthorizationType](v.AuthorizationType), ConnectionState: str[api.ConnectionState](v.State), CreationTime: connectionTime(v.Created), LastModifiedTime: connectionTime(v.Modified), LastAuthorizedTime: connectionTime(v.LastAuthorized)}
	if v.StateReason != "" && v.State != "DEAUTHORIZING" {
		out.StateReason = str[api.ConnectionStateReason](v.StateReason)
	}
	return out
}
func (s *Service) createConnection(ctx context.Context, in *api.CreateConnectionInput) (out *api.CreateConnectionOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "CreateConnection", in, &out, &rejected, false)
	if in.InvocationConnectivityParameters != nil {
		return nil, connectionPrivateUnsupported()
	}
	credentials, wire := createConnectionSecret(value(in.AuthorizationType), in.AuthParameters)
	if wire != nil {
		return nil, wire
	}
	if s.connectionSecrets == nil {
		return nil, unsupported("EventBridge Connections require a Secrets Manager owner.")
	}
	body, wire := encodeConnectionSecret(credentials)
	if wire != nil {
		return nil, wire
	}
	v := ConnectionRecord{Key: ConnectionKey{scopeFor(ctx), value(in.Name)}, ID: identifier(), Description: value(in.Description), KmsKeyIdentifier: value(in.KmsKeyIdentifier), AuthorizationType: value(in.AuthorizationType), State: "AUTHORIZED", Version: 1}
	v.CFNOwner = cloudFormationClaim(ctx, "Connection")
	projectConnectionSecret(&v, credentials)
	err := s.repository.Update(ctx, func(tx Transaction) error {
		if err := s.authorizeConnection(tx, "CreateConnection", v); err != nil {
			return err
		}
		if _, err := tx.Connection(v.Key); err == nil {
			return failure("ResourceAlreadyExistsException", "Connection '"+v.Key.Name+"' already exists.")
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		var wire *awswire.Error
		v.SecretARN, wire = s.connectionSecrets.Create(tx.Context(), v.ARN(), "events!connection/"+v.Key.Name+"/"+identifier(), v.KmsKeyIdentifier, body)
		if wire != nil {
			return wire
		}
		v.Created = s.clock.Now().Truncate(time.Second)
		v.Modified = v.Created
		if v.AuthorizationType == "OAUTH_CLIENT_CREDENTIALS" {
			v.State = "AUTHORIZING"
			v.Due = s.clock.Now()
		} else {
			v.LastAuthorized = v.Created
		}
		if err := tx.PutConnection(v); err != nil {
			return err
		}
		out = &api.CreateConnectionOutput{ConnectionArn: str[api.ConnectionArn](v.ARN()), ConnectionState: str[api.ConnectionState](v.State), CreationTime: connectionTime(v.Created), LastModifiedTime: connectionTime(v.Modified)}
		return s.recordCall(tx.Context(), "CreateConnection", in, out, nil)
	})
	if err != nil {
		return nil, connectionMutationError(ctx, err)
	}
	s.jobs.Wake()
	return out, nil
}
func (s *Service) describeConnection(ctx context.Context, in *api.DescribeConnectionInput) (out *api.DescribeConnectionOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "DescribeConnection", in, &out, &rejected, true)
	k := ConnectionKey{scopeFor(ctx), value(in.Name)}
	var v ConnectionRecord
	err := s.repository.View(ctx, func(r Reader) error {
		var err error
		v, err = readConnection(r, k)
		if err != nil {
			return err
		}
		return s.authorizeConnection(r, "DescribeConnection", v)
	})
	if err != nil {
		return nil, wireError(err)
	}
	summary := connectionSummary(v)
	out = &api.DescribeConnectionOutput{ConnectionArn: summary.ConnectionArn, Name: summary.Name, ConnectionState: summary.ConnectionState, AuthorizationType: summary.AuthorizationType, CreationTime: summary.CreationTime, LastModifiedTime: summary.LastModifiedTime, LastAuthorizedTime: summary.LastAuthorizedTime, StateReason: summary.StateReason, SecretArn: str[api.SecretsManagerSecretArn](v.SecretARN), AuthParameters: publicConnectionAuth(v)}
	if v.State == "DEAUTHORIZED" {
		out.SecretArn = nil
	}
	if v.Description != "" {
		out.Description = str[api.ConnectionDescription](v.Description)
	}
	if v.KmsKeyIdentifier != "" {
		out.KmsKeyIdentifier = str[api.KmsKeyIdentifier](v.KmsKeyIdentifier)
	}
	return out, nil
}
func (s *Service) listConnections(ctx context.Context, in *api.ListConnectionsInput) (out *api.ListConnectionsOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "ListConnections", in, &out, &rejected, true)
	scope := scopeFor(ctx)
	var rows []ConnectionRecord
	err := s.repository.View(ctx, func(r Reader) error {
		if err := s.authorize(r, "ListConnections", "*", nil, nil, authorization.BoundPolicy{}); err != nil {
			return err
		}
		var err error
		rows, err = r.Connections(scope)
		return err
	})
	if err != nil {
		return nil, wireError(err)
	}
	rows = slices.DeleteFunc(rows, func(v ConnectionRecord) bool {
		return !strings.HasPrefix(v.Key.Name, value(in.NamePrefix)) || in.ConnectionState != nil && v.State != value(in.ConnectionState)
	})
	collection := "connections:" + scope.Partition + ":" + scope.Account + ":" + scope.Region + ":" + value(in.NamePrefix) + ":" + value(in.ConnectionState)
	selected, next, wire := page(rows, func(v ConnectionRecord) string { return v.Key.Name }, collection, in.Limit, in.NextToken, "ValidationException")
	if wire != nil {
		return nil, wire
	}
	out = &api.ListConnectionsOutput{Connections: api.ConnectionResponseList{}, NextToken: next}
	for _, v := range selected {
		out.Connections = append(out.Connections, connectionSummary(v))
	}
	return out, nil
}
func connectionPublicEqual(a, b ConnectionRecord) bool {
	return a.AuthorizationType == b.AuthorizationType && a.Username == b.Username && a.APIKeyName == b.APIKeyName && a.ClientID == b.ClientID && a.AuthorizationEndpoint == b.AuthorizationEndpoint && a.OAuthMethod == b.OAuthMethod && a.HasAuth == b.HasAuth && a.HasInvocation == b.HasInvocation && a.HasOAuthHTTP == b.HasOAuthHTTP && slices.Equal(a.Parameters, b.Parameters)
}
func (s *Service) updateConnection(ctx context.Context, in *api.UpdateConnectionInput) (out *api.UpdateConnectionOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "UpdateConnection", in, &out, &rejected, false)
	if in.InvocationConnectivityParameters != nil || in.AuthParameters != nil && in.AuthParameters.ConnectivityParameters != nil {
		return nil, connectionPrivateUnsupported()
	}
	authChange := in.AuthorizationType != nil && in.AuthParameters != nil && (in.AuthParameters.BasicAuthParameters != nil || in.AuthParameters.ApiKeyAuthParameters != nil || in.AuthParameters.OAuthParameters != nil)
	if !authChange && in.Description == nil && in.KmsKeyIdentifier == nil {
		return nil, connectionAuthError("Failed to update the connection(s). At least one of the following is required: Description, KmsKeyIdentifier, AuthorizationType with BasicAuthParameters, ApiKeyAuthParameters, or OAuthParameters.")
	}
	k := ConnectionKey{scopeFor(ctx), value(in.Name)}
	var changed ConnectionRecord
	err := s.repository.Update(ctx, func(tx Transaction) error {
		v, err := readConnection(tx, k)
		if err != nil {
			return err
		}
		if err = s.authorizeConnection(tx, "UpdateConnection", v); err != nil {
			return err
		}
		if v.State == "DELETING" {
			return failure("ConcurrentModificationException", "Connection is being deleted.")
		}
		if v.State == "DEAUTHORIZING" {
			return failure("ConcurrentModificationException", "Failed to update the connection(s). Connection '"+v.Key.Name+"' was modified concurrently.")
		}
		old := v
		if in.Description != nil {
			v.Description = value(in.Description)
			v.Modified = s.clock.Now().Truncate(time.Second)
		}
		if in.KmsKeyIdentifier != nil {
			v.KmsKeyIdentifier = value(in.KmsKeyIdentifier)
			v.Modified = s.clock.Now().Truncate(time.Second)
		}
		if authChange || in.KmsKeyIdentifier != nil && v.HasAuth {
			if s.connectionSecrets == nil {
				return unsupported("EventBridge Connections require a Secrets Manager owner.")
			}
			c := connectionSecret{}
			if v.HasAuth && (in.AuthorizationType == nil || value(in.AuthorizationType) == v.AuthorizationType) {
				body, wire := s.connectionSecrets.ReadOwned(tx.Context(), v.ARN(), v.SecretARN)
				if wire != nil {
					return wire
				}
				c, wire = decodeConnectionSecret(body)
				if wire != nil {
					return wire
				}
			}
			if authChange {
				v.AuthorizationType = value(in.AuthorizationType)
				var wire *awswire.Error
				c, wire = updateConnectionSecret(v.AuthorizationType, in.AuthParameters, c)
				if wire != nil {
					return wire
				}
			}
			body, wire := encodeConnectionSecret(c)
			if wire != nil {
				return wire
			}
			if !old.HasAuth {
				v.SecretARN, wire = s.connectionSecrets.Create(tx.Context(), v.ARN(), "events!connection/"+v.Key.Name+"/"+identifier(), v.KmsKeyIdentifier, body)
			} else {
				var key *string
				if in.KmsKeyIdentifier != nil {
					key = &v.KmsKeyIdentifier
				}
				wire = s.connectionSecrets.Update(tx.Context(), v.ARN(), v.SecretARN, key, body)
			}
			if wire != nil {
				return wire
			}
			projectConnectionSecret(&v, c)
			if !connectionPublicEqual(old, v) {
				v.Modified = s.clock.Now().Truncate(time.Second)
			}
			if authChange {
				v.StateReason = ""
				v.Due = time.Time{}
				if v.AuthorizationType == "OAUTH_CLIENT_CREDENTIALS" {
					v.State = "AUTHORIZING"
					v.Due = s.clock.Now()
				} else {
					v.State = "AUTHORIZED"
					v.LastAuthorized = s.clock.Now().Truncate(time.Second)
				}
			}
		}
		v.Version++
		if err := s.updateConnectionAPIDestinations(tx, old, v); err != nil {
			return err
		}
		if err := tx.PutConnection(v); err != nil {
			return err
		}
		changed = v
		out = &api.UpdateConnectionOutput{ConnectionArn: str[api.ConnectionArn](v.ARN()), ConnectionState: str[api.ConnectionState](v.State), CreationTime: connectionTime(v.Created), LastModifiedTime: connectionTime(v.Modified), LastAuthorizedTime: connectionTime(v.LastAuthorized)}
		return s.recordCall(tx.Context(), "UpdateConnection", in, out, nil)
	})
	if err != nil {
		return nil, connectionMutationError(ctx, err)
	}
	s.connectionTokens.remove(changed.ID)
	s.cancelAPIDestination(changed.ID)
	s.jobs.Wake()
	return out, nil
}
func (s *Service) deauthorizeConnection(ctx context.Context, in *api.DeauthorizeConnectionInput) (out *api.DeauthorizeConnectionOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "DeauthorizeConnection", in, &out, &rejected, false)
	k := ConnectionKey{scopeFor(ctx), value(in.Name)}
	id := ""
	err := s.repository.Update(ctx, func(tx Transaction) error {
		v, err := readConnection(tx, k)
		if err != nil {
			return err
		}
		if err = s.authorizeConnection(tx, "DeauthorizeConnection", v); err != nil {
			return err
		}
		if v.State == "DELETING" {
			return failure("ConcurrentModificationException", "Connection is being deleted.")
		}
		old := v
		priorModified := v.Modified
		if v.HasAuth {
			if s.connectionSecrets == nil {
				return unsupported("EventBridge Connections require a Secrets Manager owner.")
			}
			if wire := s.connectionSecrets.Delete(tx.Context(), v.ARN(), v.SecretARN); wire != nil {
				return wire
			}
			v.HasAuth, v.HasInvocation, v.HasOAuthHTTP = false, false, false
			v.Parameters = nil
			v.Username, v.APIKeyName, v.ClientID, v.AuthorizationEndpoint, v.OAuthMethod = "", "", "", "", ""
			v.State = "DEAUTHORIZING"
			v.StateReason = "The authorization parameters were removed from this connection by a DeauthorizeConnection operation."
			v.Modified = s.clock.Now().Truncate(time.Second)
			v.Due = s.clock.Now().Add(time.Second)
			v.Version++
			if err := s.updateConnectionAPIDestinations(tx, old, v); err != nil {
				return err
			}
			if err := tx.PutConnection(v); err != nil {
				return err
			}
		}
		id = v.ID
		out = &api.DeauthorizeConnectionOutput{ConnectionArn: str[api.ConnectionArn](v.ARN()), ConnectionState: str[api.ConnectionState](v.State), CreationTime: connectionTime(v.Created), LastModifiedTime: connectionTime(priorModified), LastAuthorizedTime: connectionTime(v.LastAuthorized)}
		return s.recordCall(tx.Context(), "DeauthorizeConnection", in, out, nil)
	})
	if err != nil {
		return nil, connectionMutationError(ctx, err)
	}
	s.connectionTokens.remove(id)
	s.cancelAPIDestination(id)
	s.jobs.Wake()
	return out, nil
}
func (s *Service) deleteConnection(ctx context.Context, in *api.DeleteConnectionInput) (out *api.DeleteConnectionOutput, rejected *awswire.Error) {
	defer finishCall(s, ctx, "DeleteConnection", in, &out, &rejected, false)
	k := ConnectionKey{scopeFor(ctx), value(in.Name)}
	id := ""
	err := s.repository.Update(ctx, func(tx Transaction) error {
		v, err := readConnection(tx, k)
		if err != nil {
			return err
		}
		if err = s.authorizeConnection(tx, "DeleteConnection", v); err != nil {
			return err
		}
		old := v
		priorModified := v.Modified
		if v.State != "DELETING" {
			if v.HasAuth {
				if s.connectionSecrets == nil {
					return unsupported("EventBridge Connections require a Secrets Manager owner.")
				}
				if wire := s.connectionSecrets.Delete(tx.Context(), v.ARN(), v.SecretARN); wire != nil {
					return wire
				}
			}
			v.State = "DELETING"
			v.Modified = s.clock.Now().Truncate(time.Second)
			v.Due = s.clock.Now().Add(time.Second)
			v.Version++
			if err := tx.PutConnection(v); err != nil {
				return err
			}
			if err := s.updateConnectionAPIDestinations(tx, old, v); err != nil {
				return err
			}
		}
		id = v.ID
		out = &api.DeleteConnectionOutput{ConnectionArn: str[api.ConnectionArn](v.ARN()), ConnectionState: str[api.ConnectionState](v.State), CreationTime: connectionTime(v.Created), LastModifiedTime: connectionTime(priorModified), LastAuthorizedTime: connectionTime(v.LastAuthorized)}
		return s.recordCall(tx.Context(), "DeleteConnection", in, out, nil)
	})
	if err != nil {
		return nil, connectionMutationError(ctx, err)
	}
	s.connectionTokens.remove(id)
	s.cancelAPIDestination(id)
	s.jobs.Wake()
	return out, nil
}
