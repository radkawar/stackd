package docdb

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

func clientOptions(endpoint Endpoint, username, password string, direct bool) (*options.ClientOptions, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(endpoint.CA) {
		return nil, errors.New("native DocumentDB endpoint requires an explicit trusted CA")
	}
	if endpoint.Address == "" || endpoint.Port < 1 || endpoint.Port > 65535 || endpoint.ReplicaSet == "" {
		return nil, errors.New("invalid native DocumentDB endpoint")
	}
	config := options.Client().SetHosts([]string{net.JoinHostPort(endpoint.Address, portString(endpoint.Port))}).SetTLSConfig(&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}).SetAuth(options.Credential{AuthSource: "admin", Username: username, Password: password}).SetRetryWrites(false).SetServerSelectionTimeout(5 * time.Second).SetConnectTimeout(5 * time.Second)
	if direct {
		config.SetDirect(true)
	} else {
		config.SetReplicaSet(endpoint.ReplicaSet)
	}
	return config, nil
}

// Open connects with TLS verification, SCRAM authentication and native replica
// discovery. The caller owns Disconnect. It never permits insecure TLS fallback.
func Open(ctx context.Context, endpoint Endpoint, username, password string) (*mongo.Client, error) {
	config, err := clientOptions(endpoint, username, password, false)
	if err != nil {
		return nil, err
	}
	client, err := mongo.Connect(config)
	if err != nil {
		return nil, err
	}
	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		client.Disconnect(context.WithoutCancel(ctx))
		return nil, err
	}
	return client, nil
}
func (d *Docker) ready(ctx context.Context, id string, endpoint Endpoint, spec Specification, restored bool) error {
	config, err := clientOptions(endpoint, spec.Username, spec.Password, true)
	if err != nil {
		return err
	}
	config.SetServerSelectionTimeout(time.Second).SetConnectTimeout(time.Second)
	client, err := mongo.Connect(config)
	if err != nil {
		return err
	}
	defer client.Disconnect(context.WithoutCancel(ctx))
	for {
		probe, cancel := context.WithTimeout(ctx, 2*time.Second)
		err = client.Ping(probe, nil)
		cancel()
		if err == nil {
			break
		}
		if err := d.waitRunning(ctx, id); err != nil {
			return fmt.Errorf("native DocumentDB authenticated startup: %w", err)
		}
	}
	var native struct {
		Config struct {
			ID      string `bson:"_id"`
			Version int32  `bson:"version"`
			Members []struct {
				ID   int32  `bson:"_id"`
				Host string `bson:"host"`
			} `bson:"members"`
		} `bson:"config"`
	}
	err = client.Database("admin").RunCommand(ctx, bson.D{{Key: "replSetGetConfig", Value: 1}}).Decode(&native)
	member := net.JoinHostPort(endpoint.Address, portString(endpoint.Port))
	var commandError mongo.CommandError
	if errors.As(err, &commandError) && commandError.Code == 94 {
		err = client.Database("admin").RunCommand(ctx, bson.D{{Key: "replSetInitiate", Value: bson.D{{Key: "_id", Value: replicaSet}, {Key: "members", Value: bson.A{bson.D{{Key: "_id", Value: 0}, {Key: "host", Value: member}}}}}}}).Err()
	} else if err == nil {
		if native.Config.ID != replicaSet || len(native.Config.Members) != 1 || native.Config.Members[0].ID != 0 {
			return errors.New("conflicting native DocumentDB replica topology")
		}
		if native.Config.Members[0].Host != member {
			if !restored {
				return errors.New("conflicting retained DocumentDB replica endpoint")
			}
			// A cold copy contains the source's local replica metadata. Rebind
			// exactly this single member while it is not primary, never the source.
			err = client.Database("admin").RunCommand(ctx, bson.D{{Key: "replSetReconfig", Value: bson.D{{Key: "_id", Value: replicaSet}, {Key: "version", Value: native.Config.Version + 1}, {Key: "members", Value: bson.A{bson.D{{Key: "_id", Value: 0}, {Key: "host", Value: member}}}}}}, {Key: "force", Value: true}}).Err()
		}
	}
	if err != nil {
		return fmt.Errorf("initializing native DocumentDB replica set: %w", err)
	}
	for {
		var hello struct {
			Primary bool `bson:"isWritablePrimary"`
		}
		err = client.Database("admin").RunCommand(ctx, bson.D{{Key: "hello", Value: 1}}).Decode(&hello)
		if err == nil && hello.Primary {
			break
		}
		if err := d.waitRunning(ctx, id); err != nil {
			return err
		}
	}
	var build struct {
		Version string `bson:"version"`
	}
	if err := client.Database("admin").RunCommand(ctx, bson.D{{Key: "buildInfo", Value: 1}}).Decode(&build); err != nil {
		return err
	}
	if build.Version != MongoVersion {
		return fmt.Errorf("native MongoDB version %q differs from required %s", build.Version, MongoVersion)
	}
	// Exercise ordinary discovery, not merely a forced direct connection, before
	// publishing availability to the service owner.
	connected, err := Open(ctx, endpoint, spec.Username, spec.Password)
	if err != nil {
		return err
	}
	return connected.Disconnect(context.WithoutCancel(ctx))
}
func (d *Docker) SetPassword(ctx context.Context, spec Specification, newPassword string) error {
	if err := validateSpecification(spec); err != nil {
		return err
	}
	if err := validatePassword(newPassword); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, d.startupTimeout)
	defer cancel()
	if err := d.lock(ctx); err != nil {
		return err
	}
	defer d.unlock()
	state, err := d.inspect(ctx, d.name(spec.ID, "database"))
	if err != nil {
		return err
	}
	port, err := strconvPort(state.Config.Labels[labelPrefix+"port"])
	if err != nil {
		return err
	}
	if spec.Port != 0 && spec.Port != port {
		return errors.New("password update endpoint mismatch")
	}
	spec.Port = port
	if err := d.checkDatabase(state, spec); err != nil {
		return err
	}
	ca, err := d.readFile(ctx, state.ID, "/data/db/security/ca.pem")
	if err != nil {
		return err
	}
	endpoint := Endpoint{Address: "localhost", Port: port, ReplicaSet: replicaSet, CA: ca}
	// Recover a lost control-plane completion after the native update committed.
	if client, err := Open(ctx, endpoint, spec.Username, newPassword); err == nil {
		return client.Disconnect(context.WithoutCancel(ctx))
	}
	client, err := Open(ctx, endpoint, spec.Username, spec.Password)
	if err != nil {
		return err
	}
	defer client.Disconnect(context.WithoutCancel(ctx))
	return client.Database("admin").RunCommand(ctx, bson.D{{Key: "updateUser", Value: spec.Username}, {Key: "pwd", Value: newPassword}}).Err()
}
