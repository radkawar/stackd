#!/usr/bin/env python3
"""Signed RDS parameter commands and actual SQL through the local executable.

Uses only isolated local SQLite/native resources; never calls ambient AWS.
"""
import argparse
import hashlib
import json
import subprocess

from rds_executable_smoke import Application, require


def parameter(name, value, method="immediate"):
    return {"ParameterName": name, "ParameterValue": value, "ApplyMethod": method}


class ParametersApplication(Application):
    def processes(self):
        namespace = "stackd-rds-" + hashlib.sha256(str(self.database).encode()).hexdigest()[:24]
        ids = subprocess.run(["docker", "ps", "-aq", "--filter", "label=stackd.rds.namespace=" + namespace,
                              "--filter", "label=stackd.rds.role=database"], check=True, capture_output=True, text=True).stdout.split()
        rows = json.loads(subprocess.run(["docker", "inspect", *ids], check=True, capture_output=True, text=True).stdout)
        return {row["Id"]: row["State"]["StartedAt"] for row in rows}

    def workflows(self):
        targets = []
        for engine, family in (("postgres", "postgres17"), ("mysql", "mysql8.4")):
            setting = "statement_timeout" if engine == "postgres" else "wait_timeout"
            query = "SHOW statement_timeout" if engine == "postgres" else "SELECT @@SESSION.wait_timeout"
            static = "max_connections" if engine == "postgres" else "character_set_server"
            static_query = "SHOW max_connections" if engine == "postgres" else "SELECT @@GLOBAL.character_set_server"
            static_value = "131" if engine == "postgres" else "latin1"
            for cluster in (False, True):
                name = self.prefix + ("-cluster-" if cluster else "-instance-") + engine
                group = name + "-parameters"
                if cluster:
                    native_engine = "aurora-postgresql" if engine == "postgres" else "aurora-mysql"
                    self.rds.create_db_cluster_parameter_group(DBClusterParameterGroupName=group,
                        DBParameterGroupFamily="aurora-" + ("postgresql17" if engine == "postgres" else "mysql8.4"), Description="owned local proof")
                    self.cluster_parameter_groups.append(group)
                    self.clusters.append(name)
                    self.rds.create_db_cluster(DBClusterIdentifier=name, Engine=native_engine,
                        DatabaseName="appdb", MasterUsername="dbowner", MasterUserPassword=self.password,
                        DBClusterParameterGroupName=group)
                    writer = name + "-writer"
                    self.instances.append(writer)
                    self.rds.create_db_instance(DBInstanceIdentifier=writer, DBClusterIdentifier=name,
                        Engine=native_engine, DBInstanceClass="db.t3.small")
                    row = self.wait_instance(writer)
                    self.wait_cluster(name)
                else:
                    self.rds.create_db_parameter_group(DBParameterGroupName=group, DBParameterGroupFamily=family,
                        Description="owned local proof")
                    self.parameter_groups.append(group)
                    self.instances.append(name)
                    writer = name
                    self.rds.create_db_instance(DBInstanceIdentifier=name, Engine=engine, DBInstanceClass="db.t3.small",
                        DBName="appdb", MasterUsername="dbowner", MasterUserPassword=self.password, DBParameterGroupName=group)
                    row = self.wait_instance(name)
                endpoint = row["Endpoint"]
                target = {"name": name, "writer": writer, "engine": engine, "cluster": cluster, "group": group,
                          "setting": setting, "query": query, "static": static, "static_query": static_query,
                          "static_value": static_value, "endpoint": endpoint}
                target["default"] = self.native(engine, endpoint, query)
                target["static_default"] = self.native(engine, endpoint, static_query)
                before = self.processes()
                self.change(target, [parameter(static, static_value, "pending-reboot")])
                self.change(target, [parameter(setting, "9000")])
                self.wait_instance(writer)
                expected = "9s" if engine == "postgres" else "9000"
                require(self.native(engine, endpoint, query) == expected, "immediate parameter not observed by SQL")
                require(self.native(engine, endpoint, static_query) == target["static_default"], "static parameter applied before reboot")
                rejected = self.rejected(lambda: self.change(target, [parameter(setting, "8000"), parameter("unsupported_setting", "1")]), {"InvalidParameterValue"})
                self.rejected(lambda: self.change(target, [parameter(static, static_value)]), {"InvalidParameterCombination"})
                require(self.native(engine, endpoint, query) == expected, "rejected batch partly changed native setting")
                self.reset(target, [{"ParameterName": setting, "ApplyMethod": "immediate"}])
                self.wait_instance(writer)
                require(self.native(engine, endpoint, query) == target["default"], "immediate reset did not restore native default")
                self.change(target, [parameter(setting, "14000")])
                self.wait_instance(writer)
                require(self.processes() == before, "immediate parameter change restarted or replaced a native process")
                self.report["observations"][name] = {"immediate": True, "reset": True, "static_deferred": True,
                    "no_native_restart": True, "atomic_rejection": rejected}
                targets.append(target)
        before = self.processes()
        self.controller.stop(timeout=45, kill_on_timeout=True)
        self.start()
        for target in targets:
            row = self.wait_instance(target["writer"])
            target["endpoint"] = row["Endpoint"]
            expected = "14s" if target["engine"] == "postgres" else "14000"
            require(self.native(target["engine"], row["Endpoint"], target["query"]) == expected, "controller restart lost dynamic setting")
            require(self.native(target["engine"], row["Endpoint"], target["static_query"]) == target["static_default"], "controller restart applied pending static setting")
        require(self.processes() == before, "controller reattachment restarted a native process")
        for target in targets:
            name, cluster, engine = target["name"], target["cluster"], target["engine"]
            if cluster:
                self.rds.stop_db_cluster(DBClusterIdentifier=name)
                self.wait_cluster(name, "stopped")
            else:
                self.rds.stop_db_instance(DBInstanceIdentifier=name)
                self.wait_instance(name, "stopped")
            self.change(target, [parameter(target["setting"], "17000")])
            stopped = self.rds.describe_db_instances(DBInstanceIdentifier=target["writer"])["DBInstances"][0]
            require(stopped["DBInstanceStatus"] == "stopped", "immediate parameter edit started a stopped database")
            if cluster:
                self.rds.start_db_cluster(DBClusterIdentifier=name)
                self.wait_cluster(name)
            else:
                self.rds.start_db_instance(DBInstanceIdentifier=name)
            row = self.wait_instance(target["writer"])
            endpoint = row["Endpoint"]
            expected = "17s" if engine == "postgres" else "17000"
            require(self.native(engine, endpoint, target["query"]) == expected, "native restart lost dynamic setting")
            require(self.native(engine, endpoint, target["static_query"]) == target["static_value"], "restart did not apply deferred static setting")
            before = self.processes()
            self.reset(target, None)
            self.wait_instance(target["writer"])
            require(self.native(engine, endpoint, target["query"]) == target["default"], "reset-all retained dynamic setting")
            require(self.native(engine, endpoint, target["static_query"]) == target["static_value"], "reset-all applied static setting without reboot")
            require(self.processes() == before, "reset-all restarted the engine")
            self.report["observations"][name].update(controller_restart=True, stopped_not_started=True,
                native_restart=True, static_applied_on_start=True, reset_all_dynamic_only=True)

    def change(self, target, parameters):
        if target["cluster"]:
            return self.rds.modify_db_cluster_parameter_group(DBClusterParameterGroupName=target["group"], Parameters=parameters)
        return self.rds.modify_db_parameter_group(DBParameterGroupName=target["group"], Parameters=parameters)

    def reset(self, target, parameters):
        args = {"Parameters": parameters} if parameters is not None else {"ResetAllParameters": True}
        if target["cluster"]:
            return self.rds.reset_db_cluster_parameter_group(DBClusterParameterGroupName=target["group"], **args)
        return self.rds.reset_db_parameter_group(DBParameterGroupName=target["group"], **args)

    def run(self):
        try:
            self.start()
            self.workflows()
        finally:
            try:
                self.cleanup()
            finally:
                (self.state / "report.json").write_text(json.dumps(self.report, indent=2, default=str) + "\n")
        print(json.dumps(self.report, default=str))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--state-directory", required=True)
    parser.add_argument("--docker-host", default="unix:///var/run/docker.sock")
    ParametersApplication(parser.parse_args()).run()


if __name__ == "__main__":
    main()
