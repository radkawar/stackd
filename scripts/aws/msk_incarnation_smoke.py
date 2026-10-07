#!/usr/bin/env python3
"""Exercise native topic recreation through the signed production Pipes path."""
import argparse
import json
import sqlite3
from msk_executable_smoke import Proof, require


class IncarnationProof(Proof):
    def retained(self):
        with sqlite3.connect(self.state / 'msk.sqlite') as db:
            return db.execute('SELECT phase, attempts, sequence FROM pipes_work').fetchall()

    def identity(self):
        with sqlite3.connect(self.state / 'msk.sqlite') as db:
            return db.execute('SELECT cluster_id, topic_id FROM pipes_kafka_identities').fetchall()

    def run(self):
        self.start()
        try:
            self.arn = self.msk.create_cluster(ClusterName=self.prefix, KafkaVersion='3.7.1', NumberOfBrokerNodes=1,
                BrokerNodeGroupInfo={'InstanceType':'kafka.local','ClientSubnets':[]},
                ClientAuthentication={'Unauthenticated':{'Enabled':True}},
                EncryptionInfo={'EncryptionInTransit':{'ClientBroker':'PLAINTEXT','InCluster':True}})['ClusterArn']
            self.wait(self.cluster, 'native cluster readiness', 240)
            self.role = self.prefix
            role = self.iam.create_role(RoleName=self.role, AssumeRolePolicyDocument=json.dumps({'Version':'2012-10-17','Statement':[
                {'Effect':'Allow','Principal':{'Service':'pipes.amazonaws.com'},'Action':'sts:AssumeRole'}]}))['Role']['Arn']
            self.iam.put_role_policy(RoleName=self.role, PolicyName='source-target', PolicyDocument=json.dumps({'Version':'2012-10-17','Statement':[
                {'Effect':'Allow','Action':['kafka:DescribeCluster','kafka:DescribeClusterV2','kafka:GetBootstrapBrokers','sqs:SendMessage'],'Resource':'*'}]}))
            self.queue = self.sqs.create_queue(QueueName=self.prefix)['QueueUrl']
            target = self.sqs.get_queue_attributes(QueueUrl=self.queue, AttributeNames=['QueueArn'])['Attributes']['QueueArn']
            self.protocol('create')
            for failed in (True, False):
                label = 'retained_work' if failed else 'cursor_only'
                self.pipe = self.prefix + '-' + label
                group = self.pipe
                if failed:
                    self.iam.put_role_policy(RoleName=self.role, PolicyName='deny-target', PolicyDocument=json.dumps({'Version':'2012-10-17','Statement':[
                        {'Effect':'Deny','Action':'sqs:SendMessage','Resource':target}]}))
                self.protocol('produce', Partition=0, Values=['{"generation":"old"}'])
                self.pipes.create_pipe(Name=self.pipe, RoleArn=role, Source=self.arn, Target=target,
                    SourceParameters={'ManagedStreamingKafkaParameters':{'TopicName':self.prefix,'StartingPosition':'TRIM_HORIZON','BatchSize':1,'ConsumerGroupID':group}},
                    TargetParameters={'InputTemplate':'<$.value>'})
                if failed:
                    self.wait(lambda: any(row[1] > 0 for row in self.retained()), 'failed target retained')
                else:
                    require(self.wait(self.receive, 'initial successful delivery') == [{'generation':'old'}], 'wrong original record')
                    self.wait(lambda: self.offsets_committed(group,{0:1}), 'original offset committed')
                    self.wait(lambda: not self.retained(), 'cursor-only state')
                self.pipes.stop_pipe(Name=self.pipe)
                self.wait(lambda: self.pipes.describe_pipe(Name=self.pipe)['CurrentState'] == 'STOPPED', 'pipe stopped')
                before_work = self.retained()
                identity = self.identity()
                require(len(identity) == 1 and all(identity[0]), 'native source identity not retained')
                self.protocol('delete')
                self.wait(lambda: not self.protocol('metadata')['metadata']['Topics'][0]['Partitions'], 'topic absent')
                self.protocol('create')
                self.protocol('produce', Partition=0, Values=['{"generation":"replacement"}'])
                require(json.loads(self.protocol('read', Partition=0, Offset=0)['value']) == {'generation':'replacement'}, 'native replacement missing')
                if failed:
                    self.iam.delete_role_policy(RoleName=self.role, PolicyName='deny-target')
                self.controller.stop(timeout=60)
                self.start()
                self.wait(self.cluster, 'controller restart')
                self.pipes.start_pipe(Name=self.pipe)
                state = self.wait(lambda: self.changed(), 'source changed diagnosis')
                require(self.receive() is None, 'replaced source delivered retained bytes')
                offsets = self.offsets(group)
                require(all(v['CommittedOffset'] == -1 for v in offsets), 'replaced source received a commit: '+str(offsets))
                require(self.retained() == before_work, 'fencing discarded retained work')
                require(self.identity() == identity, 'restart rebound source identity')
                self.report['observations'][label] = {'state':state,'identity':identity,'retained':self.retained(),'offsets':offsets}
                self.pipes.delete_pipe(Name=self.pipe)
                self.wait(lambda: self.absent(self.pipes,'describe_pipe','NotFoundException',Name=self.pipe),'pipe deletion')
                self.pipes.create_pipe(Name=self.pipe, RoleArn=role, Source=self.arn, Target=target,
                    SourceParameters={'ManagedStreamingKafkaParameters':{'TopicName':self.prefix,'StartingPosition':'TRIM_HORIZON','BatchSize':1,'ConsumerGroupID':group}},
                    TargetParameters={'InputTemplate':'<$.value>'})
                require(self.wait(self.receive, 'explicit new pipe reads replacement') == [{'generation':'replacement'}], 'replacement was skipped')
                self.wait(lambda: self.offsets_committed(group,{0:1}), 'replacement offset committed')
                replacement_identity = self.identity()
                require(replacement_identity[0][0] == identity[0][0] and replacement_identity[0][1] != identity[0][1], 'native topic UUID did not change')
                self.report['observations'][label]['replacement_identity'] = replacement_identity
                self.pipes.delete_pipe(Name=self.pipe)
                self.wait(lambda: self.absent(self.pipes,'describe_pipe','NotFoundException',Name=self.pipe),'replacement pipe deletion')
                require(self.offsets_committed(group,{0:1}), 'borrowed group deleted')
                self.pipe = None
                self.protocol('delete')
                self.wait(lambda: not self.protocol('metadata')['metadata']['Topics'][0]['Partitions'], 'topic absent')
                self.protocol('create')
        finally:
            if self.controller.process is None:
                self.start()
            self.cleanup()
            self.controller.stop(timeout=60)
            (self.state / 'report.json').write_text(json.dumps(self.report, default=str, indent=2)+'\n')
        print(json.dumps(self.report, default=str))

    def changed(self):
        state = self.pipes.describe_pipe(Name=self.pipe)
        return state if 'source changed' in state.get('StateReason','').lower() else None


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    parser.add_argument('--protocol-probe', required=True)
    parser.add_argument('--state-directory', required=True)
    parser.add_argument('--docker-host', default='unix:///var/run/docker.sock')
    IncarnationProof(parser.parse_args()).run()
