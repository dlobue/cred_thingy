
import socket
from time import sleep
from pprint import pformat
import sys
from threading import _RLock
from time import time
from functools import wraps
from uuid import uuid4
import json
import logging
logger = logging.getLogger(__name__)


from boto.s3.lifecycle import Rule, Lifecycle as _Lifecycle
import boto, boto.s3.lifecycle

from cred_thingy.util import memoize_attr, Singleton

CLEAN_INTERVAL = 30 * 60

class Lifecycle(_Lifecycle):
    def __init__(self, bucket=None):
        self.bucket = bucket

    def to_xml(self):
        """
        Returns a string containing the XML version of the Lifecycle
        configuration as defined by S3.
        """
        s = '<LifecycleConfiguration>'
        s += ''.join((rule.to_xml() for rule in self if type(rule) is Rule))
        #for rule in self:
            #s += rule.to_xml()
        s += '</LifecycleConfiguration>'
        return s

boto.s3.lifecycle.Lifecycle = Lifecycle


def lock(already_have_shared=False):
    def decorator(f):
        @wraps(f)
        def wrapper(self, *args, **kwargs):
            if already_have_shared and not self._lock._RLock__count:
                raise RuntimeError, "Data possibly invalid! shared lock already released!"
            with self._lock:
                return f(self, *args, **kwargs)
        return wrapper
    return decorator

def update_policy(f):
    @lock()
    @wraps(f)
    def wrapper(self, *args, **kwargs):
        logger.debug("Going to be updating the bucket policy. working with %r" % f)
        policy = self._get_policy()
        f(self, policy=policy, *args, **kwargs)
        return self._update_policy(policy)
    return wrapper

class cred_bucket(Singleton):
    policy_statement_id = "instance_creds"
    policy_version = "2008-10-17"

    def __init__(self, bucket_name, path_prefix='instance_creds'):
        self._conn = boto.connect_s3() #TODO: add support for different regions
        self.name = bucket_name
        self.path_prefix = path_prefix.strip('/*')
        self._get_bucket()
        self._metadata = policy_metadata()
        self._lock = LockR(self._metadata._domain)

    def _get_bucket(self):
        try:
            self._bucket = self._conn.get_bucket(self.name)
        except boto.exception.S3ResponseError, e:
            if e.status == 404 and e.error_code == u'NoSuchBucket':
                self._bucket = self._conn.create_bucket(self.name)
            else:
                raise e
        self.set_lifecycle()

    def set_lifecycle(self):
        try:
            lifecycle = self._bucket.get_lifecycle_config()
        except boto.exception.S3ResponseError, e:
            if e.status == 404 and e.error_code == u'NoSuchLifecycleConfiguration':
                logger.debug("No lifecycle configuration found. Creating a new one.")
                lifecycle = Lifecycle()
            else:
                raise e

        rule_id = 'instance_creds'
        rule_prefix = self.path_prefix

        if lifecycle:
            rules = (r for r in lifecycle if type(r) is Rule)
            for rule in rules:
                if rule.id == rule_id or rule.prefix.startswith(rule_prefix):
                    logger.debug("Found existing lifecycle rule matching path or name.")
                    if rule.expiration != 1 or rule.status != 'Enabled':
                        logger.debug("Discovered rule was incorrectly configured. deleting it.")
                        lifecycle.pop(lifecycle.index(rule))
                    else:
                        return

        logger.debug("Creating s3 object expiration rule for instance creds.")
        lifecycle.add_rule(rule_id, rule_prefix.strip('/*') + '/', 'Enabled', 1)
        result = self._bucket.configure_lifecycle(lifecycle)
        assert result, "failed to set lifecycle!"

    @property
    @memoize_attr
    def arn(self):
        path_prefix = self.path_prefix.strip('/*')
        if not path_prefix:
            path_prefix = '/*'
        else:
            path_prefix = '/' + path_prefix + '/*'

        return "arn:aws:s3:::" + self.name + path_prefix

    def _new_policy(self):
        return dict(
                Version=self.policy_version,
                Statement=[],
            )

    @lock(already_have_shared=True)
    def _get_policy(self):
        logger.debug("Getting s3 bucket policy for bucket %s" % self.name)
        try:
            p = self._bucket.get_policy()
            return json.loads(p)
        except boto.exception.S3ResponseError:
            logger.debug("No bucket policy for bucket %s found! creating a new policy from scratch!")
            return self._new_policy()

    @lock(already_have_shared=True)
    def _update_policy(self, policy):
        logger.debug("uploading the new bucket policy to s3.")
        return self._bucket.set_policy(json.dumps(policy))

    def _find_statement(self, policy):
        """
        finds the credential access policy statement, or creates it if
        it doesn't exist yet.
        """
        logger.debug("finding the cred_thingy policy statement %s and separating it from the policy for modifications." % self.policy_statement_id)

        statements = policy['Statement']
        sid = self.policy_statement_id

        for statement in statements:
            if statement['Sid'] == sid:
                logger.debug("Found the existing cred_thingy policy statement: %s" % pformat(statement))
                #TODO: ensure the policy statement contains all required elements
                return statement

        logger.debug("No existing cred_thingy policy statement found. creating a new one")
        s = {
            "Sid": sid,
            "Effect": "Allow",
            "Principal": { "AWS": "*" },
            "Action": "s3:GetObject",
            "Resource": self.arn,
            "Condition": {
                "IpAddress": {
                    "aws:SourceIp": []
                }
            }
        }
        policy['Statement'].append(s)
        return s

    def _get_source_ips(self, policy):
        statement = self._find_statement(policy)
        source_ips = statement['Condition']['IpAddress'].get('aws:SourceIp', [])
        if not isinstance(source_ips, list):
            source_ips = [source_ips]
            statement['Condition']['IpAddress']['aws:SourceIp'] = source_ips

        return source_ips, statement

    @update_policy
    def allow_ip(self, source_ip, policy):
        #TODO: figure out a way to batch these options when this node has the lock
        logger.info("Granting access to the cred_thingy folder to the IP address %s" % source_ip)
        source_ips, statement = self._get_source_ips(policy)

        if '/' in source_ip:
            try:
                cidr_subnet = int(source_ip.split('/')[-1])
                assert cidr_subnet > 7 and cidr_subnet < 33, "Invalid subnet value"
            except Exception, e:
                raise ValueError, ("source_ip is not in valid CIDR format", e), sys.exc_traceback

        else:
            source_ip += '/32'

        if source_ip not in source_ips:
            source_ips.append(source_ip)

            self._metadata.create_ttl_record(source_ip)

        return policy

    @update_policy
    def rectify(self, policy):
        #TODO: figure out a way to batch these options when this node has the lock
        #TODO: run this once a week
        source_ips, statement = self._get_source_ips(policy)
        for source_ip in source_ips:
            self._metadata.create_ttl_record(source_ip)

    @update_policy
    def clean(self, policy, delete=False):
        source_ips, statement = self._get_source_ips(policy)
        for source_ip in self._metadata.iter_stale_ips(delete=delete):
            if source_ip in source_ips:
                logger.info("removing stale source_ip address %s from bucket policy" % source_ip)
                del source_ips[source_ips.index(source_ip)]

        return policy

    def upload_creds(self, instance_id, encrypted_creds):
        key_name = self.path_prefix.strip('/*') + '/' + instance_id
        logger.info("Uploading credential file using key name '%s' for instance %s" % (key_name, instance_id))
        s3key = self._bucket.new_key(key_name)
        return s3key.set_contents_from_string(encrypted_creds, reduced_redundancy=True)

    @update_policy
    def test_lock(self, policy):
        logger.info('testing the lock')
        try:
            sleep(600)
        except KeyboardInterrupt:
            pass


class policy_metadata(object):
    def __init__(self, domain_name='cred_thingy'):
        self.domain_name = domain_name
        self._conn = boto.connect_sdb() #TODO: add support for different regions
                                        #need to sync up sdb and s3 regions
        try:
            self._domain = self._conn.get_domain(domain_name)
        except boto.exception.SDBResponseError, e:
            if e.status == 400 and e.error_code == u'NoSuchDomain':
                self._domain = self._conn.create_domain(domain_name)
            else:
                raise e

    def create_ttl_record(self, source_ip):
        now = time()
        ttl = now - (now % CLEAN_INTERVAL) + CLEAN_INTERVAL + (60 * 60 * 24)
        logger.debug("Creating ttl record for ip address %s to go off at epoch %s" % (source_ip, ttl))
        self._domain.put_attributes(ttl, dict(source_ips=source_ip, ttl=ttl),
                                    replace=False)

    def iter_stale_ips(self, delete=False):
        logger.info("Iterating over records that are past their ttl.")
        if delete:
            logger.debug("ttl records will be deleted when finished iterating.")
        now = int(time())
        results = self._domain.select(
            "select source_ips from {domain_name} where ttl < '{now}'".format(
                domain_name=self.domain_name,
                now=now
            )
        )
        for result in results:
            source_ips = result['source_ips']
            if hasattr(source_ips, 'capitalize'):
                source_ips = [source_ips]

            logger.debug("Search conducted at %s returned ttl record %s containing source ips: %s" %\
                         (now, result.name, ', '.join(source_ips)))
            for source_ip in source_ips:
                yield source_ip

            if delete:
                result.delete()


class LockR(_RLock):
    def __init__(self, sdb_domain, lock_key='lockr', *args, **kwargs):
        super(LockR, self).__init__(*args, **kwargs)
        self._domain = sdb_domain
        self.lock_key = lock_key
        self._fqdn = '%s%s' % (socket.getfqdn(), uuid4().hex)
        #self._fqdn = socket.getfqdn() #XXX: should we use fqdn, or perhaps just a uuid?

    def acquire(self, *args, **kwargs):
        r = super(LockR, self).acquire(*args, **kwargs)
        if r and self._RLock__count == 1:
            self._acquire_shared_lock()
        return r

    def release(self):
        if self._is_owned() and self._RLock__count == 1:
            self._release_shared_lock()
        return super(LockR, self).release()

    def __enter__(self):
        return self.acquire()

    def __exit__(self, *args, **kwargs):
        self.release()

    def _acquire_shared_lock(self, timeout=None):
        #TODO: implement a timeout
        result = False
        c=1
        while 1:
            logger.debug("Attempt %s to acquire shared lock" % c)
            try:
                result = self._domain.put_attributes(self.lock_key,
                                                     dict(owner=self._fqdn),
                                                     expected_value=['owner',
                                                                     False])
                if result is True:
                    logger.debug("Shared lock acquired")
                    return result
            except boto.exception.SDBResponseError:
                #TODO: create a list of acceptable errors to retry on, and only retry on those
                pass
            c+=1
            sleep(1)
            #TODO: implement backing-off timer
            #XXX: implement queue to prevent starvation?

    def _release_shared_lock(self):
        logger.debug("Releasing shared lock")
        while 1:
            try:
                self._domain.delete_attributes(self.lock_key, ['owner'],
                                               expected_values=['owner',
                                                                self._fqdn])
                break
            except boto.exception.SDBResponseError, e:
                if e.status == 404:
                    break
                elif e.status in (500,503):
                    continue
                else:
                    raise e


