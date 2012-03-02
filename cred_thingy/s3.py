
import socket
from time import sleep
from pprint import pformat
import sys
from threading import _RLock
from time import time
import json
import logging
logger = logging.getLogger(__name__)


from boto.s3.lifecycle import Lifecycle
import boto

from cred_thingy.util import memoize_attr, Singleton

CLEAN_INTERVAL = 30 * 60


class cred_bucket(Singleton):
    policy_statement_id = "instance_creds"
    policy_version = "2008-10-17"

    def __init__(self, bucket_name, path_prefix='instance_creds'):
        self._conn = boto.connect_s3()
        self.name = bucket_name
        self.path_prefix = path_prefix.strip('/*')
        self._get_bucket()
        self._metadata = policy_metadata()
        self._lock = LockR(self._metadata._domain)


    def _get_bucket(self):
        try:
            self._bucket = self._conn.get_bucket(self.name)
            #TODO: ensure the lifecycle is set and correct
        except boto.exception.S3ResponseError, e:
            if e.status == 404 and e.error_code == u'NoSuchBucket':
                self._bucket = self._conn.create_bucket(self.name)
                self.set_lifecycle()
            else:
                raise e


    def set_lifecycle(self):
        #TODO: figure out where/when to do this
        logger.debug("Creating s3 object expiration rule for instance creds.")
        new_lifecycle = Lifecycle()
        #TODO: use path prefix in the lifecycle rule prefix
        new_lifecycle.add_rule('instance_creds', 'instance_creds/', 'Enabled', 1)
        result = self._bucket.configure_lifecycle(new_lifecycle)
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

    def _get_policy(self):
        #TODO: need to ensure we have lock before running this
        logger.debug("Getting s3 bucket policy for bucket %s" % self.name)
        try:
            p = self._bucket.get_policy()
            return json.loads(p)
        except boto.exception.S3ResponseError:
            logger.debug("No bucket policy for bucket %s found! creating a new policy from scratch!")
            return self._new_policy()

    def _find_statement(self, policy):
        """
        finds the credential access policy statement, or creates it if
        it doesn't exist yet.
        """

        #TODO: need to ensure we have lock before running this
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

    def _allow_ip(self, source_ip, policy):
        #TODO: need to ensure we have lock before running this
        statement = self._find_statement(policy)
        source_ips = statement['Condition']['IpAddress'].get('aws:SourceIp', [])
        if not isinstance(source_ips, list):
            source_ips = [source_ips]
            statement['Condition']['IpAddress']['aws:SourceIp'] = source_ips


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

    def allow_ip(self, source_ip):
        logger.info("Granting access to the cred_thingy folder to the IP address %s" % source_ip)
        policy = self._get_policy()
        self._allow_ip(source_ip, policy)
        self._update_policy(policy)

    def _update_policy(self, policy):
        logger.debug("uploading the new bucket policy to s3.")
        return self._bucket.set_policy(json.dumps(policy))


    def rectify(self):
        #TODO: once a week go through the list of source ip addresses in the policy
        # and give them a 1 day TTL.
        pass

    def clean(self):
        #TODO: need to ensure we have lock before running this
        policy = self._get_policy()
        self._clean(policy, delete=True)
        self._update_policy(policy)

    def _clean(self, policy, delete=False):
        statement = self._find_statement(policy)
        source_ips = statement['Condition']['IpAddress'].get('aws:SourceIp', [])
        if not isinstance(source_ips, list):
            source_ips = [source_ips]
            statement['Condition']['IpAddress']['aws:SourceIp'] = source_ips

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


class policy_metadata(object):
    def __init__(self, domain_name='cred_thingy'):
        self.domain_name = domain_name
        self._conn = boto.connect_sdb()
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
        super().__init__(*args, **kwargs)
        self._domain = sdb_domain
        self.lock_key = lock_key
        self._fqdn = socket.getfqdn() #XXX: should we use fqdn, or perhaps just a uuid?

    def acquire(self, *args, **kwargs):
        r = super().acquire(*args, **kwargs)
        if r and self._RLock__count == 1:
            self._acquire_shared_lock()
        return r

    def release(self):
        if self._is_owned() and self._RLock__count == 1:
            self._release_shared_lock()
        return super().release()

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
                pass
            sleep(1)
            #TODO: implement backing-off timer
            #XXX: implement queue to prevent starvation?



    def _release_shared_lock(self):
        logger.debug("Releasing shared lock")
        self._domain.delete_attributes(self.lock_key, ['owner'],
                                       expected_value=['owner', self._fqdn])


