
import socket
from time import sleep
from pprint import pformat
import sys
from threading import Lock
from time import time
import logging

logger = logging.getLogger(__name__)


from boto.s3.lifecycle import Lifecycle
import boto

from cred_thingy.util import memoize_attr

CLEAN_INTERVAL = 30 * 60


class cred_bucket(object):
    policy_statement_id = "instance_creds"
    policy_version = "2008-10-17"

    def __init__(self, bucket_name, path_prefix='instance_creds'):
        self._conn = boto.connect_s3()
        self.name = bucket_name
        self.path_prefix = path_prefix.strip('/*')
        self._get_bucket()
        self._metadata = policy_metadata()


    def _acquire(self, timeout=None):
        #TODO: proper handling of timeout
        logger.debug("Acquiring lockr")
        self._metadata._acquire()

    def _release(self):
        logger.debug("Releasing lockr")
        self.__policy = self.__statement = None
        self._metadata._release()

    def __enter__(self):
        self._acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._release()
        #XXX: what else?


    def _get_bucket(self):
        try:
            self._bucket = self._conn.get_bucket(self.name)
        except boto.exception.S3ResponseError, e:
            if e.status == 404 and e.error_code == u'NoSuchBucket':
                self._bucket = self._conn.create_bucket(self.name)
            else:
                raise e
            #TODO: if we have to create the bucket, then we have to set the default policy
            #TODO: also need to set the lifecycle
            #XXX: or should these be in an 'ensure' stage?


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


    def _get_policy(self):
        #TODO: need to ensure we have lock before running this
        logger.debug("Getting s3 bucket policy for bucket %s" % self.name)
        try:
            r = self._bucket.get_policy()
            logger.debug("Found the bucket policy for bucket %s" % self.name)
        except boto.exception.S3ResponseError:
            logger.debug("No bucket policy for bucket %s found! creating a new policy from scratch!")
            r =  dict(
                Version=self.policy_version,
                Statement=[],
            )
        self.__policy = r #XXX: should i?
        return r

    def _set_policy(self):
        logger.debug("merging updated policy statement with existing bucket policy")
        policy = self.__policy
        statement = self.__statement
        if statement not in policy['Statement']:
            policy['Statement'].append(statement)

        logger.debug("uploading the new bucket policy to s3.")
        self._bucket.set_policy(policy)
        self.__policy = self.__statement = None



    def _find_statement(self):
        #TODO: need to ensure we have lock before running this
        logger.debug("finding the cred_thingy policy statement %s and separating it from the policy for modifications." % self.policy_statement_id)
        if hasattr(self, '__policy') and self.__policy is not None:
            policy = self.__policy
        else:
            policy = self._get_policy()

        statements = policy['Statement']
        sid = self.policy_statement_id

        found = [s for s in statements if s['Sid'] == sid]
        assert len(found) < 2, "Found multiple policy statements with the same Sid (%s) on aws! statements: %s" % (sid, pformat(found))

        try:
            s = statements.pop(statements.index(found[0]))
            logger.debug("Found the existing cred_thingy policy statement: %s" % pformat(s))
        except IndexError:
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
        self.__statement = s
        return s

    def _allow_ip(self, source_ip):
        #TODO: need to ensure we have lock before running this
        if hasattr(self, '__statement') and self.__statement is not None:
            statement = self.__statement
        else:
            statement = self._find_statement()

        source_ips = statement['Condition']['IpAddress']['aws:SourceIp']

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

        return statement

    def allow_ip(self, source_ip):
        logger.info("Granting access to the cred_thingy folder to the IP address %s" % source_ip)
        self._allow_ip(source_ip)
        self._set_policy()


    def rectify(self):
        #TODO: once a week go through the list of source ip addresses in the policy
        # and give them a 1 day TTL.
        pass

    def clean(self):
        #TODO: need to ensure we have lock before running this
        if hasattr(self, '__statement') and self.__statement is not None:
            statement = self.__statement
        else:
            statement = self._find_statement()

        source_ips = statement['Condition']['IpAddress']['aws:SourceIp']

        for source_ip in self._metadata.iter_stale_ips(delete=True):
            if source_ip in source_ips:
                logger.info("removing stale source_ip address from bucket policy", source_ip)
                del source_ips[source_ips.index(source_ip)]

    def upload_creds(self, instance_id, encrypted_creds):
        key_name = self.path_prefix.strip('/*') + '/' + instance_id
        logger.info("Uploading credential file using key name '%s' for instance %s" % (key_name, instance_id))
        s3key = self._bucket.new_key(key_name)
        s3key.set_contents_from_string(encrypted_creds, reduced_redundancy=True)








class policy_metadata(object):
    _lock = Lock()
    def __init__(self, domain_name='cred_thingy', lock_key='lockr'):
        self._fqdn = socket.getfqdn()
        self.domain_name = domain_name
        self.lock_key = lock_key
        self._conn = boto.connect_sdb()
        self._domain = self._conn.get_domain(domain_name)

    def create_ttl_record(self, source_ip):
        now = time()
        ttl = now - (now % CLEAN_INTERVAL) + CLEAN_INTERVAL + (60 * 60 * 24)
        logger.debug("Creating ttl record for ip address %s to go off at epoch %s" % (source_ip, ttl))
        self._domain.put_attributes(ttl,
                                    dict(source_ips=source_ip,
                                         ttl=ttl),
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


    def _acquire(self):
        #XXX: should we acquire the shared lock first, or the process lock?
        self._lock.acquire()
        self.acquire_shared_lock()
        #XXX: should we make sure __policy and __statement are empty?

    def _release(self):
        self.release_shared_lock()
        self._lock.release()

    def acquire_shared_lock(self):
        result = False
        c=1
        while 1:
            logger.debug("Attempt %s to acquire shared lock" % c)
            try:
                result = self._conn.put_attributes(self.domain_name,
                                                self.lock_key,
                                                dict(owner=self._fqdn),
                                                expected_value=['owner', False]
                                               )
                if result is True:
                    break
            except boto.exception.SDBResponseError:
                pass
            sleep(1)
            #TODO: implement backing-off timer
            #TODO: implement queue to prevent starvation?

        logger.debug("Shared lock acquired")


    def release_shared_lock(self):
        logger.debug("Releasing shared lock")
        self._conn.delete_attributes(self.domain_name,
                                   self.lock_key,
                                   ['owner'],
                                   expected_value=['owner', self._fqdn])


