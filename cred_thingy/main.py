

from gevent import monkey, sleep
monkey.patch_all(httplib=True, thread=True)
from gevent.core import timer


from gevent.pool import Pool

import sys
import signal
import logging

logger = logging.getLogger('cred_thingy')

import xtraceback
xtraceback.compat.install_sys_excepthook()

import boto
import boto.ec2

from cred_thingy.notifications import JSONMessage
from cred_thingy.iam import user_manager, CLEAR_DEAD_ACCOUNTS_INTERVAL
from cred_thingy.crypt import encrypt_data, get_host_key
from cred_thingy.s3 import cred_bucket, CLEAN_INTERVAL, lock

def schedule(time, f, *args, **kwargs):
    try:
        f(*args, **kwargs)
    finally:
        timer(time, schedule, time, f, *args, **kwargs)

class runner(object):
    def __init__(self, queue_name, bucket_name, path_prefix='instance_creds'):
        self.stop_now = False
        self.bucket = cred_bucket(bucket_name, path_prefix)
        self.queue_name = queue_name
        self._sqsconn = boto.connect_sqs() #TODO: support sqs queues in other regions
        self._ec2conns = {region.name: region.connect() for region in boto.ec2.regions()}
        self.pool = Pool(1000)
        self.user_manager = user_manager()
        self._get_queue()


    @property
    def _lock(self):
        return self.bucket._lock #hacky..

    def on_sighup(self, signalnum, frame):
        logger.info("got sighup")
        pass

    def on_sigterm(self, signalnum, frame):
        logger.info("got sigterm")
        self.stop_now = True
        self.pool.join()


    def add_signal_handlers(self):
        signal.signal(signal.SIGHUP, self.on_sighup)
        signal.signal(signal.SIGINT, self.on_sigterm)
        signal.signal(signal.SIGTERM, self.on_sigterm)


    def _get_queue(self):
        queue = self._sqsconn.get_queue(self.queue_name)
        if queue is None:
            #TODO: determine how best to handle missing sqs queue.
            print "queue not found."
            sys.exit(1)
            #queue = sqsconn.create_queue(queue_name, 60)
        
        queue.set_message_class(JSONMessage)
        self.queue = queue

    def run(self):
        self.add_signal_handlers()
        #clean out stale source ips every 30 minutes
        self.pool.spawn(schedule, CLEAN_INTERVAL, self.pool.spawn, self.clean_acl)
        #clear out iam accounts belonging to dead ec2 instances every 60 minutes
        self.pool.spawn(schedule, CLEAR_DEAD_ACCOUNTS_INTERVAL, self.pool.spawn, self.clear_dead_instance_accounts)
        try:
            self.poll_sqs()
        except KeyboardInterrupt:
            pass
        finally:
            self.bucket._lock._release_shared_lock()

    def poll_sqs(self):
        queue = self.queue
        logger.debug("Starting to poll sqs")
        pool = self.pool

        while 1:
            message = queue.read(300)
            if self.stop_now:
                if message is not None:
                    message.change_visibility(0)
                break
            if message is None:
                sleep(5)
                continue

            try:
                func = {'autoscaling:EC2_INSTANCE_LAUNCH':
                        self.on_instance_launch,
                        'autoscaling:EC2_INSTANCE_TERMINATE':
                        self.on_instance_terminate,
                        'autoscaling:EC2_INSTANCE_TERMINATE_ERROR':
                        self.on_instance_terminate, }[message.Message['Event']]
            except (KeyError, AttributeError):
                if message.Message['Event'] != 'autoscaling:TEST_NOTIFICATION':
                    logger.error("Got an unknown message type: %s" % message._body)
                message.delete()
                continue

            pool.spawn(func, message)


    def on_instance_launch(self, message):
        #TODO: verify message signature
        instance_id = message.Message['EC2InstanceId']
        asg_arn = message.Message['AutoScalingGroupARN']
        region = asg_arn.split(':')[3]
        logger.debug("Notified of instance launch for instance %s." % instance_id)
        self.create_creds(instance_id, region)
        logger.debug("Deleting launch notice of instance %s" % instance_id)
        message.delete()

    def create_creds(self, instance_id, region=None):
        msg = "Creating creds for instance %s" % instance_id
        if region:
            if region in self._ec2conns:
                msg += " in region %s" % region
            else:
                logger.error(("Specified region %s does not exist or "
                              "is not supported by boto. Will try "
                              "all regions") % region)
                region = None
        logger.info(msg)

        response = None

        if region:
            try:
                response = self._ec2conns[region].get_all_instances([instance_id])
            except boto.exception.EC2ResponseError, e:
                if e.status == 400 and e.error_code == u'InvalidInstanceID.NotFound':
                    logger.warn(("Instance not found in specified "
                                 "region. Trying the rest"))
                    response = None
                else:
                    raise e


        if not response:
            for ec2conn in self._ec2conns.itervalues():
                try:
                    response = ec2conn.get_all_instances([instance_id])
                    break
                except boto.exception.EC2ResponseError, e:
                    if e.status == 400 and e.error_code == u'InvalidInstanceID.NotFound':
                        pass
                    else:
                        raise


        if not response:
            logger.warn("unable to locate instance %s on aws" % instance_id)
            return

        instance = response[0].instances[0]

        if not instance.public_dns_name:
            logger.warn("Instance %s is no longer online" % instance_id)
            return

        host_pubkey = get_host_key(instance.public_dns_name)
        creds = self.user_manager.create_instance_user(instance_id)
        encrypted_creds = encrypt_data(host_pubkey, creds)

        self.bucket.upload_creds(instance_id, encrypted_creds)
        self.bucket.allow_ip(instance.ip_address)

    def delete_creds(self, instance_id):
        self.user_manager.delete_instance_user(instance_id)

    def on_instance_terminate(self, message):
        instance_id = message.Message['EC2InstanceId']
        logger.debug("Notified instance %s was terminated." % instance_id)
        self.delete_creds(instance_id)
        logger.debug("Deleting termination notice of instance %s" % instance_id)
        message.delete()

    def clean_acl(self):
        logger.info("Cleaning bucket ACLs")
        self.bucket.clean(delete=True)

    @lock()
    def clear_dead_instance_accounts(self):
        logger.info("Cleaning out iam accounts belonging to dead instances.")
        self.user_manager.clear_dead_instance_accounts()

    def test_lock(self):
        self.bucket.test_lock()


if __name__ == '__main__':

    logger.setLevel(logging.DEBUG)
    loggerHandler = logging.StreamHandler(sys.stdout)
    loggerHandler.setLevel(logging.DEBUG)
    loggerFormatter = logging.Formatter('%(asctime)s [%(name)s] [%(funcName)s] [%(thread)d] %(levelname)s: %(message)s')
    loggerHandler.setFormatter(loggerFormatter)
    logger.addHandler(loggerHandler)

    r = runner(sys.argv[1], sys.argv[2])
    try:
        cmd = sys.argv[3]
    except IndexError:
        r.run()
    else:
        getattr(r, cmd)(*sys.argv[4:])

