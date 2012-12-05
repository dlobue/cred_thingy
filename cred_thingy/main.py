

from gevent import monkey, sleep
monkey.patch_all(httplib=True, thread=True)


from gevent.pool import Pool

import sys
import signal
import logging
import ConfigParser
from argparse import ArgumentParser

logger = logging.getLogger('cred_thingy')

try:
    import xtraceback
    xtraceback.compat.install_sys_excepthook()
except ImportError:
    pass

import boto
import boto.ec2
from boto.sqs import connect_to_region as sqs_connect_to_region

from cred_thingy.notifications import JSONMessage
from cred_thingy.iam import user_manager, CLEAR_DEAD_ACCOUNTS_INTERVAL
from cred_thingy.crypt import encrypt_data, get_host_key
from cred_thingy.s3 import cred_bucket, CLEAN_INTERVAL, lock
from cred_thingy.subcmd import register_subcommand, collect_subcmds_from_class, generate_subcmd_parser
from cred_thingy.util import schedule


class runner(object):

    default_conf = '/etc/cred_thingy.conf'
    section = 'core'
    default_path_prefix = 'instance_creds'
    default_loglevel = 'debug'
    default_region = 'us-east-1'

    def read_basic_config(self):
        self.config_filename = self.options.config_filename
        cp = ConfigParser.ConfigParser(
            defaults=dict(
                path_prefix=self.default_path_prefix,
                loglevel=self.default_loglevel,
                region=self.default_region,
            )
        )
        cp.read([self.config_filename])
        self.config_parser = cp

    def __init__(self):
        self.stop_now = False
        self.pool = Pool(1000)


    def config_logging(self):
        if self.config_parser.has_option(self.section, 'logconfig'):
            import logging.config
            logging.config.fileConfig( self.config_parser.get(self.section, 'logconfig') )
        else:
            self._config_logging()

    def _config_logging(self):
        """Configure the logging module"""
        loglevel = self.config_parser.get(self.section, 'loglevel')
        logger.setLevel(logging.DEBUG)

        try:
            level = int(loglevel)
        except ValueError:
            level = int(logging.getLevelName(loglevel.upper()))


        handlers = []
        logfile = None
        if self.config_parser.has_option(self.section, 'logfile'):
            logfile = self.config_parser.get(self.section, 'logfile').strip()

        if logfile:
            handlers.append(logging.FileHandler(logfile))
        else:
            handlers.append(logging.StreamHandler(sys.stdout))

        log = logging.getLogger()
        for h in handlers:
            #TODO: make configurable
            h.setLevel(level)
            h.setFormatter(logging.Formatter(
                '%(asctime)s [%(name)s] [%(funcName)s] [%(thread)d] %(levelname)s: %(message)s'
                ))
            log.addHandler(h)


    def _init(self):
        region = self.config_parser.get('core', 'region')
        self._sqsconn = sqs_connect_to_region(region) if region else boto.connect_sqs()
        self._ec2conns = {region.name: region.connect() for region in boto.ec2.regions()}
        self.user_manager = user_manager()

    def main(self):
        """Read the command line and either start or stop the daemon"""
        ns = self.parse_options()
        self.read_basic_config()
        self.config_logging()

        self.bucket = cred_bucket(self.config_parser.get('core', 'bucket_name'),
                                  path_prefix=self.config_parser.get('core', 'path_prefix'),
                                  region=self.config_parser.get('core', 'region'))

        if hasattr(ns, 'action'):
            action = ns.action

        kwargs = vars(ns).copy()
        if 'action' in kwargs:
            del kwargs["action"]
        del kwargs["config_filename"]

        self._init()

        getattr(self, action)(**kwargs)


    def parse_options(self):
        parser = ArgumentParser()
        parser.add_argument('-c', '--config_filename',
                            default=self.default_conf,
                            help='Specify alternate configuration file name')

        subparsers = parser.add_subparsers(dest='action',
                                           title='utilities',
                                           description="direct access to functions for manual use.",
                                           )

        generate_subcmd_parser(subparsers, collect_subcmds_from_class(self))
        self.options = ns = parser.parse_args()
        return ns



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
            logger.error("queue not found.")
            sys.exit(1)
            #queue = sqsconn.create_queue(queue_name, 60)
        
        queue.set_message_class(JSONMessage)
        self.queue = queue

    @register_subcommand
    def serve(self):
        '''
        Start polling SQS for ASG events to act upon.
        Long running action, runs in forground. This is the default action.
        **THIS IS THE ONE YOU WANT**
        '''
        self.add_signal_handlers()
        self.queue_name = self.config_parser.get('core', 'queue_name')
        self._get_queue()
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

    @register_subcommand
    def create_creds(self, instance_id, region=None):
        '''
        Create IAM account and AWS credentials for new (or existing) server
        that was started manually. This is meant for servers that are not part
        of an autoscaling group.
        Requires instance id.
        '''
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

    @register_subcommand
    def delete_creds(self, instance_id):
        '''
        Delete credentials and IAM account for a server that has been shutdown.
        Requires instance id
        '''
        self.user_manager.delete_instance_user(instance_id)

    def on_instance_terminate(self, message):
        instance_id = message.Message['EC2InstanceId']
        logger.debug("Notified instance %s was terminated." % instance_id)
        self.delete_creds(instance_id)
        logger.debug("Deleting termination notice of instance %s" % instance_id)
        message.delete()

    @register_subcommand
    def clean_acl(self):
        '''
        Clean old IP addresses from the s3 bucket ACL.
        '''
        logger.info("Cleaning bucket ACLs")
        self.bucket.clean(delete=True)

    @lock()
    @register_subcommand
    def clear_dead_instance_accounts(self):
        '''
        For every cred_thingy managed IAM account, ensure the corresponding
        instance is alive. If not, delete the IAM account and all credentials.
        '''
        logger.info("Cleaning out iam accounts belonging to dead instances.")
        self.user_manager.clear_dead_instance_accounts()

    @register_subcommand
    def list_dead_instance_accounts(self):
        '''
        list all iam usernames that do not have a matching instance id.
        '''
        for instance_id in self.user_manager.iter_dead_instance_accounts():
            print(instance_id)



def run():
    runner().main()


if __name__ == '__main__':
    run()


