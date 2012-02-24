
import sys
from time import sleep
import logging

logger = logging.getLogger(__name__)

import xtraceback
xtraceback.compat.install_sys_excepthook()

import boto

from cred_thingy.notifications import JSONMessage
from cred_thingy.iam import user_manager
from cred_thingy.crypt import encrypt_data, get_host_key
from cred_thingy.s3 import cred_bucket

class runner(object):
    def __init__(self, queue_name, bucket_name, path_prefix='instance_creds'):
        self.bucket = cred_bucket(bucket_name, path_prefix)
        self.queue_name = queue_name
        self._sqsconn = boto.connect_sqs()
        self._ec2conn = boto.connect_ec2()
        self.user_manager = user_manager()
        self._get_queue()

    def _get_queue(self):
        queue = self._sqsconn.get_queue(self.queue_name)
        if queue is None:
            #TODO: figure out how to handle missing sqs queue.
            print "queue not found."
            sys.exit(1)
            #queue = sqsconn.create_queue(queue_name, 60)
        
        queue.set_message_class(JSONMessage)
        self.queue = queue



    def poll_sqs(self):
        queue = self.queue
        logger.debug("Starting to poll sqs")


        while 1:
            message = queue.read(30)
            if message is None:
                sleep(30)
                continue

            {'autoscaling:EC2_INSTANCE_LAUNCH': self.on_instance_launch,
             'autoscaling:EC2_INSTANCE_TERMINATE': self.on_instance_terminate,
             'autoscaling:EC2_INSTANCE_TERMINATE_ERROR': self.on_instance_terminate,
            }[message.Message['Event']](message)


    def rectify(self):
        #TODO: find manually launched instances (or should we?)
        pass

    def on_instance_launch(self, message):
        instance_id = message.Message['EC2InstanceId']
        logger.debug("Notified of instance launch for instance %s." % instance_id)
        instance = self._ec2conn.get_all_instances([instance_id])[0].instances[0]

        creds = self.user_manager.create_instance_user(instance_id)
        host_pubkey = get_host_key(instance.public_dns_name)
        encrypted_creds = encrypt_data(host_pubkey, creds)

        self.bucket.upload_creds(encrypted_creds)
        self.bucket.allow_ip(instance.ip_address)

        message.delete()

    def on_instance_terminate(self, message):
        instance_id = message.Message['EC2InstanceId']
        logger.debug("Notified instance %s was terminated." % instance_id)
        self.user_manager.delete_instance_user(instance_id)
        message.delete()


if __name__ == '__main__':
    r = runner(sys.argv[1], sys.argv[2])
    runner.poll_sqs()

