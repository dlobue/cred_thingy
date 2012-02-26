
import base64
import json
import sys
from hashlib import sha1

import boto
import boto.sqs.jsonmessage
from boto.exception import SQSDecodeError


class JSONMessage(boto.sqs.jsonmessage.JSONMessage):
    def endElement(self, name, value, connection):
        if value.strip():
            #return super(JSONMessage, self).endElement(name, value, connection)
            return boto.sqs.jsonmessage.JSONMessage.endElement(self, name, value, connection)

    def __getattr__(self, value):
        if value in self._body:
            return self[value]
        raise AttributeError(self, value)

    @property
    def Message(self):
        try:
            return self._message
        except AttributeError:
            self._message = msg = json.loads(self['Message'])
            return msg

    message = Message

    def verify(self):
        fields = [u'Message',
                  u'MessageId',
                  u'Subject',
                  u'Timestamp',
                  u'TopicArn',
                  u'Type'
                 ]
        hsh = sha1()
        for field in fields:
            hsh.update(field)
            hsh.update(u'\n')
            hsh.update(self[field])

        #TODO: figure out how to parse x509
        #TODO: base64 decode signature


    def decode(self, value):
        try:
            try:
                value = json.loads(base64.b64decode(value))
            except: pass
            value = json.loads(value)
        except Exception, e:
            #raise SQSDecodeError('Unable to decode message', self, e), None, sys.exc_traceback
            raise SQSDecodeError, ('Unable to decode message', self, e), sys.exc_traceback
        return value


def link_sqs_sns():
    sns = boto.connect_sns()
    sqs = boto.connect_sqs()

    queue = sqs.create_queue('asg_notifications', 60)
    topic = sns.create_topic('asg_notifications')

    sns.subscribe_sqs_queue(topic['CreateTopicResponse']['CreateTopicResult']['TopicArn'], queue)

def install_autoscaling_notifications(asg_name, topicArn):
    asgconn = boto.connect_autoscale()
    params = {
        "AutoScalingGroupName":asg_name,
        "TopicARN":topicArn,
    }
    asgconn.build_list_params(params, ["autoscaling:EC2_INSTANCE_LAUNCH",
                                       "autoscaling:EC2_INSTANCE_LAUNCH_ERROR",
                                       "autoscaling:EC2_INSTANCE_TERMINATE",
                                       "autoscaling:EC2_INSTANCE_TERMINATE_ERROR"],
                              'NotificationTypes')

    status = asgconn.get_status("PutNotificationConfiguration", params)
    assert status, "error during PutNotificationConfiguration"

def delete_autoscaling_notifications(asg_name, topicArn):
    asgconn = boto.connect_autoscale()
    params = {
        "AutoScalingGroupName":asg_name,
        "TopicARN":topicArn,
    }
    status = asgconn.get_status("DeleteNotificationConfiguration", params)
    assert status, "error during DeleteNotificationConfiguration"

