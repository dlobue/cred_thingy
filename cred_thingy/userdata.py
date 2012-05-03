
from email import message_from_string
from base64 import decodestring
from json import loads as json_loads
from zlib import decompress, error
import logging

logger = logging.getLogger(__name__)

import boto
try:
    from cloudinit.UserDataHandler import process_includes
except ImportError:
    from cred_thingy.cloudconfig import process_includes

ec2conn = boto.connect_ec2()

def preprocess_userdata(data):
    logger.debug("Preprocessing userdata")
    parts = {}
    data = decodestring(data)
    try:
        data = decompress(data)
    except error:
        pass
        
    process_includes(message_from_string(data),parts)
    return parts

def _get_chef_attribs(parts):
    logger.debug("Locating chef-attribs part from userdata and then loading the json")
    attribs_header = '#chef-attribs\n'
    try:
        chef_attribs_idx = parts['types'].index('text/chef-attribs')
    except ValueError:
        return None

    chef_attribs = parts['content'][chef_attribs_idx]

    if chef_attribs.startswith(attribs_header):
        chef_attribs = chef_attribs[len(attribs_header):]

    return json_loads(chef_attribs)


def get_chef_attribs(instance_id):
    logger.info("Getting instance-specific chef configuration for instance %s from instance userdata." % instance_id)
    ud = get_instance_userdata(instance_id)
    if ud is None:
        return None
    udp = preprocess_userdata(ud)
    return _get_chef_attribs(udp)



def get_asg_userdata(asgname):
    #XXX: don't think this one is needed
    asgconn = boto.connect_autoscale()
    asg = asgconn.get_all_groups(names=[asgname])[0]
    lc = asgconn.get_all_launch_configurations(names=[asg.launch_config_name])
    return lc.user_data

def get_instance_userdata(instance_id):
    #TODO: iter over all regions until the region the instance belongs to is located.
    logger.debug("Acquiring userdata for instance %s from aws." % instance_id)
    return ec2conn.get_instance_attribute(instance_id, 'userData')['userData']

