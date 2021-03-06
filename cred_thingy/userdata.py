
from email import message_from_string
from base64 import decodestring
from json import loads as json_loads
from zlib import decompress, error
from cStringIO import StringIO
from gzip import GzipFile
import logging

logger = logging.getLogger(__name__)

import boto
import boto.ec2
try:
    from cloudinit.UserDataHandler import process_includes
except ImportError:
    from cred_thingy.cloudconfig import process_includes

#ec2conn = boto.connect_ec2()

regions = {region.name: region.connect() for region in boto.ec2.regions()}

class NotCompressed(Exception): pass

def preprocess_userdata(data):
    logger.debug("Preprocessing userdata")
    parts = {}
    def _decompress(data):
        try:
            data = decompress(data)
            logger.debug("Was able to decompress userdata using zlib")
        except error:
            try:
                data = GzipFile(mode='rb', fileobj=StringIO(data)).read()
                logger.debug("Had to use GzipFile to decompress userdata.")
            except IOError, e:
                if e.message == 'Not a gzipped file':
                    raise NotCompressed
                else:
                    raise e
        return data

    try:
        data = _decompress(data)
        logger.debug("Userdata was not encoded in base64 at all.")
    except NotCompressed:
        try:
            data = _decompress( decodestring( data ) )
            logger.debug("Had to decode base64 encoded userdata before decompression.")
        except NotCompressed:
            logger.debug("Userdata is either uncompressed, or useless!")
            #TODO: write out userdata to /tmp?
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
    lc = asgconn.get_all_launch_configurations(names=[asg.launch_config_name])[0]
    return lc.user_data

def get_instance_userdata(instance_id, region=None):
    msg = "Acquiring userdata from aws for instance %s" % instance_id
    if region:
        if region in regions:
            msg += " in region %s" % region
        else:
            logger.warn(("Specified region %s does not exist or "
                          "is not supported by boto. Will try "
                          "all regions") % region)
            region = None
    logger.debug(msg)

    if region:
        try:
            return regions[region].get_instance_attribute(instance_id, 'userData')['userData']
        except boto.exception.EC2ResponseError, e:
            if e.status == 400 and e.error_code == u'InvalidInstanceID.NotFound':
                logger.warn(("Instance not found in specified "
                             "region. Trying the rest"))
            else:
                raise e

    for ec2conn in regions.itervalues():
        try:
            return ec2conn.get_instance_attribute(instance_id, 'userData')['userData']
        except boto.exception.EC2ResponseError, e:
            if e.status == 400 and e.error_code == u'InvalidInstanceID.NotFound':
                continue
            else:
                raise e

    logger.error("unable to locate instance %s on aws" % instance_id)
    raise


