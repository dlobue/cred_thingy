
import logging
logger = logging.getLogger(__name__)

import boto

from cred_thingy.userdata import get_chef_attribs


class AlreadyDeleted(Exception): pass


class user_manager(object):
    default_groups = ['base']
    boto_cred_template = '[Credentials]\naws_access_key_id = {access_key_id}\naws_secret_access_key = {secret_access_key}\n'

    def __init__(self, group_prefix='chef'):
        self.group_prefix = group_prefix
        self._iamconn = boto.connect_iam()

    def iter_applicable_groups(self, traits):
        logger.debug("iterating over iam groups that match up with chef traits: %s" % ', '.join(traits))
        res = self._iamconn.get_all_groups()
        groups = res['list_groups_response']['list_groups_result']['groups']
        groups = (x['group_name'] for x in groups if x['group_name'].startswith(self.group_prefix))

        match_list = list(traits)
        match_list.extend(self.default_groups)

        prefix_len = len(self.group_prefix)

        for group in groups:
            if group[prefix_len:].strip('-_') in match_list:
                yield group



    def _get_instance_access_keys(self, instance_id):
        logger.debug("Locating all existing access keys for instances %s" % instance_id)
        resp = self._iamconn.get_all_access_keys(instance_id)
        access_keys = resp['list_access_keys_response']['list_access_keys_result']['access_key_metadata']
        for access_key in access_keys:
            if access_key['user_name'] == instance_id:
                yield access_key['access_key_id']


    def _delete_instance_access_keys(self, instance_id):
        for access_key in self._get_instance_access_keys(instance_id):
            logger.debug("Deleting access key id %s from for instance %s" % (access_key, instance_id))
            self._iamconn.delete_access_key(access_key, instance_id)

    def _delete_instance_groups(self, instance_id):
        resp = self._iamconn.get_groups_for_user(instance_id)
        groups = resp[u'list_groups_for_user_response'][u'list_groups_for_user_result'][u'groups']

        for group in groups:
            logger.debug("Removing instance user %s from groups %s" % (instance_id, group[u'group_name']))
            self._iamconn.remove_user_from_group(group[u'group_name'], instance_id)

    def delete_instance_user(self, instance_id):
        logger.info("Deleting iam user for ec2 instance %s" % instance_id)
        try:
            self._delete_instance_access_keys(instance_id)
        except boto.exception.BotoServerError, e:
            if e.status == 404 and e.error_code == u'NoSuchEntity':
                return None
            else:
                raise e
        self._delete_instance_groups(instance_id)
        self._iamconn.delete_user(instance_id)
        logger.debug("User for ec2 instance %s deleted" % instance_id)


    def _create_instance_creds(self, instance_id):
        logger.debug("Generating access keys for instance %s" % instance_id)
        inst_creds = self._iamconn.create_access_key(instance_id)
        creds = self.boto_cred_template.format(**inst_creds['create_access_key_response']['create_access_key_result']['access_key'])
        return creds

    def create_instance_user(self, instance_id):
        logger.info("Creating iam user and access keys for ec2 instances %s" % instance_id)
        iamconn = self._iamconn
        chef_attribs = get_chef_attribs(instance_id)
        if chef_attribs is None:
            traits = []
            deployment = 'no_deployment'
        else:
            traits = chef_attribs.get('traits', [])
            traits = chef_attribs.get('deployment', 'no_deployment')

        result = iamconn.create_user(instance_id, '/cred_thingy/%s/' % deployment)
        #TODO: check result to ensure user was created successfully

        for group in self.iter_applicable_groups(traits):
            logger.debug("Adding iam user for instance %s to iam group %s" % (instance_id, group))
            iamconn.add_user_to_group(group, instance_id)

        return self._create_instance_creds(instance_id)

