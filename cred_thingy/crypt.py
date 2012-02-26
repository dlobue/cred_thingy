
from paramiko.transport import Transport, SSHException
from socket import create_connection
import logging

from uuid import uuid4
from Crypto.PublicKey import RSA

logger = logging.getLogger(__name__)

def get_host_key(host, port=22):
    #TODO: need to add in a retry mechanism
    sock = create_connection((host, port))
    logger.debug("Connecting to host %s to get ssh public host key" % host)

    transport = Transport(sock)
    transport.start_client()
    key = transport.get_remote_server_key()
    transport.close()

    return key


def encrypt_data(pubkey, data):
    logger.debug("Encrypting credentials using ssh public key. shhhhhhh!")
    rsa = RSA.construct((long(pubkey.n), long(pubkey.e)))
    return rsa.encrypt(data, uuid4().hex)[0]


def load_pubkey():
    import base64, paramiko
    pubkeyfh = open('/etc/ssh/ssh_host_rsa_key.pub', 'r')
    pubkeydata = pubkeyfh.read()
    return paramiko.RSAKey(data=base64.decodestring(pubkeydata.split()[1]))

def decrypt_data(encrypteddata):
    import paramiko
    hostprivkey = paramiko.RSAKey(filename='/etc/ssh/ssh_host_rsa_key')
    rsapriv = RSA.construct((long(hostprivkey.n), long(hostprivkey.e), long(hostprivkey.d)))
    return rsapriv.decrypt(encrypteddata)

