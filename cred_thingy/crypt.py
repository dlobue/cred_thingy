
from socket import create_connection, error
from uuid import uuid4
from time import sleep
import logging

logger = logging.getLogger(__name__)

from paramiko.transport import Transport, SSHException
from Crypto.PublicKey import RSA


def get_host_key(host, port=22):
    #TODO: need to add in a retry mechanism
    logger.debug("Connecting to host %s to get ssh public host key" % host)
    MAX_RETRY = 60 / 15 * 5
    c = 0
    while 1:
        try:
            sock = create_connection((host, port))

            transport = Transport(sock)
            transport.start_client()
            key = transport.get_remote_server_key()
            transport.close()
            break
        except (error, SSHException):
            c += 1
            assert MAX_RETRY > c, "aborting attempt to connect to connect to server"
            logger.exception("attempt %s - error while attempting to connect to %s" % (c, host))
            #TODO: check if instance has been shutdown since we were told about it
            sleep(15)


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

