
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
    return rsa.encrypt(data, uuid4().hex)


