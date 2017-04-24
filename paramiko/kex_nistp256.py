from hashlib import sha256
from paramiko.message import Message
from paramiko.py3compat import byte_chr, long
from paramiko.ssh_exception import SSHException
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers
from paramiko.common import four_byte
from paramiko.util import deflate_long

_MSG_KEXECDH_INIT, _MSG_KEXECDH_REPLY = range(30, 32)
c_MSG_KEXECDH_INIT, c_MSG_KEXECDH_REPLY = [byte_chr(c) for c in range(30, 32)]


class KexECDH():
    name = "ecdh-sha2-nistp256"
    hash_algo = sha256

    def __init__(self, transport):
        self.curve = ec.SECP256R1()
        self.transport = transport
        self.P = long(0)
        self.Q_C = long(0)
        self.Q_S = long(0)


    def start_kex(self):
        self._generate_key_pair()
        if self.transport.server_mode:
            self.transport._expect_packet(_MSG_KEXECDH_INIT)
            return
        m = Message()
        m.add_byte(c_MSG_KEXECDH_INIT)
        m.add_string(self.Q_C.public_numbers().encode_point())
        self.transport._send_message(m)
        self.transport._expect_packet(_MSG_KEXECDH_REPLY)
    
    def point_to_byte_string(self, point, key_size):
        no_of_octets = (key_size + 7)//8
        x_bytes = deflate_long(point.x, add_sign_padding=False)
        x_bytes = b'\x00' * (no_of_octets - len(x_bytes)) + x_bytes
        y_bytes = deflate_long(point.y, add_sign_padding=False)
        y_bytes = b'\x00' * (no_of_octets - len(y_bytes)) + y_bytes
        return four_byte + x_bytes + y_bytes

    def parse_next(self, ptype, m):
        if self.transport.server_mode and (ptype == _MSG_KEXECDH_INIT):
            return self._parse_kexecdh_init(m)
        elif not self.transport.server_mode and (ptype == _MSG_KEXECDH_REPLY):
            return self._parse_kexecdh_reply(m)
        raise SSHException('KexECDH asked to handle packet type %d' % ptype)


    def _generate_key_pair(self):
        self.P = ec.generate_private_key(self.curve, default_backend())
        if self.transport.server_mode:
            self.Q_S = self.P.public_key()
            return
        self.Q_C = self.P.public_key()
      #  print(type(self.Q_C))
      #  print(self.Q_C)



    def _parse_kexecdh_init(self, m):
        Q_C_bytes = m.get_string()
        self.Q_C = EllipticCurvePublicNumbers.from_encoded_point(self.curve, Q_C_bytes)
        #verify if key is valid
        #compute shared secret  K
        #Generate exchange hash

        K_S = self.transport.get_server_key().asbytes()

        K = self.P.exchange(ec.ECDH(), self.Q_C.public_key(default_backend()))

        #compute exchange hash
        hm = Message()
        hm.add(self.transport.remote_version, self.transport.local_version,
               self.transport.remote_kex_init, self.transport.local_kex_init)
        hm.add_string(K_S)
        hm.add_string(self.Q_C_bytes)
        hm.add_string(self.Q_S.public_numbers().encode_point())
        hm.add_mpint(int(K))
        H = sha256(hm.asbytes()).digest()
        self.transport._set_K_H(K, H)
        sig = self.transport.get_server_key().sign_ssh_data(H)

        #construct reply
        m = Message()
        m.add_byte(_MSG_KEXECDH_REPLY)
        m.add_string(K_S)
        m.add_string(self.Q_S.public_numbers().encode_point())
        m.add_string(sig)
        self.transport._send_message(m)
        self.transport._activate_inbound()


    def _parse_kexecdh_reply(self, m):
        K_S = m.get_string()
        Q_S_bytes = m.get_string()
        self.Q_S = EllipticCurvePublicNumbers.from_encoded_point(self.curve, Q_S_bytes)
        sig = m.get_string()

        print(self.Q_S)
        K = self.P.exchange(ec.ECDH(), self.Q_S.public_key(default_backend()))
        K = int(K.encode('hex'), 16)
        hm = Message()
        hm.add(self.transport.local_version, self.transport.remote_version,
               self.transport.local_kex_init, self.transport.remote_kex_init)
        hm.add_string(K_S)
        hm.add_string(self.Q_C.public_numbers().encode_point())
        hm.add_string(Q_S_bytes)
        hm.add_mpint(K)
        self.transport._set_K_H(K, sha256(hm.asbytes()).digest())
        self.transport._verify_key(K_S, sig)
        self.transport._activate_outbound()



