#!/usr/bin/env python
# The contents of this file are subject to the Mozilla Public License
# Version 1.1 (the "License"); you may not use this file except in
# compliance with the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS"
# basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
# License for the specific language governing rights and limitations
# under the License.
#
# The Original Code is pynsca.
#
# The Initial Developer of the Original Code is Dustin J. Mitchell.  Portions
# created by Dustin J. Mitchell are Copyright (C) Mozilla, Inc. All Rights
# Reserved.
#
# Alternatively, the contents of this file may be used under the terms of the
# GNU Public License, Version 2 (the  "GPLv2 License"), in which case the
# provisions of GPLv2 License are applicable instead of those above. If you
# wish to allow use of your version of this file only under the terms of the
# GPLv2 License and not to allow others to use your version of this file under
# the MPL, indicate your decision by deleting the provisions above and replace
# them with the notice and other provisions required by the GPLv2 License. If
# you do not delete the provisions above, a recipient may use your version of
# this file under either the MPL or the GPLv2 License.

import struct, binascii, itertools, socket


# return value constants
OK = 0
UP = 0
WARNING = 1
DOWN = 2
UNREACHABLE = 2
CRITICAL = 2
UNKNOWN = 3

class NSCANotifier(object):
    """
    Class to send notifications to a Nagios server via NSCA.
    """

    # utilities for below
    proto_version = 3
    fromserver_fmt = "!128sL"
    fromserver_fmt_size = struct.calcsize(fromserver_fmt)
    toserver_fmt = "!HxxlLH64s128s514s"
    toserver_fmt_size = struct.calcsize(toserver_fmt)

    def __init__(self, monitoring_server, monitoring_port=5667, encryption_mode=1, password=None):
        self.monitoring_server = monitoring_server
        self.monitoring_port = monitoring_port
        self.encryption_mode = encryption_mode
        self.password = password

    def _decode_from_server(self, bytes):
        iv, timestamp = struct.unpack(self.fromserver_fmt, bytes)
        return iv, timestamp

    def _pad_password(self, password, length):
        return password + ('\0' * (length - len(password)))

    def _apply_cipher(self, cipher, key_size, iv, password, toserver_pkt):
        import Crypto.Util.randpool

        password = self._pad_password(password, key_size)
        iv_size = cipher.block_size
        if len(iv) >= iv_size:
            iv = iv[:iv_size]
        else:
            iv += self.random_pool.get_bytes(iv_size - iv)
        e = cipher.new(password, cipher.MODE_CFB, iv)
        return ''.join(e.encrypt(toserver_pkt))

    def _encrypt_packet(self, toserver_pkt, iv, mode, password):
        from Crypto.Cipher import DES, DES3, CAST, Blowfish
        crypto_modes = {
            2: (DES, 8),
            3: (DES3, 24),
            4: (CAST, 16),
            8: (Blowfish, 56),
        }
        if mode in crypto_modes:
            cipher, key_size = crypto_modes[mode]
            return self._apply_cipher(cipher, key_size, iv, password, toserver_pkt)

        if mode == 1:
            cycle = [iv]
            if password:
                cycle = [iv, password]
            for key in cycle:
                toserver_pkt = ''.join([chr(p^i)
                                for p,i in itertools.izip(
                                        itertools.imap(ord, toserver_pkt),
                                        itertools.imap(ord, itertools.cycle(key)))])
        elif mode == 16:
            import mcrypt
            m = mcrypt.MCRYPT('rijndael-256', 'cfb')
            iv_size = m.get_iv_size()
            key_size = m.get_key_size()
            key = ['\0'] * key_size
            key[0:len(password)] = password
            m.init(''.join(key), iv[:iv_size])
            toserver_pkt = ''.join([m.encrypt(x) for x in toserver_pkt])
        elif mode == 0:
            return toserver_pkt
        else:
            print("no supported encryption_mode")
        return toserver_pkt

    def _encode_to_server(self, iv, timestamp, return_code, host_name,
                         svc_description, plugin_output, mode=1, password=None):
        # note that this will pad the strings with 0's instead of random digits.  Oh well.
        toserver = [
                self.proto_version,
                0, # crc32_value
                timestamp,
                return_code,
                self._force_str(host_name),
                self._force_str(svc_description),
                self._force_str(self._escape_newlines(plugin_output)),
        ]

        # calculate crc32 and insert into the list
        crc32 = binascii.crc32(struct.pack(self.toserver_fmt, *toserver))
        toserver[1] = crc32

        # convert to bytes
        toserver_pkt = struct.pack(self.toserver_fmt, *toserver)

        # and encode or encrypt
        toserver_pkt = self._encrypt_packet(toserver_pkt, iv, mode, password)

        return toserver_pkt

    def _escape_newlines(self, text):
        """Escape backslash and newlines; see https://github.com/djmitche/pynsca/issues/12#issuecomment-60086643"""
        return text.replace('\\', r'\\').replace('\n', r'\n')

    def _force_str(self, text):
        if isinstance(text, unicode):
            return text.encode('utf-8')
        return text

    def host_result(self, host_name, return_code, plugin_output):
        """
        Send a passive host check to the configured monitoring host

        Host checks are just service checks with no service listed.

        @param host_name: host containing the service
        @param return_code: result (e.g., C{OK} or C{CRITICAL})
        @param plugin_output: textual output
        """
        self.svc_result(host_name, '', return_code, plugin_output)

    def svc_result(self, host_name, svc_description, return_code, plugin_output, timeout=5):
        """
        Send a service result to the configured monitoring host

        Note that the nagios server provides no way to tell if it has actually
        processed the check result.

        @param host_name: host containing the service
        @param svc_description: description of the service with the result
        @param return_code: result (e.g., C{OK} or C{CRITICAL})
        @param plugin_output: textual output
        """
        sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sk.settimeout(timeout)
        sk.connect((self.monitoring_server, self.monitoring_port))

        # read packet
        buf = ''
        while len(buf) < self.fromserver_fmt_size:
            data = sk.recv(self.fromserver_fmt_size - len(buf))
            if not data:
                break
            buf += data

        # make up reply
        iv, timestamp = self._decode_from_server(buf)
        toserver_pkt = self._encode_to_server(iv, timestamp, return_code,
                host_name, svc_description, plugin_output,
                self.encryption_mode, self.password)

        # and send it
        sk.sendall(toserver_pkt)
        sk.close()
