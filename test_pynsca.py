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

import threading
import socket
import unittest
import base64
import pynsca
try:
    import mcrypt
except ImportError:
    mcrypt = None

class TestConstants(unittest.TestCase):

    def test_OK(self):
        self.assertEqual(pynsca.OK, 0)

    def test_UP(self):
        self.assertEqual(pynsca.UP, 0)

    def test_WARNING(self):
        self.assertEqual(pynsca.WARNING, 1)

    def test_DOWN(self):
        self.assertEqual(pynsca.DOWN, 2)

    def test_UNREACHABLE(self):
        self.assertEqual(pynsca.UNREACHABLE, 2)

    def test_CRITICAL(self):
        self.assertEqual(pynsca.CRITICAL, 2)

    def test_UNKNOWN(self):
        self.assertEqual(pynsca.UNKNOWN, 3)

class TestNetwork(unittest.TestCase):

    def setUp(self):
        self.from_server = None
        self.got_from_client = None

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]

        self.server_thread = threading.Thread(target=self.server)
        self.server_thread.setDaemon(1)
        self.server_thread.start()

    def server(self):
        # TODO: async in case no connection happens
        sock, addr = self.sock.accept()
        assert self.from_server is not None
        sock.send(self.from_server)

        buf = ''
        while 1:
            data = sock.recv(1024)
            if not data:
                break
            buf += data

        self.got_from_client = buf
        sock.close()

    def setServerBannerB64(self, b64):
        bytes = base64.b64decode(b64)
        self.from_server = bytes

    def assertGotB64(self, b64):
        self.server_thread.join()
        self.assertEqual(self.got_from_client, base64.b64decode(b64))

    # tests

    def test_xor(self):
        self.setServerBannerB64("""
            unvxWHaOSEOA67AxsyjFCCOJ5i2d8pz5uHVA7A2ilccehh+UFWfXlVOIxwawjQ/UFvYBs
            +mdraET7o4gkCTnrqoHQsBvGlbDoh7KU6vZJ8HQKHW5xiJb2RDq+aAO4U+56ZJ5WKzQHE
            /u5qKZwMpbkPPQSrnzpZMDj42knW7zVlhNubCx
        """)

        notif = pynsca.NSCANotifier('127.0.0.1', self.port)
        notif.svc_result('linux-ix-slave10.build', 'buildbot-start', 0, 'hello!')

        self.assertGotB64("""
            unjxWM93GWrNUgCAsyipYU38ngD0irGK1BQ2iTySu6Vr73PwFWfXlVOIxwawjQ/UFvYBs
            +mdraET7o4gkCTnrqoHQsBvGlbDoh7KU6vZRbS5RBHbqVZ2qmSLi9QO4U+56ZJ5WKzQHE
            /u5qKZwMpbkPPQSrnzpZMDj42knW7zVli6e/FYdo5IQ4DrsDGzKMUII4nmLZ3ynPm4dUD
            sDaKVxx6GH5QVZ9eVU4jHBrCND9QW9gGz6Z2toRPujiCQJOeuqgdCwG8aVsOiHspTq9lP
            pLxEGpjGIlvZEOr5oA7hT7npknlYrNAcT+7mopnAyluQ89BKufOlkwOPjaSdbvNWWLp78
            Vh2jkhDgOuwMbMoxQgjieYtnfKc+bh1QOwNopXHHoYflBVn15VTiMcGsI0P1Bb2AbPpna
            2hE+6OIJAk566qB0LAbxpWw6IeylOr2SfB0Ch1ucYiW9kQ6vmgDuFPuemSeVis0BxP7ua
            imcDKW5Dz0Eq586WTA4+NpJ1u81ZYunvxWHaOSEOA67AxsyjFCCOJ5i2d8pz5uHVA7A2i
            lccehh+UFWfXlVOIxwawjQ/UFvYBs+mdraET7o4gkCTnrqoHQsBvGlbDoh7KU6vZJ8HQK
            HW5xiJb2RDq+aAO4U+56ZJ5WKzQHE/u5qKZwMpbkPPQSrnzpZMDj42knW7zVli6e/FYdo
            5IQ4DrsDGzKMUII4nmLZ3ynPm4dUDsDaKVxx6GH5QVZ9eVU4jHBrCND9QW9gGz6Z2toRP
            ujiCQJOeuqgdCwG8aVsOiHspTq9knwdAodbnGIlvZEOr5oA7hT7npknlYrNAcT+7mopnA
            yluQ89BKufOlkwOPjaSdbvNWWLp78Vh2jkhDgOuwMbMoxQgjieYtnfKc+bh1QOwNopXHH
            oYflBVn15VTiMcGsI0P1Bb2AbPpna2hE+6OIJAk566qB0LAbxpWw6IeylOr2SfB
        """)

    def test_xor_with_password(self):
        self.setServerBannerB64("""
            unvxWHaOSEOA67AxsyjFCCOJ5i2d8pz5uHVA7A2ilccehh+UFWfXlVOIxwawjQ/UFvYBs
            +mdraET7o4gkCTnrqoHQsBvGlbDoh7KU6vZJ8HQKHW5xiJb2RDq+aAO4U+56ZJ5WKzQHE
            /u5qKZwMpbkPPQSrnzpZMDj42knW7zVlhNubCx
        """)

        notif = pynsca.NSCANotifier('127.0.0.1', self.port, password='ham')
        notif.svc_result('linux-ix-slave10.build', 'buildbot-start', 0, 'hello!')

        self.assertGotB64("""
            0hmcMK4acQugOmHt20nECSyR9mGZ4tDnvHVb4V3/08QGhxKdfQa6/TLlr2fd5W65fpds24jwxcB+
            hu9N+EWKxstqKqECcjeuyn+nO8q0LdXULHC2wTcbwgXm47VjiS7UgfMUMM29dC6DjsP0qKs2+JK9
            ItiezfJu5+zJ9Q+ePjnXE5A1Hu8lK+GG2FDeQKRlS+iLRfyf9JjVHSGBZcP4r3/rd/V4D7b4O+mq
            btHgZ7V7nmDegfzAyXKD5kH9TIbDwmYvqA53PqLPdqs+w7gizN0pcvmrSjq0eIuUyG+MJ9iE+hg1
            xLFxJ4+Lyvitojr9m7En0ZLI+2Li5cXwBpI7MNsWmTkb5iku6IrdWdJFrWlO4YdA9ZPxkdkYKI1g
            yvSqdudy/HQKv/Q+4KZr2OxivHebadKE9czMe4/jSPFJj8/HbyOtB3s7q8NzojLGsUasuEkY0adP
            M7h9gpjNZoAi0Yj/ETnBuH0ihofP8aGnM/GeuCvUm8T+a+7gzPwDmzc10hqcMBfjICLtg9Fc20mo
            YELkjkzwmv2U0BQthGzP/aZz7n75fQa6/TLlr2fd5W65fpds24jwxcB+hu9N+EWKxstqKqECcjeu
            yn+nO8q0T6C9QBTUrkM2sXGHkcFjiS7UgfMUMM29dC6DjsP0qKs2+JK9ItiezfJu5+zJ9Q+ePjnX
            E5A1Hu8lK+GG2FDeQKRlS+iLRfyf9JjVHSGBZcP4r3/rd/V4D7b4O+mqbtHgZ7V7nmDegfzAyXKD
            5kH9TIbDwmYvqA53PqLPdqs+w7hKqbFFHdirSjq0eIuUyG+MJ9iE+hg1xLFxJ4+Lyvitojr9m7En
            0ZLI+2Li5cXwBpI7MNsWmTkb5iku6IrdWdJFrWlO4YdA9ZPxkdkYKI1gyvSqdudy/HQKv/Q+4KZr
            2OxivHebadKE9czMe4/jSPFJj8/HbyOtB3s7q8NzojLGsUas
        """)

class TestPacketMethods(unittest.TestCase):

    def setUp(self):
        self.notif = pynsca.NSCANotifier("host", 1234)

    def test_decode_from_server(self):
        fromserver = base64.b64decode("""
            unvxWHaOSEOA67AxsyjFCCOJ5i2d8pz5uHVA7A2ilccehh+UFWfXlVOIxwawjQ/UFvYBs+mdr
            aET7o4gkCTnrqoHQsBvGlbDoh7KU6vZJ8HQKHW5xiJb2RDq+aAO4U+56ZJ5WKzQHE/u5qKZwM
            pbkPPQSrnzpZMDj42knW7zVlhNubCx
        """)

        exp_iv = base64.b64decode("""
            unvxWHaOSEOA67AxsyjFCCOJ5i2d8pz5uHVA7A2ilccehh+UFWfXlVOIxwawjQ/UFvYBs+mdr
            aET7o4gkCTnrqoHQsBvGlbDoh7KU6vZJ8HQKHW5xiJb2RDq+aAO4U+56ZJ5WKzQHE/u5qKZwM
            pbkPPQSrnzpZMDj42knW7zVlg=
        """)

        got_iv, got_timestamp = self.notif._decode_from_server(fromserver)
        got_iv = [ ord(b) for b in got_iv ]
        exp_iv = [ ord(b) for b in exp_iv ]

        self.assertEqual((got_iv, got_timestamp), (exp_iv, 0x4db9b0b1))

    def test_encode_service_to_server(self):
        iv = base64.b64decode("""
        7ensPMny90d3fCFfruLNODYz6lm855IZDAku6g4Id/zyZDi7VjADzawkLVoH+pM+LX6X6
        WUqA3EzMVxCOtQ+LDh26I6n61xUEImvGINCV7HB75smGZ+YTdD1jwrJzjcBRSCQ7AzsQB
        127zX6Moyr83tHGpXms+O3qHPCckH6c4Y=""")
        timestamp = 1304029911

        exp_pkt = base64.b64decode("""
        7ersPBp/aAE6xcuIruKhUVhGknTVn79qYGhYjz84WZ6HDVTfVjADzawkLVoH+pM+LX6X6
        WUqA3EzMVxCOtQ+LDh26I6n61xUEImvGINCNcSog/9Eduu1PqSU/X7JzjcBRSCQ7AzsQB
        127zX6Moyr83tHGpXms+O3qHPCckH6c4bt6ew8yfL3R3d8IV+u4s04NjPqWbznkhkMCS7
        qDgh3/PJkOLtWMAPNrCQtWgf6kz4tfpfpZSoDcTMxXEI61D4sOHbojqfrXFQQia8Yg0I/
        1K2D9AcZn5hN0PWPCsnONwFFIJDsDOxAHXbvNfoyjKvze0caleaz47eoc8JyQfpzhu3p7
        DzJ8vdHd3whX67izTg2M+pZvOeSGQwJLuoOCHf88mQ4u1YwA82sJC1aB/qTPi1+l+llKg
        NxMzFcQjrUPiw4duiOp+tcVBCJrxiDQlexwe+bJhmfmE3Q9Y8Kyc43AUUgkOwM7EAddu8
        1+jKMq/N7RxqV5rPjt6hzwnJB+nOG7ensPMny90d3fCFfruLNODYz6lm855IZDAku6g4I
        d/zyZDi7VjADzawkLVoH+pM+LX6X6WUqA3EzMVxCOtQ+LDh26I6n61xUEImvGINCV7HB7
        5smGZ+YTdD1jwrJzjcBRSCQ7AzsQB127zX6Moyr83tHGpXms+O3qHPCckH6c4bt6ew8yf
        L3R3d8IV+u4s04NjPqWbznkhkMCS7qDgh3/PJkOLtWMAPNrCQtWgf6kz4tfpfpZSoDcTM
        xXEI61D4sOHbojqfrXFQQia8Yg0JXscHvmyYZn5hN0PWPCsnONwFFIJDsDOxAHXbvNfoy
        jKvze0caleaz47eoc8JyQfpzhu3p7DzJ8vdHd3whX67izTg2M+pZvOeSGQwJLuoOCHf88
        mQ4u1YwA82sJC1aB/qTPi1+l+llKgNxMzFcQjrUPiw4duiOp+tcVBCJrxiDQlex
        """)

        pkt = self.notif._encode_to_server(iv, timestamp, 0,
                'linux-ix-slave10.build', 'buildbot-start', 'hello!')
        self.assertEqual(
                [ ord(b) for b in exp_pkt ],
                [ ord(b) for b in pkt ])

    def test_encode_host_to_server(self):
        iv = base64.b64decode("""
        7ensPMny90d3fCFfruLNODYz6lm855IZDAku6g4Id/zyZDi7VjADzawkLVoH+pM+LX6X6
        WUqA3EzMVxCOtQ+LDh26I6n61xUEImvGINCV7HB75smGZ+YTdD1jwrJzjcBRSCQ7AzsQB
        127zX6Moyr83tHGpXms+O3qHPCckH6c4Y=""")
        timestamp = 1304029911

        exp_pkt = base64.b64decode("""
        7ersPMnky/k6xcuIruKhUVhGknTVn79qYGhYjz84WZ6HDVTfVjADzawkLVoH+pM+LX6X6WUqA3Ez
        MVxCOtQ+LDh26I6n61xUEImvGINCV7HB75smGZ+YTdD1jwrJzjcBRSCQ7AzsQB127zX6Moyr83tH
        GpXms+O3qHPCckH6c4bt6ew8yfL3R3d8IV+u4s04NjPqWbznkhkMCS7qDgh3/PJkOLtWMAPNrCQt
        Wgf6kz4tfpfpZSoDcTMxXEI61D4sOHbojqfrXFQQia8Yg0I/1K2D9AcZn5hN0PWPCsnONwFFIJDs
        DOxAHXbvNfoyjKvze0caleaz47eoc8JyQfpzhu3p7DzJ8vdHd3whX67izTg2M+pZvOeSGQwJLuoO
        CHf88mQ4u1YwA82sJC1aB/qTPi1+l+llKgNxMzFcQjrUPiw4duiOp+tcVBCJrxiDQlexwe+bJhmf
        mE3Q9Y8Kyc43AUUgkOwM7EAddu81+jKMq/N7RxqV5rPjt6hzwnJB+nOG7ensPMny90d3fCFfruLN
        ODYz6lm855IZDAku6g4Id/zyZDi7VjADzawkLVoH+pM+LX6X6WUqA3EzMVxCOtQ+LDh26I6n61xU
        EImvGINCV7HB75smGZ+YTdD1jwrJzjcBRSCQ7AzsQB127zX6Moyr83tHGpXms+O3qHPCckH6c4bt
        6ew8yfL3R3d8IV+u4s04NjPqWbznkhkMCS7qDgh3/PJkOLtWMAPNrCQtWgf6kz4tfpfpZSoDcTMx
        XEI61D4sOHbojqfrXFQQia8Yg0JXscHvmyYZn5hN0PWPCsnONwFFIJDsDOxAHXbvNfoyjKvze0ca
        leaz47eoc8JyQfpzhu3p7DzJ8vdHd3whX67izTg2M+pZvOeSGQwJLuoOCHf88mQ4u1YwA82sJC1a
        B/qTPi1+l+llKgNxMzFcQjrUPiw4duiOp+tcVBCJrxiDQlex
        """)

        pkt = self.notif._encode_to_server(iv, timestamp, 0,
                'linux-ix-slave10.build', '', 'hello!')
        self.assertEqual(
                [ ord(b) for b in exp_pkt ],
                [ ord(b) for b in pkt ])

    def test_encode_service_to_server_aes256(self):
        if not mcrypt:
            raise unittest.SkipTest("python-mcrypt not installed")
        iv = base64.b64decode("""
        7ensPMny90d3fCFfruLNODYz6lm855IZDAku6g4Id/zyZDi7VjADzawkLVoH+pM+LX6X6
        WUqA3EzMVxCOtQ+LDh26I6n61xUEImvGINCV7HB75smGZ+YTdD1jwrJzjcBRSCQ7AzsQB
        127zX6Moyr83tHGpXms+O3qHPCckH6c4Y=""")
        timestamp = 1304029911

        exp_pkt = base64.b64decode("""
        w0EnKnd4gHVklNEYZFDS1u/mnDk2jtpz1sCfQjFfc/e/17ngOzEOgiasHLMCLm5eJ36BowwVSZGP
        yZk1amnUljA+ZMXrfOo2rhEB8wN7x3+M91br71Zw3GSEvBCvjQBofJ2SUwBNMG6g64E1lVwe5yoH
        LhOwMmXqQ82mSEcWTMbMY3H0+UaqLoglCW9gRXjMauKTfpRcbPLqKcIuCBmPFgV3PrkrZ/pIu3qY
        hrwY5u5Eg0xFBXy8iiwL3I9Kc9uewJHWHA4SAL01eg+e36Y1yT+fZMA7WX/HSMYv0o/+do8JoSvm
        Mf4TiGxHBqdDMKMOLSlUeaisO6fA9krtJ1RRDpyy8xJ1ZnToRwMIt6cNtEjuZNMUewr79ZH17D3N
        BhEpFzbN/B50JrAyp8GG4+EcG9DU6uEX8BohMV6PTG59HW/Hr8PXTcVAH4VNCr+UED8BHdg39niL
        +ehQbOSqyTpLuhtSx53KZHSk8Se5cQQJciy6Ioizx3UH2sHfMxJcYX24BjB728SmF9Oj3EUZjsLW
        q7QnEvUTjkBGXqKvtgBRNHE3ZLGZxpkbf1eX6WKMmU+Xu3mRmbkGiRe/xefEUTIDOVTD1WBrtTqP
        McE9DQp+rTBeGHZGfa0RuCb1f+1TKD5/v6OcplStx0Sp3T39RkP7yzy2hItq5Newyi05mQf27Va5
        E7NTMMSKRYqTtqTH/hproDI8n1hMMcAAWLxfN750ACCAl13lMxmGaobtyvYDMhj6DVSn9fkHxP86
        7aw6NLUgMyq7w5xo6BfcAdvu4o1N7hkDNkq96iELZRQ7D8Xyb2cfCRRnrwNpIImgepgKSPRoyOed
        c1qoqbwFNGwPlokd3ecOaB2eeLx2s9DtLNdG0RB0GbGuS7SbD17egmvOa9DXDgeYw9humZE2kJNy
        OSL4Q5gJVSqB9CTjHMduaozrMQE0MS6gUj8k0OC7knpCHNhG
        """)

        pkt = self.notif._encode_to_server(iv, timestamp, 0,
                'linux-ix-slave10.build', 'buildbot-start', 'hello!',
                16, '1234')
        self.assertEqual(
                [ ord(b) for b in exp_pkt ],
                [ ord(b) for b in pkt ])

if __name__ == '__main__':
    unittest.main()
