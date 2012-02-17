# -*- coding: utf-8 -*-

import os
import sys
import base64
import hashlib
import socket
import asynchat
import asyncore
import mimetools
from StringIO import StringIO

from utils import format_header, parse_frame_head, apply_mask,\
                  consider_extended_frame_head, create_message


_ws_key = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11'

CONTROL_FRAME_TYPES = {
    0x8: 'close',
    0x9: 'ping',
    0xA: 'pong',
}


class FrameReaderWriter(asynchat.async_chat):

    collect_incoming_data = asynchat.async_chat._collect_incoming_data
    require_masking = False
    mask_outgoing = False

    def __init__(self):
        asynchat.async_chat.__init__(self)
        self.set_terminator('\r\n\r\n')
        self.process_data = self._handle_handshake
        self.frames = []
        self._closing_frame_sent = False

    def handle_error(self):
        raise

    def found_terminator(self):
        self.process_data()

    def _on_message(self, message, binary=False):
        self.log_info('on_message: {0}'.format(message))

    def on_connect(self):
        self.log_info('on_connect')

    def on_close(self, close):
        self.log_info('on_close')

    def send_message(self, message, opcode=0x1):
        self.log_info('send_message({1}): {0}'.format(message, repr(self)))
        mask = ''
        if self.mask_outgoing:
            mask = os.urandom(4)
        self.push(create_message(message, mask=mask, opcode=opcode))

    def send_close_message(self, payload=''):
        self._closing_frame_sent = True
        self.send_message(payload, opcode=0x8)

    def handle_handshake(self):
        raise NotImplementedError()

    def _handle_handshake(self):
        self.handle_handshake()
        self.process_data = self._parse_frame_head
        # minimal posible frame length
        self.set_terminator(2)
        self.on_connect()

    def _parse_frame_head(self):
        data = self._get_data()
        frame = parse_frame_head(data)
        self.frames.append(frame)
        more, plen = frame['more'], frame['payload_len']
        if self.require_masking:
            assert frame['mask']
        if more:
            self.process_data = self._parse_extended_frame_head
            self.set_terminator(more)
        elif plen:
            self.process_data = self._parse_frame_payload
            self.set_terminator(plen)
        else:
            # unmasked frame (no payload)
            self._handle_frame()

    def _parse_extended_frame_head(self):
        frame = self.frames[-1]
        consider_extended_frame_head(frame, self._get_data())
        plen = frame['payload_len']
        if plen:
            self.process_data = self._parse_frame_payload
            self.set_terminator(plen)
        else:
            # masked frame (no payload)
            self._handle_frame()

    def _parse_frame_payload(self):
        frame = self.frames[-1]
        payload = self._get_data()
        if frame['mask'] and payload:
            payload = apply_mask(payload, frame['mask'])
        frame['payload'] = payload
        self._handle_frame()

    def _handle_frame(self):
        control_frame = CONTROL_FRAME_TYPES.get(self.frames[-1]['opcode'], None)
        # control frames
        if control_frame:
            assert self.frames[-1]['fin']
            # every such handler removes last frame
            getattr(self, '_ctl_frame_%s' % control_frame)()
        if self.frames:
            if self.frames[-1]['fin']:
                self._handle_fin_frame()
            else:
                assert self.frames[-1]['opcode']==0x0
        self.process_data = self._parse_frame_head
        self.set_terminator(2)

    def _handle_fin_frame(self):
        payload_type = self.frames[0]['opcode']
        assert payload_type in (0x1, 0x2)
        message = ''.join([f['payload'] for f in self.frames])
        if payload_type == 0x1:
            message = message.decode('utf-8')
        self.frames = []
        self._on_message(message, binary=payload_type==0x2)

    def _ctl_frame_close(self):
        frame = self.frames.pop()
        payload = frame['payload']
        if frame['mask'] and payload:
            payload = apply_mask(payload, frame['mask'])
        self.log_info('Connection is closing: %s' % payload)
        if self._closing_frame_sent:
            self.close()
        else:
            self.send_message(payload, opcode=0x8)
            self.close_when_done()
        self.on_close(payload)
        sys.exit(0)

    def _ctl_frame_ping(self):
        frame = self.frames.pop()
        self.send_message(frame['payload'], opcode=0xA)

    def _ctl_frame_pong(self):
        self.frames.pop()
        # there is no response for pong frame


class Client(FrameReaderWriter):

    mask_outgoing = True

    def __init__(self, host, port, path='/'):
        self.host = host
        self.port = port
        self.path = path
        self._key = base64.b64encode(os.urandom(16))
        self._response_key = base64.b64encode(
                hashlib.sha1(self._key+_ws_key).digest())
        FrameReaderWriter.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect((host, port))

    def handle_connect(self):
        self.push('GET {0} HTTP/1.1\r\n'.format(self.path))
        self.push(format_header('Host', self.host))
        self.push(format_header('Connection', 'Upgrade'))
        self.push(format_header('Upgrade', 'websocket'))
        self.push(format_header('Sec-Websocket-Key', self._key))
        self.push(format_header('Sec-Websocket-Protocol', 'chat'))
        self.push(format_header('Sec-Websocket-Version', '13'))
        self.push('\r\n')

    def handle_handshake(self):
        response_status_line, headers = self._get_data().split('\r\n', 1)
        assert response_status_line.lower().startswith('http/1.1 101 ')
        # omg
        headers = mimetools.Message(StringIO(headers))
        assert headers.get('connection', '').lower() == 'upgrade'
        assert headers.get('upgrade', '').lower() == 'websocket'
        assert headers.get('sec-websocket-accept', '') == self._response_key

    def _on_message(self, message, binary):
        self.on_message(message, binary)


class ClientHandler(FrameReaderWriter):

    require_masking = True

    def __init__(self, sock, on_message):
        FrameReaderWriter.__init__(self)
        self.set_socket(sock)
        self._response_key = ''
        self.on_message = on_message

    def handle_handshake(self):
        request, headers = self._get_data().split('\r\n', 1)
        assert request.lower()== 'get / http/1.1'
        headers = mimetools.Message(StringIO(headers))
        assert headers.get('connection', '').lower() == 'upgrade'
        assert headers.get('upgrade', '').lower() == 'websocket'
        assert headers.get('sec-websocket-version', '') == '13'
        key = headers.get('sec-websocket-key', '')
        assert key
        self._response_key = rkey = base64.b64encode(
                hashlib.sha1(key+_ws_key).digest())
        self.push('HTTP/1.1 101 Switching Protocols\r\n')
        self.push(format_header('Connection', 'Upgrade'))
        self.push(format_header('Upgrade', 'websocket'))
        self.push(format_header('Sec-Websocket-Accept', rkey))
        self.push(format_header('Sec-Websocket-Protocol', 'chat'))
        self.push('\r\n')

    def _on_message(self, message, binary):
        self.on_message(self, message, binary)




class Server(asyncore.dispatcher):

    def __init__(self, host, port, path='/'):
        self.host = host
        self.port = port
        self.path = path
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.bind((host, port))
        self.listen(5)

    def handle_accept(self):
        client_info = self.accept()
        ClientHandler(client_info[0], self.on_message)


if __name__ == '__main__':
    try:
        class EchoClient(Client):
            def on_connect(self):
                self.send_message('Hello')
                #self.send_close_message()
            def on_message(self, message, binary=False):
                self.log_info('client got: {0}'.format(message))
                self.send_message(message+' !')

        class EchoServer(Server):
            def on_message(self, client, message, binary=False):
                self.log_info('server got: {0}'.format(message))
                client.send_message(message)

        host, port = 'localhost', 2828
        server = EchoServer(host, port)
        client = EchoClient(host, port)
        asyncore.loop()
    except KeyboardInterrupt:
        client.send_close_message()
        asyncore.loop()
