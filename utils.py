# -*- coding: utf-8 -*-

import struct


def format_header(name, value):
    return '{0}: {1}\r\n'.format(name.capitalize(), value)


def parse_frame_head(head):
    assert len(head) == 2
    first, last = map(ord, head)
    rv = {'payload': ''}
    rv['fin'] = test_bit(first, 7)
    rv['rsv1'] = test_bit(first, 6)
    rv['rsv2'] = test_bit(first, 5)
    rv['rsv3'] = test_bit(first, 4)
    rv['opcode'] = first & 15
    rv['mask'] = mask = test_bit(last, 7)
    rv['payload_len'] = plen = last & 127
    rv['more'] = 0
    if plen == 126:
        rv['more'] += 2
    elif plen == 127:
        rv['more'] += 8
    if mask:
        rv['more'] += 4
    return rv


def consider_extended_frame_head(frame_head, more):
    plen = frame_head['payload_len']
    if plen == 126:
        frame_head['payload_len'] = struct.unpack('>H', more[:2])[0]
    elif plen == 127:
        frame_head['payload_len'] = struct.unpack('>Q', more[:8])[0]
    if frame_head['mask']:
        frame_head['mask'] = more[-4:]

def apply_mask(data, mask):
    mask = map(ord, mask)
    encoded_octets = [chr(ord(c)^mask[i%4]) for i, c in enumerate(data)]
    return ''.join(encoded_octets)


def test_bit(int_type, offset):
    return (int_type & (1 << offset))


#XXX consider binary data packing
def create_message(payload='', fin=1, mask='', opcode=0x1):
    first, last = 0, 0
    if fin:
        first |= 1 << 7
    first |= opcode
    if isinstance(payload, unicode):
        payload = payload.encode('utf-8')
    if mask:
        last |= 1 << 7
        payload = apply_mask(payload, mask)
    plen = len(payload)
    additional_plen = ''
    if plen <= 125:
        last = last | plen
    elif plen <= 65535:
        last = last | 126
        additional_plen = struct.pack('>H', plen)
    else:
        last = last | 127
        additional_plen = struct.pack('>Q', plen)
    head = chr(first) + chr(last) + additional_plen
    if mask:
        head += mask
    return  head + payload
