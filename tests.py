# -*- coding: utf-8 -*-

import unittest
import utils


class UtilsTest(unittest.TestCase):

    def test_fin_unmasked_text(self):
        head = utils.parse_frame_head('\x81\x05')
        self.assertTrue(head['fin'])
        self.assertEqual(head['opcode'], 0x1)
        self.assertFalse(head['mask'])
        self.assertEqual(head['payload_len'], 5)
        self.assertEqual(head['more'], 0)

    def test_fin_masked_text(self):
        head = utils.parse_frame_head('\x81\x85')
        self.assertTrue(head['fin'])
        self.assertEqual(head['opcode'], 0x1)
        self.assertTrue(head['mask'])
        self.assertEqual(head['payload_len'], 5)
        self.assertEqual(head['more'], 4)

    def test_unmasked_ping_request(self):
        head = utils.parse_frame_head('\x89\x05')
        self.assertTrue(head['fin'])
        self.assertEqual(head['opcode'], 0x9)
        self.assertFalse(head['mask'])
        self.assertEqual(head['payload_len'], 5)
        self.assertEqual(head['more'], 0)

    def test_masked_ping_response(self):
        head = utils.parse_frame_head('\x8a\x85')
        self.assertTrue(head['fin'])
        self.assertEqual(head['opcode'], 0xA)
        self.assertTrue(head['mask'])
        self.assertEqual(head['payload_len'], 5)
        self.assertEqual(head['more'], 4)

    def test_fragmented_unmasked_text(self):
        head = utils.parse_frame_head('\x01\x03')
        self.assertFalse(head['fin'])
        self.assertEqual(head['opcode'], 0x1)
        self.assertFalse(head['mask'])
        self.assertEqual(head['payload_len'], 3)
        self.assertEqual(head['more'], 0)
        head = utils.parse_frame_head('\x80\x02')
        self.assertTrue(head['fin'])
        self.assertEqual(head['opcode'], 0x0)
        self.assertFalse(head['mask'])
        self.assertEqual(head['payload_len'], 2)
        self.assertEqual(head['more'], 0)

    def test_unmasked_binary_256b(self):
        head = utils.parse_frame_head('\x82\x7e')
        self.assertTrue(head['fin'])
        self.assertEqual(head['opcode'], 0x2)
        self.assertFalse(head['mask'])
        self.assertEqual(head['payload_len'], 126)
        self.assertEqual(head['more'], 2)

    def test_unmasked_binary_64k(self):
        head = utils.parse_frame_head('\x82\x7F')
        self.assertTrue(head['fin'])
        self.assertEqual(head['opcode'], 0x2)
        self.assertFalse(head['mask'])
        self.assertEqual(head['payload_len'], 127)
        self.assertEqual(head['more'], 8)

    def test_masking_text(self):
        self.assertEqual(utils.apply_mask('Hello', '7\xfa!='), '\x7f\x9fMQX')

    def test_unmasking_text(self):
        self.assertEqual(utils.apply_mask('\x7f\x9fMQX', '7\xfa!='), 'Hello')


if __name__ == '__main__':
    unittest.main()
