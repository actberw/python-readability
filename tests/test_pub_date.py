#coding=utf-8

import unittest, datetime
from readability.readability import Document

class PubDateTestCase(unittest.TestCase):
    def setUp(self):
        self.html = open('./samples/21853124_0.shtml').read() 

    def test_pub_date(self):
        html = self.html
        doc = Document(html)
        doc.transform()
        self.assertEqual(datetime.datetime(2013, 2, 1, 11, 16), doc.get_publish_date())
        self.assertEqual('PN039', doc.get_author())

if __name__ == '__main__':
    unittest.main()
