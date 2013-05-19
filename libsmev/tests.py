#coding: utf-8

import unittest
import os

from lxml import etree

from tempfile import NamedTemporaryFile

from skeleton import construct_smev_envelope
from helpers import dict_to_xmldoc
from namespaces import NS_MAP
from signer import sign_document, verify_envelope_signature

# Тестовый ключ
PEM = r'''
-----BEGIN CERTIFICATE-----
MIIBtzCCAWQCCQCUhYafJf4zaTAKBgYqhQMCAgMFADBiMQswCQYDVQQGEwJSVTES
MBAGA1UECAwJVGF0YXJzdGFuMQ4wDAYDVQQHDAVLYXphbjETMBEGA1UECgwKQkFS
Uy1Hcm91cDEMMAoGA1UECwwDRURVMQwwCgYDVQQDDANFRFUwHhcNMTIxMDIxMTAz
MzQyWhcNMTMxMDIyMTAzMzQyWjBiMQswCQYDVQQGEwJSVTESMBAGA1UECAwJVGF0
YXJzdGFuMQ4wDAYDVQQHDAVLYXphbjETMBEGA1UECgwKQkFSUy1Hcm91cDEMMAoG
A1UECwwDRURVMQwwCgYDVQQDDANFRFUwYzAcBgYqhQMCAhMwEgYHKoUDAgIjAQYH
KoUDAgIeAQNDAARAxdw/hP6gGRCqSYKMptrnObSGeu6OZ1Cc80WmbPR7S34hSvjG
Ie2fEClMpDzBKZjuMsIijY3QxlIWyLZXYMX3bzAKBgYqhQMCAgMFAANBAMc+WaiP
p8PLXZHAL6EgXDXomPIA7s97dHvPYqOlfuAmENZ/8yNvYN/VT4DdsqtRrZtMo0Og
PmZZIIpBTbUSyvg=
-----END CERTIFICATE-----

-----BEGIN ENCRYPTED PRIVATE KEY-----
MIGMMEAGCSqGSIb3DQEFDTAzMBsGCSqGSIb3DQEFDDAOBAg3P+ShojSyRAICCAAw
FAYIKoZIhvcNAwcECLhovJf8tmC3BEhjHrDcLeg8vPnIMXdl8j4J6fsmcoSV9d7V
MpXUYhi0SVVPA37O6LrLL6nqwRucIgZzVfpBKinmNvM9tdC4gVt+xepETiB1WsM=
-----END ENCRYPTED PRIVATE KEY-----
'''
PEM_PASS = 'BARS_PASS_sidurniq38ymlskjn,jh<HGjhBJKGjmHGJKGM'

class TestHelpersFunctions(unittest.TestCase):
    def setUp(self):
        self.empty_doc = etree.Element('Empty')

    def test_dict_to_xmldoc(self):
        test_dict = {
            'InfNode': {
                '__ns__': 'inf',
                'Var1': 'Hello',
                'Var2': 'world'
            },
            'NodeWithoutNs': {
                'Test1': 'Hello, world?',
                'Test2': 'Bandersnatch',
                'Surpise': {
                    '__ns__': 'smev',
                    'Recipient': 'Someone',
                    'Sender': 'Someone else'
                }
            }
        }

        dict_to_xmldoc(self.empty_doc, test_dict)

        paths_and_values = {
            '//Empty/InfNode/inf:Var1': test_dict['InfNode']['Var1'],
            '//Empty/InfNode/inf:Var2': test_dict['InfNode']['Var2'],
            '//Empty/NodeWithoutNs/Test1': test_dict['NodeWithoutNs']['Test1'],
            '//Empty/NodeWithoutNs/Test2': test_dict['NodeWithoutNs']['Test2'],
            '//Empty/NodeWithoutNs/Surpise/smev:Recipient': test_dict['NodeWithoutNs']['Surpise']['Recipient'],
            '//Empty/NodeWithoutNs/Surpise/smev:Sender': test_dict['NodeWithoutNs']['Surpise']['Sender'],
        }

        for xpath, val in paths_and_values.items():
            inf_node = self.empty_doc.xpath(xpath, namespaces=NS_MAP)
            assert inf_node, 'XPath "%s" returned no nodes!' % xpath
            self.assertEquals(inf_node[0].text, val)


class TestSkeletonFunction(unittest.TestCase):
    def setUp(self):
        self.ctx = {
            'Service': {
                'Mnemonic': 'MONR001001',
                'Version': '0.10'
            },
            'Sender': {
                'Code': "SEND01001",
                'Name': "Sender"
            },
            'Recipient': {
                'Code': 'RECV01001',
                'Name': 'Recipient'
            },
            'Originator': {
                'Code': "SEND01001",
                'Name': "Sender's origin"
            },
            'TypeCode': 'GSRV',
            'Status': 'REQUEST',
            'TestMsg': True
        }

        self.req = construct_smev_envelope('TestPacket', self.ctx)

    def test_envelope_creation(self):        
        prefix = './/SOAP-ENV:Body/inf:TestPacket/smev:Message'

        paths_and_values = {
            '%s/smev:Service/smev:Mnemonic' % prefix: self.ctx['Service']['Mnemonic'],
            '%s/smev:Service/smev:Version' % prefix: self.ctx['Service']['Version'],
            '%s/smev:Sender/smev:Code' % prefix: self.ctx['Sender']['Code'],
            '%s/smev:Sender/smev:Name' % prefix: self.ctx['Sender']['Name'],
            '%s/smev:Recipient/smev:Code' % prefix: self.ctx['Recipient']['Code'],
            '%s/smev:Recipient/smev:Name' % prefix: self.ctx['Recipient']['Name'],
            '%s/smev:Originator/smev:Code' % prefix: self.ctx['Originator']['Code'],
            '%s/smev:Originator/smev:Name' % prefix: self.ctx['Originator']['Name'],
            '%s/smev:TypeCode' % prefix: self.ctx['TypeCode'],
            '%s/smev:Status' % prefix: self.ctx['Status'],
            '%s/smev:TestMsg' % prefix: 'true',
        }

        for xpath, val in paths_and_values.items():
            node = self.req.xpath(xpath, namespaces=NS_MAP)
            assert node, 'XPath "%s" returned no nodes!' % xpath
            self.assertEquals(node[0].text, val)


class TestSigner(unittest.TestCase):
    def setUp(self):
        self.ctx = {
            'Service': {
                'Mnemonic': 'MONR001001',
                'Version': '0.10'
            },
            'Sender': {
                'Code': "SEND01001",
                'Name': "Sender"
            },
            'Recipient': {
                'Code': 'RECV01001',
                'Name': 'Recipient'
            },
            'Originator': {
                'Code': "SEND01001",
                'Name': "Sender's origin"
            },
            'TypeCode': 'GSRV',
            'Status': 'REQUEST',
            'TestMsg': True
        }

        self.req = construct_smev_envelope('TestPacket', self.ctx)
        self.tmp_file = NamedTemporaryFile(delete=False)
        self.tmp_file.write(PEM)
        self.tmp_file.close()

    def test_sign_verify(self):
        signed = sign_document(self.req, self.tmp_file.name, PEM_PASS)
        assert verify_envelope_signature(signed), 'Signing mechanism produced invalid signature :('

        sender_node = signed.xpath('.//SOAP-ENV:Body/inf:TestPacket/smev:Message/smev:Sender/smev:Name', namespaces=NS_MAP)[0]
        sender_node.text = 'Impersonator'
        assert not verify_envelope_signature(signed), 'Document was changed, but signature still verifies!'


    def tearDown(self):
        os.remove(self.tmp_file.name)

if __name__ == '__main__':
    unittest.main()
