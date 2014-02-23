#coding: utf-8

import shutil
import base64
import StringIO
import uuid
import unittest
import os
import zipfile

from lxml import etree
from mimetypes import types_map
from tempfile import NamedTemporaryFile, mkdtemp

from skeleton import construct_smev_envelope
from helpers import dict_to_xmldoc, extract_smev_parts
from namespaces import NS_MAP
from signer import sign_document, verify_envelope_signature, get_text_digest
from attachments import encode_directory, extract_directory

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

TEST_ENVELOPE = r'''<?xml version='1.0' encoding='utf-8'?>
<SOAP-ENV:Envelope xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:ws="http://pe.minregion.ru/" xmlns:smev="http://smev.gosuslugi.ru/rev120315" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:inf="http://smev.gosuslugi.ru/inf/" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Header><wsse:Security SOAP-ENV:actor="http://smev.gosuslugi.ru/actors/smev"><wsse:BinarySecurityToken EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3" wsu:Id="CertId">MIIBtzCCAWQCCQCUhYafJf4zaTAKBgYqhQMCAgMFADBiMQswCQYDVQQGEwJSVTESMBAGA1UECAwJVGF0YXJzdGFuMQ4wDAYDVQQHDAVLYXphbjETMBEGA1UECgwKQkFSUy1Hcm91cDEMMAoGA1UECwwDRURVMQwwCgYDVQQDDANFRFUwHhcNMTIxMDIxMTAzMzQyWhcNMTMxMDIyMTAzMzQyWjBiMQswCQYDVQQGEwJSVTESMBAGA1UECAwJVGF0YXJzdGFuMQ4wDAYDVQQHDAVLYXphbjETMBEGA1UECgwKQkFSUy1Hcm91cDEMMAoGA1UECwwDRURVMQwwCgYDVQQDDANFRFUwYzAcBgYqhQMCAhMwEgYHKoUDAgIjAQYHKoUDAgIeAQNDAARAxdw/hP6gGRCqSYKMptrnObSGeu6OZ1Cc80WmbPR7S34hSvjGIe2fEClMpDzBKZjuMsIijY3QxlIWyLZXYMX3bzAKBgYqhQMCAgMFAANBAMc+WaiPp8PLXZHAL6EgXDXomPIA7s97dHvPYqOlfuAmENZ/8yNvYN/VT4DdsqtRrZtMo0OgPmZZIIpBTbUSyvg=</wsse:BinarySecurityToken><ds:Signature><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411"/><ds:Reference URI="#body"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#gostr3411"/><ds:DigestValue>y1Feix2ktiF64VtgPmEyBtam5yaxkJeGdTcX3bg44h0=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>5OyGOTSI0Nu+unDVU1c9jDn6fHIqILyKP8QJMefyqJ6zt7Oqxn+ws4wCkAU+FiNeBbPvty433CMPnOcSP6bgBg==</ds:SignatureValue><ds:KeyInfo><wsse:SecurityTokenReference><wsse:Reference URI="#CertId" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"/></wsse:SecurityTokenReference></ds:KeyInfo></ds:Signature></wsse:Security></SOAP-ENV:Header><SOAP-ENV:Body wsu:Id="body"><inf:TestRequest><smev:Message><smev:Sender><smev:Code>AAAA11112</smev:Code><smev:Name>Sender</smev:Name></smev:Sender><smev:Recipient><smev:Code>BBBB22222</smev:Code><smev:Name>Recipient</smev:Name></smev:Recipient><smev:Originator><smev:Code>AAAA11112</smev:Code><smev:Name>Originator</smev:Name></smev:Originator><smev:Service><smev:Mnemonic>TEST001001</smev:Mnemonic><smev:Version>0.10</smev:Version></smev:Service><smev:TypeCode>GSRV</smev:TypeCode><smev:Status>REQUEST</smev:Status><smev:Date>2014-02-23T11:54:38.8091</smev:Date><smev:ExchangeType>0</smev:ExchangeType><smev:TestMsg>true</smev:TestMsg></smev:Message><smev:MessageData><smev:AppData wsu:Id="AppData"><inf:Phrases><inf:Greeting><inf:Hello>World</inf:Hello></inf:Greeting></inf:Phrases></smev:AppData><smev:AppDocument><smev:RequestCode/><smev:BinaryData/></smev:AppDocument></smev:MessageData></inf:TestRequest></SOAP-ENV:Body></SOAP-ENV:Envelope>
'''

class TestHelpersFunctions(unittest.TestCase):
    def setUp(self):
        self.empty_doc = etree.Element('Empty')
        self.envelope = etree.fromstring(TEST_ENVELOPE)

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


    def test_extract_smev_parts(self):
        parts = extract_smev_parts(self.envelope)
        assert len(parts) == 4, "Too many or too few parts returned."

        tags = (
            '{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}BinarySecurityToken',
            '{http://www.w3.org/2000/09/xmldsig#}Signature',
            '{http://smev.gosuslugi.ru/rev120315}Message',
            '{http://smev.gosuslugi.ru/rev120315}MessageData'
        )
        for (part, full_tag) in zip(parts, tags):
            assert part.tag == full_tag, "{0} != {1}".format(part, full_part)


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


class TestAttachments(unittest.TestCase):
    def setUp(self):
        self.directory = mkdtemp()
        self.files = ['%s%s' % (str(uuid.uuid4()), ext) for ext in types_map.keys()]

        # Файл без расширения, по которому можно было бы определить MIME-тип

        self.example_text = str(uuid.uuid4())
        self.example_hash = get_text_digest(self.example_text)
        self.example_sig_hash = get_text_digest(self.example_hash)

        for fn in self.files:
            with open(os.path.join(self.directory, fn), 'w') as f:
                f.write(self.example_text)

    def testEncode(self):
        req_code, encoded_zip = encode_directory(self.directory)
        decoded_zip = base64.b64decode(encoded_zip)
        sio = StringIO.StringIO(decoded_zip)
        zip_arc = zipfile.ZipFile(sio, 'r')

        for fn in self.files:
            f = zip_arc.open(fn, 'r')
            text = f.read()
            f.close()

            sig_f = zip_arc.open('%s.sig' % fn, 'r')
            dgst_text = sig_f.read()
            sig_f.close()

            assert dgst_text == self.example_hash, u'Digests are not identical!'
            assert text == self.example_text, u'Text in file is corrupted!'

        with open('tmp.zip', 'wb') as f:
            f.write(decoded_zip)

    def testExtract(self):
        req_code, encoded_zip = encode_directory(self.directory)
        manifest, extracted_to = extract_directory(req_code, encoded_zip)

        applied_documents_node = manifest.xpath('//AppliedDocuments')
        assert applied_documents_node, '"AppliedDocuments" node not found!'
        applied_documents = applied_documents_node[0].xpath('.//AppliedDocument')
        assert applied_documents, 'No documents in manifest!'

        for doc in applied_documents:
            doc_info = dict([(n.tag, n.text) for n in doc])

            if doc_info['URL'].endswith('.sig'):
                assert doc_info['DigestValue'] == self.example_sig_hash, u'Digests are not identical!'
            else:
                assert doc_info['URL'] in self.files, u'Path "%s" outside of testing set!' % doc_info['URL']
                assert doc_info['DigestValue'] == self.example_hash, u'Digests are not identical!'

            dot_pos = doc_info['URL'].rindex('.')
            if dot_pos:
                ext = doc_info['URL'][dot_pos:]
                if ext != '.sig':
                    assert doc_info['Type'] == types_map[ext], 'Invalid MIME type "%s" for "%s"' % (doc_info['Type'], ext)
            else:
                assert doc_info['Type'] == 'application/octet-stream', 'File without extension not classified as octet-stream!'

    def tearDown(self):
        shutil.rmtree(self.directory)

if __name__ == '__main__':
    unittest.main()
