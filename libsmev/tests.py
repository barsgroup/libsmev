import unittest

from lxml import etree

from helpers import dict_to_xmldoc
from namespaces import NS_MAP


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


if __name__ == '__main__':
    unittest.main()
