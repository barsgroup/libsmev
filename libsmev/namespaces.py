#coding: utf-8

from lxml import etree

NS_MAP = {
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "smev": "http://smev.gosuslugi.ru/rev120315",
    "SOAP-ENV": "http://schemas.xmlsoap.org/soap/envelope/",
    "wsse": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
    "wsu": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
    "ws": "http://pe.minregion.ru/",
    "inf": "http://smev.gosuslugi.ru/inf/"
}

make_node_with_ns = lambda ns: lambda el_name: etree.Element('{%s}%s' % (NS_MAP[ns], el_name), nsmap={ns: NS_MAP[ns]})
