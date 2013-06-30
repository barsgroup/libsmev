#coding: utf-8

import subprocess

from lxml import etree
from lxml.etree import XMLSyntaxError

from namespaces import NS_MAP, REVERSE_NS_MAP, make_node_with_ns


class Fault(Exception):
    u'''
    Системная ошибка.
    '''
    pass


def tags(doc, path, ns_map=None):
    u'''
    Выборка XML-элемента по указанному XPath c заранее прописанным
    пространством имен.

    Существует исключительно для удобства.

    @param  doc     XML-документ, по которому производится выборка.
    @type   doc     lxml.Element

    @param  path    XPath-выражение.
    @type   path    unicode

    @param  ns_map  Словарь с пространством имен.
    @type   dict

    @return Найденные по выражению тэги.
    @rtype  list of lxml.Element
    '''

    if ns_map is None:
        ns_map = NS_MAP
    return doc.xpath(path, namespaces=ns_map)


def tag_single(doc, path, ns_map=None):
    u'''
    Выбор единичного XML-элемента по указанному XPath c заранее прописанным
    пространством имен.

    Если элемент не найден, возвращается None.
    Если найден более чем один элемент - выбрасывается исключение ValueError.

    Существует исключительно для удобства.

    @param  doc     XML-документ, по которому производится выборка.
    @type   doc     lxml.Element

    @param  path    XPath-выражение.
    @type   path    unicode

    @param  ns_map  Словарь с пространством имен.
    @type   ns_map  dict

    @return Найденный XML-элемент.
    @rtype  lxml.Element
    '''

    result = tags(doc, path, ns_map)
    if not result:
        return None
    if len(result) > 1:
        raise ValueError('Multiple tags found for "%s"' % path)
    return result[0]


# Замыкание для создания XML-элемента с указанным именем.
make_node = lambda el_name: etree.Element(('%s' % el_name))


def run_cmd(cmd, input=None):
    u'''
    Выполняем команду в интерпретаторе ОС и считываем выводимые ею данные.

    @param  cmd     Команда для запуска.
    @type   cmd     unicode

    @param  input   Входные данные, которые будут поданы на stdin.
    @type   input   unicode

    @return Вывод вызванной программы
    @rtype  unicode
    '''
    pr = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)

    return pr.communicate(input=input)


def parse_xml_string(xml_string, charset=u'utf-8',
                     parser=etree.XMLParser(remove_comments=True)):
    u'''
    Разбор строки, содержащей XML-документ с настраиваемым парсером.

    По умолчанию используется парсер, удаляющий комментарии из документа.

    @param  xml_string  Строка, содержащая XML-документ.
    @type   xml_string  unicode

    @param  charset     Кодировка.
    @type   charset     unicode

    @param  parser      Парсер, используемый для разбора строки.
    @type   parser      function       

    @return Корень XML-документа.
    @rtype  lxml.Element
    '''
    try:
        try:
            root, xmlids = etree.XMLID(xml_string, parser)
        except XMLSyntaxError as err:
            raise Fault(unicode(err))
    except ValueError:
        try:
            root, xmlids = etree.XMLID(xml_string.encode(charset), parser)
        except XMLSyntaxError as err:
            raise Fault(unicode(err))
    return root


def _from_soap(envelope):
    u'''
    Выделение заголовка и тела SOAP-запроса из XML-документа.

    @param  envelope    XML-документ, содержащий SOAP-запрос.
    @type   envelope    lxml.Element

    @return Заголовок и тело запроса.
    @rtype  list of lxml.Element
    '''

    # Выделение из конверта заголовка и тела запроса.
    if envelope.tag != "{%s}Envelope" % NS_MAP['SOAP-ENV']:
        raise Fault("No {%s}Envelope element was found!" % NS_MAP['SOAP-ENV'])

    header_envelope = envelope.xpath("e:Header", namespaces={"e": NS_MAP['SOAP-ENV']})
    body_envelope = envelope.xpath("e:Body", namespaces={"e": NS_MAP['SOAP-ENV']})

    if len(header_envelope) == 0 and len(body_envelope) == 0:
        raise Fault("Soap envelope is empty!")

    header = None
    if len(header_envelope) > 0:
        header = header_envelope[0]

    body = None
    if len(body_envelope) > 0:
        body = body_envelope[0]

    return header, body


def extract_smev_parts(envelope):
    u'''
    Выделение из SOAP-запроса относящихся к СМЭВу частей.

    @param  envelope    XML-документ, содержащий SOAP-запрос.
    @type   envelope    lxml.Element

    @return Информация о подписи, заголовок сообщения, сообщение.
    @rtype  list of lxml.Element
    '''

    header, body = _from_soap(envelope)

    security_node = tags(header, 'wsse:Security')
    if security_node:
        security_node = security_node[0]
        token_node = tags(security_node, 'wsse:BinarySecurityToken')[0]
        signature_node = tags(security_node, 'ds:signature_node')[0]
    else:
        token_node = signature_node = None

    message_node = tags(body, '//smev:Message')[0]
    message_data_node = tags(body, '//smev:MessageData')[0]

    return token_node, signature_node, message_node, message_data_node


def dict_to_xmldoc(node, d, inherited_ns=None):
    u'''
    Преобразование питоновского словаря в структурированное дерево
    XML-элементов с поддержкой выставления пространства имен.

    @param  node    XML-элемент, к которому будут прикреплены созданные
                    элементы.
    @type   node    lxml.Element

    @param  d   Преобразуемый словарь.
    @type   d   dict
    '''

    ns = d.get('__ns__', inherited_ns)

    node_factory = make_node_with_ns(ns) if ns else make_node

    for k, v in d.iteritems():
        if k == '__ns__':
            continue

        sub_node = node_factory(k)
        if isinstance(v, list):
            for el in v:
                el_node = make_node(k)
                dict_to_xmldoc(el_node, el, inherited_ns=ns)
                sub_node.append(el_node)
        elif isinstance(v, dict):
            dict_to_xmldoc(sub_node, v, inherited_ns=ns)
        else:
            sub_node.text = unicode(v)
        node.append(sub_node)


def xmldoc_to_dict(node, include_ns=True, ns_map=REVERSE_NS_MAP):
    u'''
    Преобразование XML-элемента и всех подчиненных ему в древовидную
    структуру внутри питоновского словаря. Пространства имен автоматически
    определяются по переданной карте соответствий, где ключами являются
    полноценные URL-ы к схемам, а значениями - кодовые имена пространств имен.

    Если среди дочерних элементов узла встречаются 2 или более с одинаковыми
    названиями, то в ключе будет храниться список из таких узлов.

    Обратно совместим с dict_to_xmldoc.

    @param  node    XML-элемент, который преобразуется в словарь.
    @type   node    lxml.Element

    @param  include_ns  Флаг сокрытия пространств имен элементов из конечного
                        результата.
    @type   include_ns  boolean

    @param  ns_map      Карта соответсвия пространств имен кодовым идентификаторам.
    @type   ns_map      dict вида {'http://schemas.xmlsoap.org/soap/envelope': 'SOAP-ENV'}
    '''

    def get_ns(n):
        if n.tag[0] == '{':
            ns, tag = n.tag[1:].split('}', 1)
            return ns
        return ''

    def get_tag(n):
        if n.tag[0] == '{':
            ns, tag = n.tag.split('}', 1)
            return tag
        return n.tag

    def flatten(d):
        res = {}

        for k, v in d.iteritems():
            if isinstance(v, list) and len(v) == 1:
                res[k] = v[0]
            else:
                res[k] = v
        return res

    result = {}

    ns = get_ns(node)
    if include_ns and ns:
        result['__ns__'] = REVERSE_NS_MAP.get(ns, ns)

    if len(node):
        for child in node:
            result.setdefault(get_tag(child), []).append(
                xmldoc_to_dict(child, include_ns=include_ns))
        return flatten(result)
    else:
        return node.text
