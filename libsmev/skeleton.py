#coding: utf-8

import copy

from lxml import etree
from datetime import datetime

from helpers import make_node, extract_smev_parts, tag_single, dict_to_xmldoc
from namespaces import NS_MAP, make_node_with_ns


SMEV_VERSIONS = ['2.4.4', '2.5.5', '2.5.6']


# Исключение, выбрасываемое в случае отсутствия возможности
# конвертации между указанными версиями СМЭВ
class NoViableConversionError(Exception): pass


def convert_smev_request(envelope, from_ver='2.5.6', to_ver=None):
    u'''
    Экспериментальный механизм преобразования структуры сообщений согласно
    предписаний из различных версий методических рекомендаций.

    В случае отсутствия пути конвертации между указанными версиями выбрасывается
    исключение.

    Внимание: преобразование происходит прямо над переданным объектом,
    _не_ над копией.

    @param  envelope    Преобразуемое СМЭВ сообщение в виде дерева XML.
    @type   envelope    lxml.Element

    @param  from_ver    Версия переданного сообщения.
    @type   from_ver    unicode

    @param  from_ver    Версия, в которую необходимо преобразовать сообщение.
    @type   from_ver    unicode

    @return Преобразованное СМЭВ-сообщение.
    @rtype  lxml.Element
    '''

    smev_node = make_node_with_ns('smev')
    token, signature, msg_node, msg_data_node = extract_smev_parts(envelope)

    def convert_256_to_255(envelope):
        service_node = msg_data_node.xpath('//smev:Service', namespaces=NS_MAP)[0]
        name_node = msg_data_node.xpath('//smev:Service/smev:Mnemonic', namespaces=NS_MAP)
        if name_node:
            name = name_node[0].text
        servicename_node = smev_node('ServiceName')
        servicename_node.text = name
        service_node.getparent().remove(service_node)
        msg_node.insert(3,  servicename_node)

        return envelope

    mapping = {
        ('2.5.6', '2.5.5'): convert_256_to_255
    }

    if not (from_ver, to_ver) in mapping:
        raise NoViableConversionError("from %s to %s" % (from_ver, to_ver))

    return mapping[(from_ver, to_ver)](envelope)


def create_empty_context(version='2.5.6'):
    u'''
    Создание пустого контекста запроса, используемого для формирования 
    СМЭВ-сообщения. В зависимости от версии, набор необходимых полей может 
    меняться. По умолчанию формируется контекст для создания сообщения
    по версии 2.5.6 МР и проставляется флаг тестового взаимодействия.

    В случае запроса формирования контекста по неподдерживаемой нами
    версии МР - выьрасывается исключение.
    '''

    blanks = {
        '2.5.6': {
            'Sender': {
                'Code': u'',
                'Name': u''
            },
            'Originator': {
                'Code': u'',
                'Name': u''
            },
            'Recipient': {
                'Code': u'',
                'Name': u'Recipient'
            },
            'Service': {
                'Mnemonic': u'',
                'Version': u''
            },
            'Status': 'REQUEST',
            'TypeCode': 'GSRV',
            'TestMsg': True
        },
        '2.5.5': {
            'Sender': {
                'Code': u'',
                'Name': u''
            },
            'Originator': {
                'Code': u'',
                'Name': u''
            },
            'Recipient': {
                'Code': u'',
                'Name': u'Recipient'
            },
            'ServiceName': u'',
            'Status': 'REQUEST',
            'TypeCode': 'GSRV',
            'TestMsg': True
        }
    }

    assert version in blanks, 'Unknown SMEV version: %s' % version
    return blanks[version]


def extract_context_from_envelope(envelope):
    u'''
    Формирование контекста на основе данных из существующего сообщения СМЭВ.
    На данный момент поддерживается только обработка структуры сообщений по 
    МР версии 2.5.6.

    Если какой-либо из элементов содержит текст "true" или "false", то значение
    будет заменено на True или False соответственно.

    @param  envelope    Сообщение СМЭВ.
    @type   envelope    lxml.Element

    @return Словарь контекста.
    @rtype  dict

    '''

    smev_version = '2.5.6'

    ctx = create_empty_context(version=smev_version)
    ctx['Sender']['Code'] = tag_single(envelope, './/smev:Sender/smev:Code')
    ctx['Sender']['Name'] = tag_single(envelope, './/smev:Sender/smev:Name')

    ctx['Originator']['Code'] = tag_single(envelope, './/smev:Originator/smev:Code')
    ctx['Originator']['Name'] = tag_single(envelope, './/smev:Originator/smev:Name')

    ctx['Recipient']['Code'] = tag_single(envelope, './/smev:Recipient/smev:Code')
    ctx['Recipient']['Name'] = tag_single(envelope, './/smev:Recipient/smev:Name')

    ctx['Service']['Mnemonic'] = tag_single(envelope, './/smev:Service/smev:Mnemonic')
    ctx['Service']['Version'] = tag_single(envelope, './/smev:Service/smev:Version')

    ctx['Status'] = tag_single(envelope, './/smev:Status')
    ctx['TypeCode'] = tag_single(envelope, './/smev:TypeCode')
    ctx['TestMsg'] = tag_single(envelope, './/smev:TestMsg')

    def format_tag_contents(root):
        for k, v in root.iteritems():
            if isinstance(v, dict):
                root[k] = format_tag_contents(v)
            else:
                root[k] = getattr(v, 'text', v)
                if root[k] in ('true', 'false'):
                    root[k] = root[k] == 'true'
        return root

    return format_tag_contents(ctx)


def construct_smev_envelope(action_name, context, nsmap=None, version='2.5.6'):
    u'''
    Составления обертки СМЭВ-сообщения на основе переданного контекста и имени
    блока с данными.

    @param  action_name     Имя блока, содержащего данные сообщения.
    @type   action_name     unicode

    @param  context     Словарь с данными заголовка СМЭВ-сообщения.
    @type   context     dict

    @param  nsmap   Карта пространств имен XML-документа.
    @type   nsmap   dict

    @param  version     Версия методических рекомендаций, используемая при 
                        создании обертки сообщения.
    @type   version     unicode

    @return Созданное СМЭВ-сообщение.
    @rtype  lxml.Element
    '''

    required_fields = [
        'Sender',
        'Recipient',
        'TypeCode',
        'Status',
    ]
    type_codes = (
        'GSRV',  # Оказание государственных услуг
        'GFNC',  # Исполнение государственных функций
        'OTHR'   # Взаимодействие в иных целях
    )
    statuses = (
        'ACCEPT',  # Сообщение-квиток о приеме
        'CANCEL',  # Отзыв заявления
        'FAILURE',  # Технический сбой
        'INVALID',  # Ошибка при ФЛК (форматно-логический контроль)
        'NOTIFY',  # Уведомление об ошибке
        'PING',  # Запрос данных/результатов
        'PACKET',  # Пакетный режим обмена
        'PROCESS',  # В обработке
        'REJECT',  # Мотивированный отказ
        'REQUEST',
        'RESULT',
        'STATE'  # Возврат состояния
    )

    for name in required_fields:
        assert name in context, u'Required field "%s" missing from context!' % name
    assert context['TypeCode'] in type_codes, u'Type code should be one of %s' % (type_codes,)
    assert context['Status'] in statuses, u'Status code should be one of %s' % (statuses,)

    _ns_map = copy.copy(NS_MAP)
    if nsmap:
        _ns_map.update(nsmap)

    envelope = etree.Element("{%s}Envelope" % _ns_map['SOAP-ENV'], nsmap=_ns_map)
    header_node = etree.Element("{%s}Header" % _ns_map['SOAP-ENV'])
    body_node = etree.Element("{%s}Body" % _ns_map['SOAP-ENV'], attrib={"{%s}Id" % _ns_map['wsu']: "body"})

    message_node = etree.Element("{%s}Message" % _ns_map['smev'])

    # Данные о системе-инициаторе взаимодействия (Поставщике)
    sender_node = etree.Element("{%s}Sender" % _ns_map['smev'])
    sender_code_node = etree.Element("{%s}Code" % _ns_map['smev'])
    sender_name_node = etree.Element("{%s}Name" % _ns_map['smev'])
    sender_code_node.text = context['Sender']['Code']
    sender_name_node.text = context['Sender']['Name']

    # Данные о системе-получателе сообщения (Потребителе)
    recipient_node = etree.Element("{%s}Recipient" % _ns_map['smev'])
    recipient_code_node = etree.Element("{%s}Code" % _ns_map['smev'])
    recipient_name_node = etree.Element("{%s}Name" % _ns_map['smev'])
    recipient_code_node.text = context['Recipient']['Code']
    recipient_name_node.text = context['Recipient']['Name']

    # Данные о системе, инициировавшей цепочку из нескольких
    # запросов-ответов, объединенных единым процессом в рамках
    # взаимодействия
    originator_node = etree.Element("{%s}Originator" % _ns_map['smev'])
    originator_code_node = etree.Element("{%s}Code" % _ns_map['smev'])
    originator_name_node = etree.Element("{%s}Name" % _ns_map['smev'])
    originator_code_node.text = context['Originator']['Code']
    originator_name_node.text = context['Originator']['Name']

    # Данные о вызванном сервисе
    if version == '2.5.6':
        service_node = etree.Element("{%s}Service" % _ns_map['smev'])
        service_mnemonic_node = etree.Element("{%s}Mnemonic" % _ns_map['smev'])
        service_version_node = etree.Element("{%s}Version" % _ns_map['smev'])
        service_mnemonic_node.text = context['Service']['Mnemonic']
        service_version_node.text = context['Service']['Version']
        
        service_node.extend([
            service_mnemonic_node,
            service_version_node])
    else:
        service_node = etree.Element("{%s}ServiceName" % _ns_map['smev'])
        service_node.text = context['ServiceName']

    # Тип сообщения по классификатору типов сообщений,  передаваемых через
    # узел СМЭВ (приложение 2 метод. рекомендаций )
    typecode_node = etree.Element("{%s}TypeCode" % _ns_map['smev'])
    typecode_node.text = context.get('TypeCode', '')

    # Сведения о статусе электронного сообщения (см. приложение 2)
    status_node = etree.Element("{%s}Status" % _ns_map['smev'])
    status_node.text = context.get('Status', '')

    # Дата и время создания сообщения в формате UTC
    # 'yyyy-MM-dd'T'HH:mm:ss.SSSZ’
    utc_now = datetime.strftime(datetime.utcnow(), "%Y-%m-%dT%H:%M:%S.%f")[:-2]
    date_node = etree.Element("{%s}Date" % _ns_map['smev'])
    date_node.text = context.get('Date', utc_now)

    # Признак принадлежности электронного сообщения различным категориям
    # взаимодействия, возникающим при межведомственном обмене (приложение 2)
    # По умолчанию выставляется "Неопределенная категория"
    exchangetype_node = etree.Element("{%s}ExchangeType" % _ns_map['smev'])
    exchangetype_node.text = context.get('Exchangetype', '0')

    # Признак тестового режима
    testmsg_node = None
    if context.get('TestMsg', True):
        testmsg_node = etree.Element("{%s}TestMsg" % _ns_map['smev'])
        testmsg_node.text = 'true'

    messagedata_node = etree.Element("{%s}MessageData" % _ns_map['smev'])
    appdata_node = etree.Element("{%s}AppData" % _ns_map['smev'], attrib={"{%s}Id" % _ns_map['wsu']: "AppData"})
    app_document_node = etree.Element("{%s}AppDocument" % _ns_map['smev'])
    binarydata_node = etree.Element("{%s}BinaryData" % _ns_map['smev'])
    requestcode_node = etree.Element("{%s}RequestCode" % _ns_map['smev'])

    app_document = context.get('AppDocument')
    if app_document is not None:
        if isinstance(app_document, dict):
            requestcode_node.text = app_document['RequestCode'] or ''
            binarydata_node.text = app_document['BinaryData'] or ''
        else:
            app_document_node.text = app_document or ''

    app_document_node.extend([
        requestcode_node,
        binarydata_node])

    messagedata_node.extend([
        appdata_node,
        app_document_node])

    sender_node.extend([
        sender_code_node,
        sender_name_node])

    recipient_node.extend([
        recipient_code_node,
        recipient_name_node])

    originator_node.extend([
        originator_code_node,
        originator_name_node])

    message_node.extend([
        sender_node,
        recipient_node,
        originator_node,
        service_node,
        typecode_node,
        status_node,
        date_node,
        exchangetype_node,
    ])
    if testmsg_node is not None:
        message_node.append(testmsg_node)

    if 'CaseNumber' in context:
        # Номер дела в ИС отправителя
        casenumber_node = etree.Element("{%s}CaseNumber" % _ns_map['smev'])
        casenumber_node.text = context['CaseNumber']
        message_node.append(casenumber_node)

    own_section_node = etree.Element("{%s}%s" % (_ns_map['inf'], action_name), nsmap=_ns_map)
    own_section_node.extend([
        message_node,
        messagedata_node])

    body_node.append(
        own_section_node)
    envelope.extend([
        header_node,
        body_node])

    return envelope


def construct_error_reply(original_req, err_code, msg, custom_status=None):
    u'''
    Создание ответ на СМЭВ-сообщение, который будет содержать в себе 
    код и сообщение об ошибке.

    @param  original_req    СМЭВ-сообщение, на которое формируется ответ.
    @type   original_req    lxml.Element

    @param  err_code    Код сообщения об ошибке.
    @type   err_code    unicode

    @param  msg    Текст сообщения об ошибке.
    @type   msg    unicode

    @param  custom_status    Статус в заголовке СМЭВ-сообщения.
    @type   custom_status    unicode

    @return Ответное сообщение об ошибке.
    @rtype  lxml.Element
    '''

    reply_ctx = extract_context_from_envelope(original_req)

    recipient_code = reply_ctx['Recipient']['Code']
    recipient_name = reply_ctx['Recipient']['Name']

    reply_ctx['Recipient']['Code'] = reply_ctx['Sender']['Code']
    reply_ctx['Recipient']['Name'] = reply_ctx['Sender']['Name']

    reply_ctx['Sender']['Code'] = recipient_code
    reply_ctx['Sender']['Name'] = recipient_name

    reply_ctx['Status'] = custom_status or 'REJECT'

    reply_req = construct_smev_envelope('Error', reply_ctx)
    appdata_node = tag_single(reply_req, './/smev:AppData')

    dict_to_xmldoc(appdata_node, {
                   '__ns__': 'inf', 
                   'Error': dict(errorCode=err_code, errorMessage=msg)})

    return reply_req
