#coding: utf-8

import base64

from lxml import etree

from helpers import run_cmd, tags
from skeleton import make_node_with_ns
from namespaces import NS_MAP


def load_cert_from_pem(pem_filename):
    u'''
    Загрузка данных публичного сертификата из PEM-контейнера
    (RFC 1421-1424).

    @param  pem_filename    Имя файла PEM-контейнера.
    @type   pem_filename    unicode

    @return base64-представление данных сертификата.
    @rtype  unicode
    '''

    data = None

    with open(pem_filename, 'rb') as fp:
        data = fp.read()

    data = data.replace('\r', '').replace('\n', '')
    cert_start = data.find('-----BEGIN CERTIFICATE-----')
    cert_end = data.find('-----END CERTIFICATE-----')

    # Не найдены маркеры начала и окончания сертификата в PEM
    if not (cert_start > -1 and cert_end > -1):
        raise ValueError('PEM has no certificate markers (BEGIN, END)!')

    return data[cert_start + 27:cert_end]


def c14n_tags(tag):
    u'''
    Исключительная каноникализация (см. http://www.w3.org/TR/xml-exc-c14n/) 
    дерева XML-элементов.

    @param  tag     Корень дерева XML-элементов.
    @type   tag     lxml.Element

    @return Строковое представление каноникализированной формы XML-дерева.
    @rtype  unicode
    '''

    return etree.tostring(tag, method='c14n', exclusive=True, with_comments=False)


def get_text_signature(text, private_key_fn, private_key_pass):
    u'''
    Получение ЭП указанного текста через вызов внешнего экземпляра OpenSSL,
    с использованием частного ключа ОИВ.

    @param  text    Подписываемый текст.
    @type   text    unicode

    @param  private_key_fn  Путь к PEM-файлу, содержащему частный ключ.
    @param  private_key_fn  unicode

    @param  private_key_pass    Пароль к частному ключу.
    @type   private_key_pass    unicode

    @return Закодированная в base64 ЭП текста.
    @rtype  unicode
    '''
    openssl_sign_cmd = [
        'openssl', 'dgst', '-sign', private_key_fn, '-binary',
        '-md_gost94', '-passin', 'stdin']

    out, err = run_cmd(openssl_sign_cmd, input=private_key_pass + '\n' + text)
    if err:
        raise ValueError(u'OpenSSL error: %s' % err)

    return base64.b64encode(out)


def get_text_digest(text):
    u'''
    Получение текстового представления хэш-кода переданного текста
    по ГОСТ Р 34.11-94.

    @param  text    Текст, хэш-код которого необходимо получить.
    @type   text    unicode

    @return Закодированный в base64 хэш-код текста.
    @rtype  unicode
    '''
    openssl_sign_cmd = ['openssl', 'dgst', '-binary', '-md_gost94']

    out, err = run_cmd(openssl_sign_cmd, input=text)
    if err:
        raise ValueError(u'OpenSSL error: %s' % err)

    return base64.b64encode(out)


def construct_wsse_header(digest=None, signature=None, certificate=None):
    u'''
    Формирование в виде дерева XML-элементов заголовка WS-Security.

    @param  digest  Хэш-код подписи элементов сообщения.
    @type   digest  unicode

    @param  signature ЭП сообщения.
    @type   signature unicode

    @param  certificate     Открытый ключ сообщения.
    @type   certificate     unicode

    @return WS-Security заголовок.
    @rtype  lxml.Element
    '''
    ds_node = make_node_with_ns('ds')
    wsse_node = make_node_with_ns('wsse')

    security_node = wsse_node('Security')
    security_node.attrib['{%s}actor' % NS_MAP['SOAP-ENV']] = 'http://smev.gosuslugi.ru/actors/smev'

    binary_sec_token_node = wsse_node('BinarySecurityToken')

    signature_node = ds_node('Signature')
    signed_info_node = ds_node('SignedInfo')
    c14n_method_node = ds_node('CanonicalizationMethod')
    signature_method_node = ds_node('SignatureMethod')
    reference_node = ds_node('Reference')
    transforms_node = ds_node('Transforms')
    transform1_node = ds_node('Transform')
    transform2_node = ds_node('Transform')
    key_info_node = ds_node('KeyInfo')
    digest_method_node = ds_node('DigestMethod')
    digest_value_node = ds_node('DigestValue')
    signature_value_node = ds_node('SignatureValue')

    sec_token_reference_node = wsse_node('SecurityTokenReference')
    token_reference_node = wsse_node('Reference')

    # FIX: Они вообще здесь нужны? Метод. рекомендации сами себе противоречат :-\
    #x509_data_node = ds_node('X509Data')
    #x509_cert_node = ds_node('X509Certificate')

    binary_sec_token_node.text = certificate

    # Установка предопределенных значений согласно метод. рекомендациям v. 2.5.6
    c14n_method_node.attrib['Algorithm'] = 'http://www.w3.org/2001/10/xml-exc-c14n#'
    transform2_node.attrib['Algorithm'] = 'http://www.w3.org/2001/10/xml-exc-c14n#'
    transform1_node.attrib['Algorithm'] = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature'
    digest_method_node.attrib['Algorithm'] = 'http://www.w3.org/2001/04/xmldsig-more#gostr3411'
    signature_method_node.attrib['Algorithm'] = 'http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411'

    reference_node.attrib['URI'] = '#body'
    binary_sec_token_node.attrib['EncodingType'] = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary'
    binary_sec_token_node.attrib['ValueType'] = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3'
    binary_sec_token_node.attrib['{%s}Id' % NS_MAP['wsu']] = 'CertId'
    token_reference_node.attrib['URI'] = '#CertId'
    token_reference_node.attrib['ValueType'] = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3'

    sec_token_reference_node.append(token_reference_node)

    key_info_node.extend([
        sec_token_reference_node])
        #x509_data_node,
        #x509_cert_node])

    transforms_node.extend([
        transform1_node,
        transform2_node])

    reference_node.extend([
        transforms_node,
        digest_method_node,
        digest_value_node])

    signed_info_node.extend([
        c14n_method_node,
        signature_method_node,
        reference_node])

    signature_node.extend([
        signed_info_node,
        signature_value_node,
        key_info_node])

    security_node.extend([
        binary_sec_token_node,
        signature_node])

    return security_node


def sign_document(doc, priv_key_fn, priv_key_pass):
    u'''
    Подписание сообщения без вложения согласно ГОСТ Р 34.10-2001.

    @param  doc     Подписываемый XML-документ, содержащий себе в себе СМЭВ-сообщение.
    @type   doc     lxml.Element

    @param  priv_key_fn     Путь к файлу с частному ключу подписи.
    @type   priv_key_fn     unicode

    @param  priv_key_pass   Пароль к частному ключу подписи.
    @type   priv_key_pass   unicode

    @return Подписанный XML-документ.
    @rtype  lxml.Element
    '''
    header_node = tags(doc, '/SOAP-ENV:Envelope/SOAP-ENV:Header')
    security_node = tags(doc, '/SOAP-ENV:Envelope/SOAP-ENV:Header/wsse:Security')

    if not security_node:
        cert_data = load_cert_from_pem(priv_key_fn)
        wsse_header_node = construct_wsse_header(certificate=cert_data)
        header_node[0].append(wsse_header_node)

    body_node = tags(doc, '/SOAP-ENV:Envelope/SOAP-ENV:Body')
    c14n_body = c14n_tags(body_node[0])
    digest_value = get_text_digest(c14n_body)

    digest_val_node = tags(doc, '/SOAP-ENV:Envelope/SOAP-ENV:Header/wsse:Security/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue')
    digest_val_node[0].text = digest_value

    sign_info_node = tags(doc, '/SOAP-ENV:Envelope/SOAP-ENV:Header/wsse:Security/ds:Signature/ds:SignedInfo')
    c14n_sign_info = c14n_tags(sign_info_node[0])
    signature_value = get_text_signature(c14n_sign_info, priv_key_fn, priv_key_pass)

    sign_val_node = tags(doc, '/SOAP-ENV:Envelope/SOAP-ENV:Header/wsse:Security/ds:Signature/ds:SignatureValue')
    sign_val_node[0].text = signature_value

    return doc
