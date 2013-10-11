#coding: utf-8

import base64
import os
from tempfile import NamedTemporaryFile

from lxml import etree

from helpers import run_cmd, tags, _from_soap
from skeleton import make_node_with_ns
from namespaces import NS_MAP


class SignerError(Exception):
    pass


def _format_pem(data):
    u'''
    Форматирование текстового представления сертификата
    на линии по 64 символа и заключение его в теги для
    передачи OpenSSL.

    @param  data   Текст сертификата, закодированный в base64.
    @type   unicode

    @returns PEM, содержащий отформатированный сертификат.
    @rtype    unicode
    '''

    result = []

    data = data.replace('\n', '')
    brackets = range(0, len(data) + 64, 64)

    result.append('-----BEGIN CERTIFICATE-----')
    for start, end in zip(brackets, brackets[1:]):
        result.append(data[start:end])
    result.append('-----END CERTIFICATE-----')

    return '\n'.join(result)


def load_cert_from_pem(data):
    u'''
    Загрузка данных публичного сертификата из PEM-контейнера
    (RFC 1421-1424).

    @param  pem_filename    Имя файла PEM-контейнера.
    @type   pem_filename    unicode

    @return base64-представление данных сертификата.
    @rtype  unicode
    '''

    assert data, 'No PEM provided!'

    data = data.replace('\r', '').replace('\n', '')
    cert_start = data.find('-----BEGIN CERTIFICATE-----')
    cert_end = data.find('-----END CERTIFICATE-----')

    # Не найдены маркеры начала и окончания сертификата в PEM
    if not (cert_start > -1 and cert_end > -1):
        raise SignerError('PEM has no certificate markers (BEGIN, END)!')

    return data[cert_start + 27:cert_end]


def load_pubkey_from_pem(data):
    u'''
    Загрузка данных публичного ключа из PEM-контейнера
    (RFC 1421-1424).

    @param  pem_filename    Имя файла PEM-контейнера.
    @type   pem_filename    unicode

    @return base64-представление данных публичного ключа.
    @rtype  unicode
    '''

    assert data, 'No PEM provided!'

    load_key_cmd = ['openssl', 'x509', '-inform', 'PEM', '-pubkey', '-noout']

    out, err = run_cmd(load_key_cmd, input=data)

    if err:
        raise SignerError(unicode(err))

    return out


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


def get_file_digest(fn):
    u'''
    Получение текстового представления хэш-кода переданного файла
    по ГОСТ Р 34.11-94.

    @param  fn    Путь к файлу, хэш-код которого необходимо получить.
    @type   fn    unicode

    @return Закодированный в base64 хэш-код текста.
    @rtype  unicode
    '''
    openssl_sign_cmd = ['openssl', 'dgst', '-binary', '-md_gost94', fn]

    out, err = run_cmd(openssl_sign_cmd)
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


def sign_document(doc, priv_key_fn, priv_key_pass, cert_file=None):
    u'''
    Подписание сообщения без вложения согласно ГОСТ Р 34.10-2001.

    @param  doc     Подписываемый XML-документ, содержащий себе в себе СМЭВ-сообщение.
    @type   doc     lxml.Element

    @param  priv_key_fn     Путь к файлу с частному ключу подписи.
    @type   priv_key_fn     unicode

    @param  priv_key_pass   Пароль к частному ключу подписи.
    @type   priv_key_pass   unicode

    @param cert_file    Путь к файлу с сертификатом.
    @type cert_file     unicode

    @return Подписанный XML-документ.
    @rtype  lxml.Element
    '''
    header_node = tags(doc, '/SOAP-ENV:Envelope/SOAP-ENV:Header')
    security_node = tags(doc, '/SOAP-ENV:Envelope/SOAP-ENV:Header/wsse:Security')

    if not security_node:
        if cert_file is not None:
            with open(cert_file, 'rb') as cert_file_fh:
                cert_data = load_cert_from_pem(cert_file_fh.read())
        else:            
            with open(priv_key_fn, 'rb') as priv_key_file:
                cert_data = load_cert_from_pem(priv_key_file.read())
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


def verify_gost94_signature(text, public_key, signature_value):
    u'''
    Проверка корректности ЭП переданного текста по ГОСТ Р 34.11-94.

    @param  text    Текст, подпись которого проверяется.
    @type   text    unicode

    @param  public_key  Публичный ключ, которым подписывался текст.
    @type   public_key  unicode

    @param  signature_value Подпись.
    @type   signature_value unicode

    @return Флаг корректности ЭП текста.
    @type   boolean
    '''

    # Так как OpenSSL не умеет считывать значения подписи и проверяемый
    # текст со стандартного ввода, мы вынуждены использовать временные файлы.
    # После записи они закрываются, т.к. Windows не позволяет считывать
    # открытые файлы.
    tmp_public_key = NamedTemporaryFile(delete=False)
    tmp_public_key.file.write(public_key)
    tmp_public_key.file.close()

    tmp_signature_value = NamedTemporaryFile(delete=False)
    tmp_signature_value.file.write(base64.b64decode(signature_value))
    tmp_signature_value.file.close()

    openssl_sign_cmd = ['openssl', 'dgst', '-md_gost94', '-verify',
                        tmp_public_key.name, '-signature',
                        tmp_signature_value.name]

    out, err = run_cmd(openssl_sign_cmd, input=text)

    if err:
        raise SignerError(unicode(err))

    # Убираем за собой
    os.remove(tmp_signature_value.name)
    os.remove(tmp_public_key.name)

    return out.strip() == "Verified OK"


def verify_envelope_signature(envelope):
    u'''
    Проверка подписи SOAP-запроса по ГОСТ Р 34.11-94.

    @param envelope     Подписанный XML-документ.
    @type  envelope     lxml.Element

    @return Флаг корректности подписи документа.
    @rtype  boolean
    '''

    header, body = _from_soap(envelope)

    if body is None:
        raise SignerError("'Body' tag not found in SOAP envelope!'")

    digest_value = tags(envelope, ".//ds:DigestValue")
    if not digest_value:
        raise SignerError("'DigestValue' tag is not found")

    binary_security_token = tags(envelope, './/wsse:BinarySecurityToken')
    if not binary_security_token:
        raise SignerError("'BinarySecurityToken' tag is not found")

    signed_info = tags(envelope, './/ds:SignedInfo')
    if not signed_info:
        raise SignerError("`SignedInfo' tag is not found")

    signature_value = tags(envelope, ".//ds:SignatureValue")
    if not signed_info:
        raise SignerError("`SignatureValue' tag is not found")

    if digest_value[0].text != get_text_digest(c14n_tags(body)):
        return False

    # Извлекаем публичный ключ из заголовка WS-Security
    tmp_cert = _format_pem(binary_security_token[0].text)
    public_key = load_pubkey_from_pem(tmp_cert)

    return verify_gost94_signature(c14n_tags(signed_info[0]), public_key,
                                   signature_value[0].text)
