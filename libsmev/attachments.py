#coding: utf-8

import base64
import os
import tempfile
import uuid
from zipfile import ZipFile
from StringIO import StringIO
from mimetypes import types_map as mime_types_map
from lxml import etree

from signer import get_file_digest, get_text_digest
from helpers import make_node, dict_to_xmldoc, parse_xml_string


class InvalidManifestException(Exception):
    pass


class InvalidFileDigestException(Exception):
    pass


def encode_directory(directory):
    u'''
    Преобразование содержимого папки и её структуры в вид, пригодный для присоединения
    к СМЭВ-сообщению согласно МР 2.4.4-2.5.6. 

    Результатом выполнения будет кортеж с уникальным GUID кодом (поле заголовка RequestCode)
    и закодированный в base64 ZIP-архив с манифестом, файлами директории и соответствующими
    файлами подписей.

    ZIP-архив формируется в памяти.

    @param  directory   Путь к папке, содержимое которой необходимо прикрепить.
    @type   directory   unicode

    @return GUID и закодированный в base64 ZIP-архив.
    @rtype  (unicode, unicode)    
    '''
    # Генерируем код запроса
    request_code = str(uuid.uuid4())
    i = 1

    in_memory_file = StringIO()
    zip_arc = ZipFile(in_memory_file, 'w')

    applied_documents_node = make_node('AppliedDocuments')
    for (path, subdirs, files) in os.walk(directory):
        for fn in files:            
            path_to_file = os.path.join(path, fn).replace('\\', '/').replace('\\\\', '/')
            relative_path = path_to_file[len(directory):].lstrip('/')
            dgst = get_file_digest(path_to_file)
            dot_pos = fn.find('.')

            applied_documents = [
                {
                    'URL': relative_path,
                    'Name': fn,
                    'DigestValue': dgst,
                    # Пытаемся определить MIME-тип файла, но если нет - бинарный файл.
                    'Type': mime_types_map.get(fn[dot_pos:], 'application/octet-stream'),
                    # TODO: выяснить правила генерации кода документа
                    'CodeDocument': u'0000',
                    'Number': i,
                },
                # Файл с подписью по PKCS/7
                {
                    'URL': u'%s%s' % (relative_path, '.sig'),
                    'Name': u'%s.sig' % fn,
                    'DigestValue': get_text_digest(dgst),
                    'Type': 'application/x-pkcs7-signature',
                    'CodeDocument': u'0000',
                    'Number': i + 1,
                }]

            i += 2

            for doc in applied_documents:
                app_doc_node = make_node('AppliedDocument')
                dict_to_xmldoc(app_doc_node, doc)
                applied_documents_node.append(app_doc_node)

            # Добавляем в ZIP-архив файл и его подпись
            zip_arc.write(path_to_file, arcname=relative_path)
            zip_arc.writestr('%s.sig' % relative_path, dgst)

    # Добавляем в ZIP-архив манифест и его подпись
    manifest_str = etree.tostring(applied_documents_node, pretty_print=True)
    zip_arc.writestr('req_%s.xml' % request_code, manifest_str.encode('utf-8'))
    zip_arc.writestr('req_%s.sig' % request_code, get_text_digest(manifest_str))

    zip_arc.close()
    in_memory_file.seek(0)

    # Преобразуем ZIP-архив в base64
    encoded = base64.b64encode(in_memory_file.read())
    in_memory_file.close()

    return request_code, encoded


def extract_directory(request_code, binary_data, destination=None,
                      verify=True, exclude_sigs=True):
    u'''
    Извлечение файлов из закодированного по МР архива вложений.
    '''

    # Распаковываем архив
    decoded = base64.b64decode(binary_data)
    in_memory_file = StringIO(decoded)
    zip_arc = ZipFile(in_memory_file, 'r')

    # Пробуем получить манифест из архива
    try:
        manifest_file = zip_arc.open('req_%s.xml' % request_code, 'r')
        manifest_str = manifest_file.read()
        manifest_file.close()
    except KeyError:
        raise InvalidManifestException(u'Manifest file "req_%s.xml" not found' % request_code)

    manifest = parse_xml_string(manifest_str)
    applied_documents = manifest.xpath('.//AppliedDocument')

    if not destination:
        destination = tempfile.mkdtemp()

    for doc in applied_documents:
        doc_info = dict([(n.tag, n.text) for n in doc])

        # Мы проверяем подписи по манифесту, поэтому по умолчанию
        # игнорируем файлы с ними и не распаковываем
        if doc_info['Name'].endswith('.sig') and exclude_sigs:
            continue

        zip_arc.extract(doc_info['URL'], destination)
        path_to_file = os.path.join(destination, doc_info['URL'])

        # Проверяем подписи файлов по данным из манифеста
        if verify:
            dgst = get_file_digest(path_to_file)
            if doc_info['DigestValue'] != dgst:
                raise InvalidFileDigestException((doc_info['URL'],
                                                 doc_info['DigestValue'],
                                                 dgst))

    zip_arc.close()
    in_memory_file.close()

    return manifest, destination
