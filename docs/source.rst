===============
Модули и классы
===============

helpers - вспомогательные функции
=====================================

.. automodule:: libsmev.helpers
.. autofunction:: tags
.. autofunction:: tag_single
.. autofunction:: run_cmd
.. autofunction:: parse_xml_string
.. autofunction:: _from_soap
.. autofunction:: extract_smev_parts
.. autofunction:: dict_to_xmldoc
.. autofunction:: xmldoc_to_dict

namespaces - пространства имен XML
==================================

.. automodule:: libsmev.namespaces
.. autofunction:: make_node_with_ns

attachments - работа с вложениями
=================================

.. automodule:: libsmev.attachments
.. autofunction:: encode_directory
.. autofunction:: extract_directory

signer - работа с ЭП
====================

.. automodule:: libsmev.signer
.. autofunction:: load_cert_from_pem
.. autofunction:: load_pubkey_from_pem
.. autofunction:: c14n_tags
.. autofunction:: get_text_signature
.. autofunction:: get_text_digest
.. autofunction:: get_file_digest
.. autofunction:: construct_wsse_header
.. autofunction:: sign_document
.. autofunction:: verify_gost94_signature
.. autofunction:: verify_envelope_signature

skeleton - создание скелета сообщения СМЭВ
==========================================

.. automodule:: libsmev.skeleton
.. autofunction:: convert_smev_request
.. autofunction:: create_empty_context
.. autofunction:: extract_context_from_envelope
.. autofunction:: construct_smev_envelope
.. autofunction:: construct_error_reply
