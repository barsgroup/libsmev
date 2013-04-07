#coding: utf-8

import json
import requests


def portal_check_flk(message, version='2.5.6'):
    versions = {
        '2.4.4': 'rev111111',
        '2.4.5': 'rev111111_2.4.5',
        '2.5.5': 'rev120315',
        '2.5.6': 'rev120315_2.5.6'
    }

    assert version in versions, u'Unknown method version: %s' % version
    assert message, u'Message not specified!'

    req = {
        'message': message,
        'configId': versions[version]
    }

    r = requests.post('http://smev.gosuslugi.ru/portal/api/services/flcApply',
                      data=json.dumps(req),
                      proxies=dict(http=''),
                      headers={'content-type': 'application/json'})
    r.raise_for_status()

    reply = json.loads(r.content)['error']
    return reply['errorCode'] == 0, (reply['errorMessage'] or '').split('\n')


def portal_check_signature(message):
    assert message, u'Message not specified!'

    req = {
        'message': message,
        'actor': 'http://smev.gosuslugi.ru/actors/smev'
    }

    r = requests.post('http://smev.gosuslugi.ru/portal/api/services/verifySignature',
                      data=json.dumps(req),
                      proxies=dict(http=''),
                      headers={'content-type': 'application/json'})
    r.raise_for_status()

    reply = json.loads(r.content)['error']
    return reply['errorCode'] == 0, (reply['errorMessage'] or '').split('\n')
