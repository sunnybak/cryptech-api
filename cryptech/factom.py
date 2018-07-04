VERSION = 'v1'
import os
import requests
import json
import base64

def _set_env(params):
    env_file = open('.env', 'r')
    f = env_file.read().split('\n')
    f = [x.split('=') for x in f]
    f = {x[0].replace('"','') : x[1].replace('"','') for x in f if len(x) == 2}
    for key in params.keys():
        f[key] = params[key]
    env_file.close()
    env_file = open('.env', 'w')
    for key in f.keys():
        env_file.write(key + '="' + f[key] + '"\n')
    env_file.close()

def _get_chain_id():
    try:
        return _get_env_param('FACTOM_CHAIN')
    except:
        return '8c043d7558276390b5767672bb6dbb6e5c339798e0698408740a408ccd54f1a7'

def _get_env_param(param):
    env_file = open('.env', 'r')
    f = env_file.read().split('\n')
    f = [x.split('=') for x in f]
    f = {x[0].replace('"', ''): x[1].replace('"', '') for x in f if len(x) == 2}
    env_file.close()
    return f[param]

try:
    API = _get_env_param('FACTOM_HOST')
    KEY = _get_env_param('FACTOM_KEY')
    CHAIN = _get_env_param('FACTOM_CHAIN')
    URL = API + '/' + VERSION
    # URL = API
except:
    API = 'https://api-2445581893456.production.gw.apicast.io'
    KEY = 'dfbc568f65205222a3743ff45afab285'
    CHAIN = '8c043d7558276390b5767672bb6dbb6e5c339798e0698408740a408ccd54f1a7'
    # URL = API
    URL = API + '/' + VERSION


HEADERS = {
   "Content-Type": "application/json",
   "user-key": KEY,
}

def _encode(data):
    if not data: 
        return ''

    return base64.b64encode(bytes(data, 'utf-8')).decode('utf8')

def _decode(data):
    if not data: 
        return ''
    return base64.b64decode(data)

def _decode_response(data):
    res = json.loads(data)
    if 'items' in res:
        for _item in res['items']:
            if 'external_ids' in _item:
                _item['external_ids'] = [ _decode(_id) for _id in _item['external_ids'] ]
    elif 'external_ids' in res:
            res['external_ids'] = [ _decode(_id) for _id in res['external_ids'] ]

    return res

def info():
    """ get api info """
    res = requests.request("GET", URL, headers=HEADERS)
    return _decode_response(res.content)

def chains():
    """ get api info """
    res = requests.request("GET", URL + '/chains', headers=HEADERS)
    return _decode_response(res.content)

def create_chain(external_ids=None, content=None, callback_url=None, callback_stages=None):
    """ """
    _ids = [ _encode(extid) for extid in external_ids ]
    payload = json.dumps({"external_ids": _ids, "content": _encode(content) })
    res = requests.request("POST", URL + '/chains', data=payload, headers=HEADERS)
    # _set_env({
    #     'FACTOM_CHAIN' : json.loads(res.content)['chain_id']
    # })
    return _decode_response(res.content)

def chain_search(external_ids=None):
    """ """
    _ids = [_encode(extid) for extid in external_ids ]
    payload = json.dumps({"external_ids": _ids})
    res = requests.request("POST", URL + '/chains/search', data=payload, headers=HEADERS)
    return _decode_response(res.content)

def chain_info(chain_id=CHAIN):
    """ """
    res = requests.request("GET", URL + '/chains/%s' % chain_id, headers=HEADERS)
    return _decode_response(res.content)

def chain_entries(chain_id=CHAIN):
    """ """
    res = requests.request("GET", URL + '/chains/%s/entries' % chain_id, headers=HEADERS)
    return _decode_response(res.content)

def chain_add_entry(chain_id=CHAIN, external_ids=None, content=None, callback_url=None, callback_stages=None):
    """ """
    _ids = [ _encode(extid) for extid in external_ids ]
    payload = json.dumps({"external_ids": _ids, "content": _encode(content) })
    print(payload)
    print(HEADERS)
    print(URL)
    res = requests.request("POST", URL + '/chains/%s/entries' % chain_id, data=payload, headers=HEADERS)
    return _decode_response(res.content)

def chain_entry_search(chain_id=CHAIN, external_ids=None):
    """ """
    _ids = [_encode(extid) for extid in external_ids ]
    payload = json.dumps({"external_ids": _ids})
    res = requests.request("POST", URL + '/chains/%s/entries/search' % chain_id, data=payload, headers=HEADERS)
    return _decode_response(res.content)

def chain_entry_first(chain_id=CHAIN):
    """ """
    res = requests.request("GET", URL + '/chains/%s/entries/first' % chain_id, headers=HEADERS)
    return _decode_response(res.content)

def chain_entry_last(chain_id=CHAIN):
    """ """
    res = requests.request("GET", URL + '/chains/%s/entries/last' % chain_id, headers=HEADERS)
    return _decode_response(res.content)

def chain_get_entry(chain_id=CHAIN, entry_hash=None):
    """ """
    res = requests.request("GET", URL + '/chains/%s/entries/%s' % (chain_id, entry_hash), headers=HEADERS)
    return _decode_response(res.content)




if __name__ == "__main__":

    # ext_ids = ['Timestamp', 'Public Key', 'Content Hash', 'Memo']
    # content = 'Signature'
    # print(create_chain(external_ids=ext_ids, content=content))
    # print(_get_chain_id())
    # entries = chain_entries(CHAIN)['items'][-4:]
    # API = _get_env_param('FACTOM_HOST')
    # for e in entries:
    #     print(chain_get_entry(CHAIN, e['entry_hash']))
    # print(API)
    # chain = create_chain(external_ids=ext_ids, content=content)
    # chain = chain_entries()
    content = '893e377b168fd1d6723523deafa11ce46474b458b2d9682b311164892f55244ab3f7d625f578f5b5222950fbe92f4377c8'
    ext_ids = ['timestamp', 'random_time', 'data1', 'foo', 'data2', 'ba']
    entry = chain_add_entry(external_ids=ext_ids, content=content)
    print(entry)


    """
    To see a World in a grain of sand,
    And Heaven in a Wildflower,
    Hold infinity in the palm of your hand,
    And eternity in an hour. 
    """