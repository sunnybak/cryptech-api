from django.http import HttpResponse
import time
from cryptech import factom
from django.shortcuts import render
from cryptech import nacl_sign

def index(request):
    # ext_ids = ['mediachain', str(int(time.time()))]
    # content ='Chain for copyrights, patents, and create asset protection'
    # chain_id = str(factom.create_chain(external_ids=ext_ids, content=content))
    # 'chain id = fb8d30c54e846b2bd7f1f5f68145c309be4c1885def89f05954dc89ce0878206'
    # 'entry hash = 3cbbae26e73cfeaa8d1566bef45b14a5814e018780e965d3a1366f7fa1431bf6'
    # print('chain id ' + chain_id)

    context = dict()

    fields = ['timestamp', 'msg', 'hmsg','rk', 'uk', 'sign', 'verified']
    params = process_request(request, fields)

    for f in fields:
        if f in params.keys():
            context[f] = params[f]

    params['timestamp'] = str(int(time.time()))
    if params['msg'] != '' and params['uk'] != '' and params['rk'] != '':
        params['hmsg'] = nacl_sign.hash_msg(params['msg'])
        print(params['msg'], params['rk'])
        s = nacl_sign.Sign(params['msg'], params['rk'])
        params['sign'] = s.sign
        params['verified'] = nacl_sign.verify(params['msg'], s, params['uk'])
    context['params'] = params
    print(factom.chain_add_entry(chain_id='fb8d30c54e846b2bd7f1f5f68145c309be4c1885def89f05954dc89ce0878206',
                           external_ids=[params['uk'], params['hmsg']],
                           content=params['sign']
                           ))
    return render(request, 'index.html', context)


def process_request(request, fields):
    query = dict()

    for f in fields:
        x = request.POST.get(f)
        if not x or len(x) == 0: x = ''
        query[f] = x
    return query

def keys(request):
    rk, uk = nacl_sign.generate_keys()
    return HttpResponse("Private Key: " + rk + "<br>Public   Key: " + uk)