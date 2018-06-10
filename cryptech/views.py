from django.http import HttpResponse
import time
from cryptech import factom
from django.shortcuts import render
from cryptech import nacl_sign
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def index(request):
    # ext_ids = ['mediachain', str(int(time.time()))]
    # content ='Chain for copyrights, patents, and create asset protection'
    # chain_id = str(factom.create_chain(external_ids=ext_ids, content=content))
    # 'chain id = fb8d30c54e846b2bd7f1f5f68145c309be4c1885def89f05954dc89ce0878206'
    # 'entry hash = 3cbbae26e73cfeaa8d1566bef45b14a5814e018780e965d3a1366f7fa1431bf6'
    # print('chain id ' + chain_id)
    print(request.POST)
    context = dict()

    fields = ['timestamp', 'msg', 'hmsg','private_key', 'public_key', 'sign', 'verified']
    params = process_request(request, fields)

    for f in fields:
        if f in params.keys():
            context[f] = params[f]

    params['timestamp'] = str(int(time.time()))
    if params['msg'] != '' and params['public_key'] != '' and params['private_key'] != '':
        params['hmsg'] = nacl_sign.hash_msg(params['msg'])
        print(params['msg'], params['private_key'])
        s = nacl_sign.Sign(params['msg'], params['private_key'])
        params['sign'] = s.sign
        params['verified'] = nacl_sign.verify(params['msg'], s, params['public_key'])
    context['params'] = params
    print(factom.chain_add_entry(chain_id='fb8d30c54e846b2bd7f1f5f68145c309be4c1885def89f05954dc89ce0878206',
                           external_ids=[params['public_key'], params['hmsg']],
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
    private_key, public_key = nacl_sign.generate_keys()
    return HttpResponse("Private Key: " + private_key + "<br>Public   Key: " + public_key)

# class UserViewSet(viewsets.ModelViewSet):
#     """
#     API endpoint that allows users to be viewed or edited.
#     """
#     queryset = User.objects.all().order_by('-date_joined')
#     serializer_class = UserSerializer
#
#
# class GroupViewSet(viewsets.ModelViewSet):
#     """
#     API endpoint that allows groups to be viewed or edited.
#     """
#     queryset = Group.objects.all()
#     serializer_class = GroupSerializer