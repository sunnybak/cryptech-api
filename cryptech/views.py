from django.http import HttpResponse
import hashlib
from cryptech import factom
from cryptech.nacl_sign import *
from django.views.decorators.csrf import csrf_exempt
from django.core.files.storage import FileSystemStorage
from django.views.generic import View
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
import requests, json


def index(request):
    return HttpResponse('best home page')


# @login_required
@csrf_exempt
def step_one(request):
    # ext_ids = ['mediachain', str(int(time.time()))]
    # content ='Chain for copyrights, patents, and create asset protection'
    # chain_id = str(factom.create_chain(external_ids=ext_ids, content=content))
    # 'chain id = fb8d30c54e846b2bd7f1f5f68145c309be4c1885def89f05954dc89ce0878206'
    # 'entry hash = 3cbbae26e73cfeaa8d1566bef45b14a5814e018780e965d3a1366f7fa1431bf6'

    context = dict()
    content_hash = request.POST.get('content_hash') or ''
    myfile = request.FILES.get('myfile', None)
    file = request.method == "POST" and myfile is not None and myfile != ''
    if content_hash == '':
        if file:
            fs = FileSystemStorage()
            filename = fs.save(myfile.name, myfile)
            context['content_hash'] = file_hash(filename)
        else:
            text = request.POST.get('text_content')
            if text is not None and text != '':
                context['text_content'] = text
                context['content_hash'] = hash_msg(text)
            else:
                context['content_hash'] = ''
        content_hash = context['content_hash']
    else:
        context['content_hash'] = content_hash

    private_key, public_key = generate_keys()
    context['public_key'] = public_key
    context['private_key'] = private_key
    # context['raw_nonce'] = request.user.username + User.objects.get(username=request.user.username).email
    context['raw_nonce'] = request.POST.get('raw_nonce') or ''
    # context['nonce'] = str(nonce(hash_msg(request.user.username + User.objects.get(username=request.user.username).email)),'utf-8')
    if context['raw_nonce'] == '':
        context['nonce'] = ''
    else:
        context['nonce'] = create_nonce(seed=context['raw_nonce'])
    return render(request, 'upload.html', context)


# @login_required
@csrf_exempt
def step_two(request):
    context = dict()
    fields_user = ['private_key', 'public_key']
    fields_content = ['chain_id', 'timestamp', 'content_hash', 'signature', 'verified']
    user_info = process_request(request, fields_user)
    content_info = process_request(request, fields_content)

    content_info['timestamp'] = str(int(time.time()))
    content_info['chain_id'] = 'fb8d30c54e846b2bd7f1f5f68145c309be4c1885def89f05954dc89ce0878206'
    # n = nonce(hash_msg(request.user.username + User.objects.get(username=request.user.username).email))
    n = request.POST.get('nonce')
    s = Sign(content_info['content_hash'], user_info['private_key'], nonce=create_nonce(nonce=n))
    content_info['signature'] = s.sign
    content_info['verified'] = str(verify(content_info['content_hash'], s, user_info['public_key']))
    context['content_info'] = content_info
    context['user_info'] = user_info
    entry_hash = factom.chain_add_entry(chain_id='fb8d30c54e846b2bd7f1f5f68145c309be4c1885def89f05954dc89ce0878206',
                                        external_ids=[user_info['public_key'], content_info['content_hash'],
                                                      content_info['timestamp']],
                                        content=content_info['signature']
                                        )['entry_hash'] or None
    print(entry_hash)
    if entry_hash:
        content_info['entry_hash'] = entry_hash
        entry_object = factom.chain_get_entry(
            chain_id='fb8d30c54e846b2bd7f1f5f68145c309be4c1885def89f05954dc89ce0878206', entry_hash=entry_hash)
        if entry_object is not None:
            factom_info = entry_object
            factom_info['content'] = str(factom._decode(factom_info['content']), 'utf-8')
            factom_info['links'] = factom_info['links']['chain']
            factom_info['external_ids'] = [str(x, 'utf-8') for x in factom_info['external_ids']]
            context['factom_info'] = factom_info
    context['signature'] = s.sign
    context['qr'] = shorten('http://192.168.0.5:8000/check?'
                                   + 'u='+user_info['public_key']
                                   +'&h='+content_info['content_hash']
                                   +'&s='+s.sign)
    return render(request, 'origin.html', context)


# @login_required
@csrf_exempt
def step_three(request):
    context = dict()
    dataset = []

    class data(object):
        def __init__(self, links, entry_hash):
            self.links = links
            self.entry_hash = entry_hash

    fce = factom.chain_entries('fb8d30c54e846b2bd7f1f5f68145c309be4c1885def89f05954dc89ce0878206')['items']
    for entry in fce:
        dataset.append(data(entry['links']['entry'], entry['entry_hash']))

    context['dataset'] = dataset

    return render(request, 'explore.html', context)


def process_request(request, fields):
    query = dict()
    for f in fields:
        x = request.POST.get(f)
        if not x or len(x) == 0: x = ''
        query[f] = x
    return query


def check(request):
    s = request.GET.get('s')
    u = request.GET.get('u')
    h = request.GET.get('h')
    v = verify(h, Sign(sign=s), u)
    print(request.GET) or None
    print(request.POST) or None
    if v == True:
        return render(request, 'check.html',{'status':'Success!','desc':'Your signature is valid!','color':'lightgreen'})
    return render(request, 'check.html',{'status':'Rejected','desc':'Your signature is not valid.','color':'lightcoral'})


def keys(request=None):
    private_key, public_key = generate_keys()
    return HttpResponse("Private Key: " + private_key + "<br>Public   Key: " + public_key)

@csrf_exempt
def test(request):
    myfile = request.FILES.get('webcam', None)
    if request.method == "POST" and myfile is not None and myfile != '':
        fs = FileSystemStorage()
        filename = fs.save('cryptech/static/webcam.jpg', myfile)
    requests.request('GET', 'http://api.qrserver.com/v1/read-qr-code/?fileurl=cryptech-api.herokuapp.com/static/webcam.jpg')
    return render(request, 'test.html', {})

def shorten(url):
    key = '7250c6a4b2c45454e63558ce82f214aa0ffb64f8'
    guid = 'Bi6c31plwrT'
    payload = json.dumps({
        "long_url": url,
        "group_guid": guid
    })
    HEADERS = {'Content-Type': 'application/json', 'Authorization': key, 'Host': 'api-ssl.Bitly.com'}
    res = requests.request(method='POST', url='https://api-ssl.Bitly.com/v4/shorten', data=payload, headers=HEADERS)
    return(json.loads(res.content)['link'])


def file_hash(file_name):
    BLOCKSIZE = 65536
    hasher = hashlib.sha1()
    with open(file_name, 'rb') as afile:
        buf = afile.read(BLOCKSIZE)
        while len(buf) > 0:
            hasher.update(buf)
            buf = afile.read(BLOCKSIZE)
    return hasher.hexdigest()


@csrf_exempt
def verf(request):
    context = dict()
    content_hash = request.POST.get('content_hash') or ''
    print(content_hash)
    myfile = request.FILES.get('myfile', None)
    file = request.method == "POST" and myfile is not None and myfile != ''
    if content_hash == '':
        if file:
            fs = FileSystemStorage()
            filename = fs.save(myfile.name, myfile)
            context['content_hash'] = file_hash(filename)
        else:
            text = request.POST.get('text_content')
            if text is not None and text != '':
                context['text_content'] = text
                context['content_hash'] = hash_msg(text)
            else:
                context['content_hash'] = ''
        content_hash = context['content_hash']
    else:
        context['content_hash'] = content_hash

    public_key = request.POST.get('public_key') or ''
    signature = request.POST.get('signature') or ''

    context['public_key'] = public_key
    context['signature'] = signature
    context['valid'] = str(verify(content_hash, Sign(sign=signature), public_key))
    context['qr'] = shorten('http://192.168.0.5:8000/check?'
                                   + 'u='+public_key
                                   +'&h='+content_hash
                                   +'&s='+signature)
    return render(request, 'verify.html', context)


class UserForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ['username', 'email', 'password']


class UserFormView(View):
    form_class = UserForm
    template_name = 'registration_form.html'

    # blank form
    def get(self, request):
        form = self.form_class(None)
        return render(request, self.template_name, {'form': form})

    # process the data
    def post(self, request):
        form = self.form_class(request.POST)

        if form.is_valid():
            # saving temporarily
            user = form.save(commit=False)

            # cleaning the fields
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']

            user.set_password(password)
            user.save()

            # returns User objects if correct credentials
            user = authenticate(username=username, password=password)

            if user is not None:

                if user.is_active:
                    login(request, user)

                    return redirect('upload')


def login_user(request):
    if request.method == "POST":
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username=username, password=password)
        if user is not None:
            if user.is_active:
                login(request, user)
                return step_one(request)

            else:
                return render(request, 'login.html', {'error_message': 'Your account has been disabled'})
        else:
            return render(request, 'login.html', {'error_message': 'Invalid login'})
    return render(request, 'login.html')


def logout_user(request):
    logout(request)
    form = UserForm(request.POST or None)
    context = {
        "form": form,
    }
    return render(request, 'login.html', context)
