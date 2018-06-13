from django.http import HttpResponse
import hashlib
from cryptech import factom
import cryptech.crypt as crypt
from django.views.decorators.csrf import csrf_exempt
from django.core.files.storage import FileSystemStorage
from django.views.generic import View
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
import requests, json, time


def index(request):
    return HttpResponse('best home page')


# @login_required
@csrf_exempt
def upload(request):

    fields = ['public_key', 'private_key', 'memo', 'raw_nonce', 'nonce', 'content_hash']
    context = process_request(request, fields)

    # get file or text if input present
    myfile = request.FILES.get('myfile', None)
    if context['content_hash'] == '':
        if request.method == "POST" and myfile is not None and myfile != '':
            fs = FileSystemStorage()
            filename = fs.save(myfile.name, myfile)
            context['content_hash'] = crypt.file_hash(filename)

    text = context['memo']
    if text is not None and text != '':
        context['memo'] = text

    # generate public-private key pair
    k = crypt.generate_keys()
    context['public_key'] = k['public_key']
    context['private_key'] = k['private_key']

    # create nonce
    if context['raw_nonce'] != '':
        context['nonce'] = crypt.create_nonce(seed=context['raw_nonce'])
    else:
        context['nonce'] = ''
    # context['raw_nonce'] = request.user.username + User.objects.get(username=request.user.username).email
    # context['nonce'] = str(nonce(hash_msg(request.user.username + User.objects.get(username=request.user.username).email)),'utf-8')

    return render(request, 'upload.html', context)


# @login_required
@csrf_exempt
def origin(request):
    context = dict()
    fields_user = ['private_key', 'public_key']
    fields_content = ['timestamp', 'content_hash', 'signature', 'verified', 'nonce', 'qr', 'memo']
    fields_factom = ['chain_id', 'entry_hash', 'content', 'external_ids']

    user_info = process_request(request, fields_user)
    content_info = process_request(request, fields_content)
    factom_info = process_request(request, fields_factom)

    # updating the content fields
    content_info['timestamp'] = str(int(time.time()))
    s = crypt.Sign(content_info['content_hash'],
                   user_info['private_key'],
                   nonce=crypt.create_nonce(nonce=content_info['nonce']))
    content_info['signature'] = s.sign
    content_info['verified'] = str(crypt.verify(content_info['content_hash'], s, user_info['public_key']))
    content_info['qr'] = shorten(host='https://cryptech-api.herokuapp.com/check?',
                                 u=user_info['public_key'],
                                 h=content_info['content_hash'],
                                 s=s.sign,
                                 n=content_info['nonce'])

    # updating the factom fields
    entry_hash = factom.chain_add_entry(chain_id=factom._get_chain_id(),
                                        external_ids=[content_info['timestamp'],
                                                      user_info['public_key'],
                                                      content_info['content_hash'],
                                                      content_info['memo']],
                                        content=content_info['signature']
                                        )['entry_hash'] or None
    if entry_hash is not None:
        factom_info['entry_hash'] = entry_hash
        entry_object = factom.chain_get_entry(
            chain_id=factom._get_chain_id(), entry_hash=entry_hash)
        if entry_object is not None:
            factom_info['content'] = str(factom._decode(entry_object['content']), 'utf-8')
            factom_info['external_ids'] = [str(x, 'utf-8') for x in entry_object['external_ids']]
    factom_info['chain_id'] = factom._get_chain_id()

    # updating the context
    context['content_info'] = content_info
    context['user_info'] = user_info
    context['factom_info'] = factom_info

    return render(request, 'origin.html', context)


# @login_required
@csrf_exempt
def explore(request):
    context = dict()
    chain = []

    # defining data object
    class block(object):
        def __init__(self, entry_hash, content, ext_ids):
            self.entry_hash = entry_hash
            self.signature = content
            ext_ids = [str(x, 'utf-8') if x != '' else x for x in ext_ids]
            try:
                self.timestamp = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime(int(ext_ids[0])))
            except:
                self.timestamp = '0'
            self.public_key = ext_ids[1]
            self.content_hash = ext_ids[2]
            self.memo = ext_ids[3]

    # creating blocks by fetching Factom entries
    entry_list = factom.chain_entries(factom._get_chain_id())['items'][-10:]
    for e_hash in entry_list:
        entry = factom.chain_get_entry(factom._get_chain_id(), e_hash['entry_hash'])
        chain.append(block(entry['entry_hash'], entry['content'], entry['external_ids']))

    context['chain'] = sorted(chain, key=lambda x: x.timestamp, reverse=True)

    return render(request, 'explore.html', context)


@csrf_exempt
def verify(request):

    fields = ['public_key', 'memo', 'content_hash', 'signature', 'verified', 'qr', 'nonce']
    context = process_request(request, fields)

    # get file or text if input present
    myfile = request.FILES.get('myfile', None)
    if context['content_hash'] == '':
        if request.method == "POST" and myfile is not None and myfile != '':
            fs = FileSystemStorage()
            filename = fs.save(myfile.name, myfile)
            context['content_hash'] = crypt.file_hash(filename)

    text = context['memo']
    if text is not None and text != '':
        context['memo'] = text

    # verify the signature
    if context['content_hash'] == '' or context['signature'] == '' or context['public_key'] == '':
        context['verified'] = 'Enter fields'
        context['qr'] = '/verify/'
    else:
        context['verified'] = crypt.verify(msg=context['content_hash'],
                                            sign=crypt.Sign(sign=context['signature']),
                                            auth_pk=context['public_key'])
        # get the qr code
        context['qr'] = shorten(host='https://cryptech-api.herokuapp.com/check?',
                                     u=context['public_key'],
                                     h=context['content_hash'],
                                     s=context['signature'],
                                     n=context['nonce'])
    print(context['nonce'])
    # verify the nonce
    context['verified'] = str(context['verified'] and crypt.verify_nonce(nonce=context['nonce'],sign=context['signature']))
    return render(request, 'verify.html', context)


@csrf_exempt
def check(request):
    s = request.GET.get('s')
    u = request.GET.get('u')
    h = request.GET.get('h')
    n = request.GET.get('n')
    vs = crypt.verify(h, crypt.Sign(sign=s), u)
    vn = crypt.verify_nonce(nonce=n, sign=s)
    if vs and vn:
        return render(request, 'check.html',{'status':'Success!','desc':'Your signature is valid!','color':'lightgreen'})
    return render(request, 'check.html',{'status':'Rejected','desc':'Your signature is not valid.','color':'lightcoral'})


@csrf_exempt
def keys(request=None):
    k = crypt.generate_keys()
    return HttpResponse("Private Key: " + k['private_key'] + "<br>Public Key: " + k['public_key'])


def process_request(request, fields):
    query = dict()
    for f in fields:
        x = request.POST.get(f)
        if not x or len(x) == 0: x = ''
        query[f] = x
    return query


@csrf_exempt
def test(request):
    print(request.GET)
    print(request.POST)
    print(request.FILES)
    myfile = request.FILES.get('webcam', None)
    if request.method == "POST" and myfile is not None and myfile != '':
        fs = FileSystemStorage()
        filename = fs.save('cryptech/static/webcam.jpg', myfile)

    url = "http://api.qrserver.com/v1/read-qr-code/"

    payload = "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name=\"file\"; filename=\"webcam.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name=\"MAX_FILE_SIZE\"\r\n\r\n1048576\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW--"
    headers = {
        'content-type': "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW",
        'Cache-Control': "no-cache",
        'Postman-Token': "c687e713-15e6-4398-a9b5-65cb1eb71e52"
    }

    response = requests.request("POST", url, data=payload, headers=headers)

    print(response.text, response.status_code)
    return render(request, 'test.html', {'res':response.content})


def shorten(host, s, u, h, n):
    key = '7250c6a4b2c45454e63558ce82f214aa0ffb64f8'
    guid = 'Bi6c31plwrT'

    url = host \
            + 'u=' + u \
            + '&h=' + h \
            + '&s=' + s \
            + '&n=' + n
    print(url)
    payload = json.dumps({
        "long_url": url,
        "group_guid": guid
    })

    HEADERS = {'Content-Type': 'application/json', 'Authorization': key, 'Host': 'api-ssl.Bitly.com'}
    res = requests.request(method='POST', url='https://api-ssl.Bitly.com/v4/shorten', data=payload, headers=HEADERS)
    print(res.content)
    return json.loads(res.content)['link'] or ''


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
                return upload(request)

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

# ext_ids = ['mediachain', str(int(time.time()))]
    # content ='Chain for copyrights, patents, and create asset protection'
    # chain_id = str(factom.create_chain(external_ids=ext_ids, content=content))
    # 'chain id = fb8d30c54e846b2bd7f1f5f68145c309be4c1885def89f05954dc89ce0878206'
    # 'entry hash = 3cbbae26e73cfeaa8d1566bef45b14a5814e018780e965d3a1366f7fa1431bf6'