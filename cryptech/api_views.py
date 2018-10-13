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
from django.http import JsonResponse


@csrf_exempt
def generate_key_pair(request):
    k = crypt.generate_keys()
    response = {
        "privateKey": k['private_key'],
        "publicKey": k['public_key']
    }
    return JsonResponse(response)


@csrf_exempt
def publish(request):
    response = {
        "entryHash": "",
        "signature": ""
    }
    chain_id = request.POST.get("chainID")
    content_hash = request.POST.get("hash")
    publish_context = request.POST.get("context")
    private_key = request.POST.get("privateKey")

    response["signature"] = crypt.Sign(msg=content_hash, auth_rk=private_key).sign

    context_json = json.loads(publish_context)
    context_list = []
    for key, val in context_json.items():
        context_list.append(str(key))
        context_list.append(str(val))

    resp = factom.chain_add_entry(chain_id=chain_id,
                                  external_ids=context_list,
                                  content=response["signature"])

    response["entryHash"] = resp.get('entry_hash') or None

    if response["entryHash"] is None:
        return JsonResponse({"error": "could not publish to Factom"})

    return JsonResponse(response)


@csrf_exempt
def publish_with_notary(request):

    response = {
        "entryHash": "",
        "signature": "",
        "notarySignature": ""
    }

    chain_id = request.POST.get("chainID")
    content_hash = request.POST.get("hash")
    publish_context = request.POST.get("context")
    private_key = request.POST.get("privateKey")
    notary_private_key = request.POST.get("notaryPrivateKey")
    identity = request.POST.get("identityHash")

    response["notarySignature"] = crypt.Sign(msg=identity, auth_rk=notary_private_key).sign
    response["signature"] = crypt.Sign(msg=content_hash, auth_rk=private_key,
                                       nonce=crypt.create_nonce(seed=response["notarySignature"])).sign

    context_json = json.loads(publish_context)
    context_list = []
    for key, val in context_json.items():
        context_list.append(str(key))
        context_list.append(str(val))

    response["entryHash"] = factom.chain_add_entry(chain_id=chain_id,
                                                   external_ids=context_list,
                                                   content=response["signature"]
                                                   )["entry_hash"] or None
    if response["entryHash"] is None:
        return JsonResponse({"error": "could not publish to Factom"})

    return JsonResponse(response)


@csrf_exempt
def verify_sign(request):

    response = {
        "result": ""
    }

    chain_id = request.POST.get("chainID")
    entry_hash = request.POST.get("entryHash")
    content_hash = request.POST.get("hash")
    public_key = request.POST.get("publicKey")

    signature = factom.chain_get_entry(chain_id=chain_id, entry_hash=entry_hash)["content"]
    signature = str(factom._decode(signature), 'utf-8')

    verify = crypt.verify(msg=content_hash,
                          sign=crypt.Sign(sign=signature),
                          auth_pk=public_key)

    response["result"] = str(verify)

    return JsonResponse(response)


@csrf_exempt
def verify_sign_notary(request):

    response = {
        "validAuthorSignature": "",
        "validNotarySignature": "",
        "validNonce": ""
    }

    chain_id = request.POST.get("chainID")
    entry_hash = request.POST.get("entryHash")
    content_hash = request.POST.get("hash")
    public_key = request.POST.get("publicKey")
    notary_public_key = request.POST.get("notaryPublicKey")
    notary_signature = request.POST.get("notarySign")
    identity = request.POST.get("identityHash")

    signature = factom.chain_get_entry(chain_id=chain_id, entry_hash=entry_hash)["content"]
    signature = str(factom._decode(signature), 'utf-8')

    verify = crypt.verify(msg=content_hash,
                          sign=crypt.Sign(sign=signature),
                          auth_pk=public_key)

    response["validAuthorSignature"] = str(verify)

    valid_notary_sign = crypt.verify(msg=identity,
                          sign=crypt.Sign(sign=notary_signature),
                          auth_pk=notary_public_key)

    response["validNotarySignature"] = str(valid_notary_sign)

    if valid_notary_sign:
        verify_notary = crypt.verify_nonce(nonce=crypt.create_nonce(seed=notary_signature),sign=signature)
        response["validNonce"] = str(verify_notary)
    else:
        response["validNonce"] = str(False)
    return JsonResponse(response)


@csrf_exempt
def get_published_data(request):
    return HttpResponse('ok')

@csrf_exempt
def create_chain(request):
    ext_ids = ['Ext_id_test']
    content = 'Test'
    response = factom.create_chain(external_ids=ext_ids, content=content)

    return JsonResponse(response)
