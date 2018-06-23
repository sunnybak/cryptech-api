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
        "signature": "",
        "chainID": ""
    }

    try:
        chain_id = request.POST.get("chainID") or 1 / 0
        content_hash = request.POST.get("hash") or 1 / 0
        publish_context = request.POST.get("context") or 1 / 0
        private_key = request.POST.get("privateKey") or 1 / 0
    except ZeroDivisionError:
        return JsonResponse({"error": "incorrect request"})
    except Exception as ex:
        template = "An exception of type {0} occurred. Arguments:\n{1!r}"
        message = template.format(type(ex).__name__, ex.args)
        return JsonResponse({"error": message})

    response["signature"] = crypt.Sign(msg=content_hash, auth_rk=private_key).sign

    publish_context = [str(x) for x in list(json.loads(publish_context).values())]

    response["entryHash"] = factom.chain_add_entry(chain_id= chain_id,
                                                   external_ids=publish_context,
                                                   content=response["signature"]
                                                   )["entry_hash"] or None
    if response["entryHash"] is None:
        return JsonResponse({"error": "could not publish to Factom"})

    response["chainID"] = chain_id

    return JsonResponse(response)


@csrf_exempt
def publish_with_notary(request):

    response = {
        "entryHash": "",
        "signature": "",
        "notarySignature": "",
        "chainID": ""
    }

    try:
        chain_id = request.POST.get("chainID") or 1 / 0
        content_hash = request.POST.get("hash") or 1 / 0
        publish_context = request.POST.get("context") or 1 / 0
        private_key = request.POST.get("privateKey") or 1 / 0
        notary_private_key = request.POST.get("notaryPrivateKey") or 1 / 0
        identity = request.POST.get("identity") or 1 / 0
    except ZeroDivisionError:
        return JsonResponse({"error": "incorrect request"})
    except Exception as ex:
        template = "An exception of type {0} occurred. Arguments:\n{1!r}"
        message = template.format(type(ex).__name__, ex.args)
        return JsonResponse({"error": message})

    response["notarySignature"] = crypt.Sign(msg=identity, auth_rk=notary_private_key).sign
    response["signature"] = crypt.Sign(msg=content_hash, auth_rk=private_key,
                                       nonce=crypt.create_nonce(seed=response["notarySignature"])).sign

    publish_context = [str(x) for x in list(json.loads(publish_context).values())]

    response["entryHash"] = factom.chain_add_entry(chain_id= chain_id,
                                                   external_ids=publish_context,
                                                   content=response["signature"]
                                                   )["entry_hash"] or None
    if response["entryHash"] is None:
        return JsonResponse({"error": "could not publish to Factom"})

    response["chainID"] = chain_id

    return JsonResponse(response)


@csrf_exempt
def verify_sign(request):


    return HttpResponse('ok')


@csrf_exempt
def get_published_data(request):
    return HttpResponse('ok')
