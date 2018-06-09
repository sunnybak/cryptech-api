from django.http import HttpResponse
from hellosign_sdk import HSClient


def index(request):
    return HttpResponse('hi')