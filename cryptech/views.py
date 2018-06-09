from django.http import HttpResponse
import os
def index(request):
    return HttpResponse(os.environ.get('FACTOM_HOST'))