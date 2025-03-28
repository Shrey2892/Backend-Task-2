import os
import django
from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Project.settings')

django.setup()  # 🔥 Ensures Django initializes properly

application = get_asgi_application()
