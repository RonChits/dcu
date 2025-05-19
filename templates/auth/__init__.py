from flask import Blueprint

auth_bp = Blueprint('auth', __name__, template_folder="templates")  # This creates a blueprint named 'auth'

from . import routes  # This must come after blueprint creation
