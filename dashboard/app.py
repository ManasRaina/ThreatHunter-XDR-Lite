import json
from flask import Flask
from config import FLASK_SECRET_KEY


def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = FLASK_SECRET_KEY

    # Custom Jinja2 filter
    app.jinja_env.filters['fromjson'] = json.loads

    from dashboard.routes.views import views_bp
    from dashboard.routes.api   import api_bp

    app.register_blueprint(views_bp)
    app.register_blueprint(api_bp, url_prefix="/api/v1")

    return app