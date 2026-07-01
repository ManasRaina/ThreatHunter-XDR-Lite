"""
Flask REST API for the Threat Intelligence Platform.

Provides JSON endpoints for IOCs, alerts, rules, feed refresh, and dashboard stats.
"""

import logging
import sys

from flask import Flask, jsonify, request

from config import FLASK_DEBUG, FLASK_HOST, FLASK_PORT, FLASK_SECRET_KEY

logger = logging.getLogger("tip.api")


def _configure_logging() -> None:
    if logger.handlers:
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    )
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


def create_app() -> Flask:
    _configure_logging()

    app = Flask(__name__)
    app.secret_key = FLASK_SECRET_KEY

    from api.routes import api_bp

    app.register_blueprint(api_bp)

    @app.before_request
    def log_request() -> None:
        logger.info("%s %s", request.method, request.path)

    @app.errorhandler(400)
    def bad_request(_exc):
        return jsonify({"error": "Bad request"}), 400

    @app.errorhandler(404)
    def not_found(_exc):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(500)
    def server_error(_exc):
        logger.exception("Unhandled server error")
        return jsonify({"error": "Internal server error"}), 500

    logger.info("API application created")
    return app


def run() -> None:
    app = create_app()
    logger.info("Starting API on http://%s:%s", FLASK_HOST, FLASK_PORT)
    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=FLASK_DEBUG)


if __name__ == "__main__":
    run()
