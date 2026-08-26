"""Flask Application Factory for CodeMender Dispatcher."""

import os
from flask import Flask
from .config import Config
from .models.scan_job import init_db
from .api.scans import scans_bp
from .api.webhooks import webhooks_bp
from .api.events import events_bp
from .web.routes import web_bp


def create_app(config_class=Config):
    """Factory function creating Flask application instance."""
    app = Flask(
        __name__,
        template_folder="web/templates",
        static_folder="web/static",
    )
    app.config.from_object(config_class)

    # Initialize Database Manager
    app.db_manager = init_db(app.config["DATABASE_URI"])

    # Register Blueprints
    app.register_blueprint(web_bp)
    app.register_blueprint(scans_bp)
    app.register_blueprint(webhooks_bp)
    app.register_blueprint(events_bp)

    return app


if __name__ == "__main__":
    app = create_app()
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=True)
