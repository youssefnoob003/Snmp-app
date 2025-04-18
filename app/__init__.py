from flask import Flask
from config import Config
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine
import os

# Main database
db = SQLAlchemy()

# Static models.db engine (read-only)
models_engine = None  # ✅ Exposed to be imported elsewhere

poller_started = False

def create_app():
    global models_engine
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)

    # ✅ Create static DB engine (models.db)
    if models_engine is None:
        models_engine = create_engine(app.config['MODELS_DATABASE_URI'])

    # Register blueprints
    from app.routes.device_routes import bp as device_bp
    from app.routes.graph_routes import graph_routes

    app.register_blueprint(device_bp)
    app.register_blueprint(graph_routes)

    with app.app_context():
        db.create_all()

        global poller_started
        if not poller_started:
            print(f"Starting poller in process {os.getpid()}")
            from app.services.background_snmp import start_background_snmp_polling
            start_background_snmp_polling(app)
            poller_started = True

    return app
