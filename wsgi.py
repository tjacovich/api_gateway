from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.serving import run_simple
from werkzeug.wrappers import Response
from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor

from apigateway.app import create_app

app = create_app()
FlaskInstrumentor.instrument_app(app)

SQLAlchemyInstrumentor().instrument(engine=app.db.engine)

application = DispatcherMiddleware(Response("Not Found", status=404), {"/v1": app})

if __name__ == "__main__":

    run_simple(
        "0.0.0.0",
        8181,
        application,
        use_reloader=True,
        use_debugger=False,
        threaded=True,
    )
