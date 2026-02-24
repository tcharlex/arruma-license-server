from flask import request, jsonify


def register_protected_routes(app, validate_session):

    @app.get("/ping")
    def protected_ping():
        ok, user = validate_session(request)

        if not ok:
            return {"error": "unauthorized"}, 401

        return {"status": "ok", "message": "token válido", "user": user}
