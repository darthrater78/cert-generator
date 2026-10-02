"""Failed operations answer with the app's own message, never a library's exception text."""
from app.errors import UserError
from app.web import value_error


def test_user_error_message_is_shown(fresh_app):
    with fresh_app.test_request_context():
        resp, status = value_error(UserError("Wrong password"))
        assert status == 400 and resp.get_json() == {"error": "Wrong password"}


def test_library_error_text_is_not_shown(fresh_app):
    with fresh_app.test_request_context():
        resp, status = value_error(ValueError("/internal/path/secret.pem: bad header"))
        assert status == 400 and "secret" not in resp.get_json()["error"]
