from unittest.mock import Mock

import pytest
import requests

from scripts.check_hosted_release import check_hosted_release


def responses(secure=True, hsts=True):
    def get(url, **options):
        assert options["verify"] is True
        assert options["allow_redirects"] is False
        response = requests.Response()
        response.status_code = 200
        response._content = b'{"status":"ok"}'
        if url.endswith("/live/"):
            response._content = b'{"status":"alive"}'
        elif url.endswith("/manage/"):
            response.status_code = 302
            response.headers["Location"] = "/accounts/login/?next=/manage/"
        elif url.endswith("/accounts/login/"):
            response.headers.update(
                {
                    "Strict-Transport-Security": "max-age=31536000" if hsts else "",
                    "X-Frame-Options": "DENY",
                    "Cache-Control": "no-store, private",
                    "Content-Security-Policy": "object-src 'none'; frame-ancestors 'none'",
                }
            )
            response.cookies.set("csrftoken", "secret-canary", secure=secure)
        return response

    return Mock(get=Mock(side_effect=get))


def test_hosted_release_check_passes_production_without_reporting_cookie_values():
    result = check_hosted_release("https://vault.example.test", session=responses())
    assert result["passed"]
    assert "secret-canary" not in str(result)


def test_development_cookie_and_missing_hsts_fail_the_hosted_release_gate():
    result = check_hosted_release(
        "https://vault.example.test", session=responses(secure=False, hsts=False)
    )
    assert not result["passed"]
    assert set(result["failures"]) == {"csrf_cookie_not_secure", "hsts_missing"}


def test_unreachable_host_fails_without_exception_details_or_secrets():
    client = Mock(get=Mock(side_effect=requests.ConnectionError("secret-canary")))
    result = check_hosted_release("https://vault.example.test", session=client)
    assert not result["passed"]
    assert "secret-canary" not in str(result)


@pytest.mark.parametrize(
    "origin",
    [
        "http://vault.example.test",
        "https://user:secret@vault.example.test",
        "https://vault.example.test/?token=secret",
    ],
)
def test_unsafe_origin_is_rejected_before_network_calls(origin):
    client = Mock()
    with pytest.raises(ValueError):
        check_hosted_release(origin, session=client)
    client.get.assert_not_called()
