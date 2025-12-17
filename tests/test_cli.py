from __future__ import annotations

from types import SimpleNamespace

from mcp_oauth_server import cli


class DummyApp:
    def __init__(self) -> None:
        self.config = SimpleNamespace(DEBUG=None)
        self.prepare_calls: list[dict[str, object]] = []

    def prepare(self, **kwargs: object) -> None:
        self.prepare_calls.append(kwargs)


class DummyAppLoader:
    def __init__(self, factory) -> None:
        self.factory = factory


class DummySanic:
    serve_calls: list[dict[str, object]] = []
    serve_single_calls: list[dict[str, object]] = []

    @classmethod
    def serve(cls, primary=None, app_loader=None, factory=None) -> None:  # noqa: D401
        cls.serve_calls.append({"primary": primary, "app_loader": app_loader, "factory": factory})

    @classmethod
    def serve_single(cls, primary=None) -> None:  # noqa: D401
        cls.serve_single_calls.append({"primary": primary})


def _setup_cli_mocks(monkeypatch, build_app):
    """Keep serve() from touching the real event loop or network in tests."""
    monkeypatch.setattr(cli, "_install_uvloop", lambda: None)
    monkeypatch.setattr(cli, "_configure_logging", lambda level: None)
    monkeypatch.setattr(cli, "AppLoader", DummyAppLoader)
    monkeypatch.setattr(cli, "Sanic", DummySanic)
    monkeypatch.setattr(cli, "_build_app", build_app)


def _invoke_serve(monkeypatch, debug: bool | None, log_level: str | None = None, **extra):
    built_apps: list[DummyApp] = []

    def build_app_stub(_settings, debug_enabled: bool, _app_name: str) -> DummyApp:
        app = DummyApp()
        app.config.DEBUG = debug_enabled
        built_apps.append(app)
        return app

    DummySanic.serve_calls = []
    DummySanic.serve_single_calls = []
    _setup_cli_mocks(monkeypatch, build_app_stub)
    kwargs = {
        "host": None,
        "port": None,
        "mcp_path": None,
        "json_response": None,
        "stateless": None,
        "log_level": log_level,
        "debug": debug,
    }
    kwargs.update(extra)
    cli.serve.callback(**kwargs)
    return built_apps, DummySanic


def test_debug_enables_auto_reload(monkeypatch) -> None:
    apps, sanic = _invoke_serve(monkeypatch, debug=True)
    app = apps[-1]

    assert app.config.DEBUG is True
    assert app.prepare_calls[-1]["auto_reload"] is True
    assert app.prepare_calls[-1]["dev"] is True
    assert app.prepare_calls[-1]["debug"] is True
    assert app.prepare_calls[-1]["single_process"] is False
    assert sanic.serve_calls  # multi-process path used
    assert not sanic.serve_single_calls
    assert isinstance(sanic.serve_calls[-1]["app_loader"], DummyAppLoader)


def test_non_debug_runs_without_auto_reload(monkeypatch) -> None:
    apps, sanic = _invoke_serve(monkeypatch, debug=None, log_level="INFO")
    app = apps[-1]

    assert app.config.DEBUG is False
    assert app.prepare_calls[-1]["auto_reload"] is False
    assert app.prepare_calls[-1]["dev"] is False
    assert app.prepare_calls[-1]["debug"] is False
    assert app.prepare_calls[-1]["single_process"] is True
    assert sanic.serve_single_calls  # single-process path used
    assert not sanic.serve_calls


def test_prepare_receives_overrides(monkeypatch) -> None:
    apps, _ = _invoke_serve(
        monkeypatch,
        debug=True,
        log_level="WARNING",
        host="0.0.0.0",
        port=9000,
        mcp_path="/x",
        json_response=False,
        stateless=False,
    )
    kwargs = apps[-1].prepare_calls[-1]

    assert kwargs["host"] == "0.0.0.0"
    assert kwargs["port"] == 9000
    assert kwargs["debug"] is True
    assert kwargs["auto_reload"] is True
