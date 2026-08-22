#!/usr/bin/env python3
"""Запуск тестов без pytest.

Основной способ — ``python -m pytest tests``. Этот файл нужен там, где pytest
недоступен (изолированная машина, отсутствие сети). Он подменяет минимальный
набор API pytest и прогоняет те же самые тестовые функции.
"""

from __future__ import annotations

import inspect
import io
import os
import sys
import tempfile
import traceback
import types
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))


def _install_pytest_stub() -> None:
    stub = types.ModuleType("pytest")

    class Skipped(Exception):
        pass

    class _Caught:
        """Аналог ExceptionInfo: даёт доступ к пойманному исключению через .value."""

        value = None

    @contextmanager
    def raises(expected):
        caught = _Caught()
        try:
            yield caught
        except expected as exc:
            caught.value = exc
            return
        except Exception as exc:
            name = getattr(expected, "__name__", str(expected))
            raise AssertionError(f"ожидалось {name}, получено {exc!r}") from exc
        name = getattr(expected, "__name__", str(expected))
        raise AssertionError(f"ожидалось {name}, но исключения не было")

    def fixture(*args, **kwargs):
        def wrap(fn):
            fn.__is_fixture__ = True
            return fn

        return wrap(args[0]) if args and callable(args[0]) else wrap

    class _Mark:
        @staticmethod
        def skipif(condition, reason=""):
            def wrap(fn):
                fn.__skip__ = (bool(condition), reason)
                return fn

            return wrap

        @staticmethod
        def parametrize(names, values):
            def wrap(fn):
                fn.__params__ = (names, list(values))
                return fn

            return wrap

    stub.raises = raises
    stub.fixture = fixture
    stub.mark = _Mark
    stub.Skipped = Skipped
    sys.modules["pytest"] = stub


class _MonkeyPatch:
    """Минимальный аналог фикстуры monkeypatch: setattr/setenv с откатом."""

    def __init__(self) -> None:
        self._undo: list = []

    def setattr(self, target, name, value):
        original = getattr(target, name)
        self._undo.append(lambda: setattr(target, name, original))
        setattr(target, name, value)

    def setenv(self, name, value):
        original = os.environ.get(name)
        self._undo.append(
            lambda: os.environ.__setitem__(name, original)
            if original is not None
            else os.environ.pop(name, None)
        )
        os.environ[name] = value

    def delenv(self, name, raising=True):
        original = os.environ.get(name)
        if original is None and raising:
            raise KeyError(name)
        self._undo.append(
            lambda: os.environ.__setitem__(name, original) if original is not None else None
        )
        os.environ.pop(name, None)

    def undo(self):
        for action in reversed(self._undo):
            action()
        self._undo.clear()


class _Captured:
    def __init__(self, out: str, err: str) -> None:
        self.out = out
        self.err = err


class _CapSys:
    """Аналог capsys: перехват stdout и stderr на время теста."""

    def __init__(self) -> None:
        self.out = io.StringIO()
        self.err = io.StringIO()

    def readouterr(self) -> _Captured:
        captured = _Captured(self.out.getvalue(), self.err.getvalue())
        self.out.seek(0), self.out.truncate(0)
        self.err.seek(0), self.err.truncate(0)
        return captured


def _cases(fn):
    """Разворачивает parametrize в отдельные запуски."""
    names, values = getattr(fn, "__params__", (None, None))
    if names is None:
        return [({}, "")]
    keys = [name.strip() for name in names.split(",")]
    cases = []
    for value in values:
        row = value if isinstance(value, tuple) else (value,)
        cases.append((dict(zip(keys, row)), f"[{'-'.join(map(str, row))}]"))
    return cases


def main() -> int:
    _install_pytest_stub()

    # Аналог autouse-фикстуры cheap_kdf: боевые параметры Argon2id делают
    # прогон непозволительно долгим.
    from p2pchat.crypto import identity as ident

    ident.ARGON2_MEMORY_KIB = 8 * 1024
    ident.ARGON2_TIME_COST = 1

    modules = [
        "tests.test_noise_xx",
        "tests.test_identity",
        "tests.test_net",
        "tests.test_session",
        "tests.test_mesh",
        "tests.test_files",
        "tests.test_bot",
        "tests.test_console",
        "tests.test_connect",
        "tests.test_games",
        "tests.test_more_games",
        "tests.test_cli",
        "tests.test_vectors",
    ]
    passed = skipped = 0
    failures: list[tuple[str, str]] = []

    for module_name in modules:
        module = __import__(module_name, fromlist=["*"])
        for name, fn in sorted(vars(module).items()):
            if not name.startswith("test_") or not callable(fn):
                continue
            if getattr(fn, "__is_fixture__", False):
                continue
            skip, reason = getattr(fn, "__skip__", (False, ""))
            if skip:
                print(f"SKIP {module_name}.{name}\n     {reason}")
                skipped += 1
                continue
            for params, label in _cases(fn):
                parameters = inspect.signature(fn).parameters
                kwargs = dict(params)
                patch = _MonkeyPatch()
                capsys = _CapSys()
                with tempfile.TemporaryDirectory() as tmp:
                    if "tmp_path" in parameters:
                        kwargs["tmp_path"] = Path(tmp)
                    if "monkeypatch" in parameters:
                        kwargs["monkeypatch"] = patch
                    if "capsys" in parameters:
                        kwargs["capsys"] = capsys
                    try:
                        if "capsys" in parameters:
                            with redirect_stdout(capsys.out), redirect_stderr(capsys.err):
                                fn(**kwargs)
                        else:
                            fn(**kwargs)
                    except Exception:
                        failures.append(
                            (f"{module_name}.{name}{label}", traceback.format_exc())
                        )
                        print(f"FAIL {name}{label}")
                        continue
                    finally:
                        patch.undo()
                passed += 1
                print(f"ok   {name}{label}")

    print(f"\n{passed} пройдено, {len(failures)} провалено, {skipped} пропущено")
    for name, tb in failures:
        print(f"\n--- {name} ---\n{tb}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
