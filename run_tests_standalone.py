#!/usr/bin/env python3
"""Запуск тестов без pytest.

Основной способ — ``python -m pytest tests``. Этот файл нужен там, где pytest
недоступен (изолированная машина, отсутствие сети). Он подменяет минимальный
набор API pytest и прогоняет те же самые тестовые функции.
"""

from __future__ import annotations

import inspect
import sys
import tempfile
import traceback
import types
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))


def _install_pytest_stub() -> None:
    stub = types.ModuleType("pytest")

    class Skipped(Exception):
        pass

    @contextmanager
    def raises(expected):
        try:
            yield
        except expected:
            return
        except Exception as exc:
            raise AssertionError(f"ожидалось {expected.__name__}, получено {exc!r}") from exc
        raise AssertionError(f"ожидалось {expected.__name__}, но исключения не было")

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

    stub.raises = raises
    stub.fixture = fixture
    stub.mark = _Mark
    stub.Skipped = Skipped
    sys.modules["pytest"] = stub


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
            kwargs = {}
            with tempfile.TemporaryDirectory() as tmp:
                if "tmp_path" in inspect.signature(fn).parameters:
                    kwargs["tmp_path"] = Path(tmp)
                try:
                    fn(**kwargs)
                except Exception:
                    failures.append((f"{module_name}.{name}", traceback.format_exc()))
                    print(f"FAIL {name}")
                    continue
            passed += 1
            print(f"ok   {name}")

    print(f"\n{passed} пройдено, {len(failures)} провалено, {skipped} пропущено")
    for name, tb in failures:
        print(f"\n--- {name} ---\n{tb}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
