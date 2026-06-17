"""
Logging setup. Потому что print() — это для дебага в блокноте, а не для приложения.
"""

import logging
import sys
from typing import Optional


# Формат логов: время, уровень, модуль, сообщение
LOG_FORMAT = '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'


def setup_logging(
    level: int = logging.INFO,
    log_file: Optional[str] = None,
    module_levels: Optional[dict] = None
) -> None:
    """
    Настраивает логирование для всего приложения.

    Args:
        level: общий уровень логирования (INFO по умолчанию)
        log_file: если указан — пишем в файл, иначе только в stderr
        module_levels: словарь вида {'core.crypto': logging.DEBUG} для
                       переопределения уровня отдельных модулей
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Убираем существующие хендлеры (вдруг настроено дважды)
    root_logger.handlers.clear()

    # Форматтер один для всех
    formatter = logging.Formatter(LOG_FORMAT, LOG_DATE_FORMAT)

    # Хендлер в stderr
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # Хендлер в файл (опционально)
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

    # Переопределяем уровни для конкретных модулей
    if module_levels:
        for module_name, module_level in module_levels.items():
            logging.getLogger(module_name).setLevel(module_level)


def get_logger(name: str) -> logging.Logger:
    """
    Возвращает логгер с указанным именем.

    Используй так:
        logger = get_logger(__name__)
        logger.info("Server started")
        logger.error("Shit happened: %s", error)
    """
    return logging.getLogger(name)
