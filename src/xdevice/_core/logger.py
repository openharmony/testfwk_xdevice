#!/usr/bin/env python3
# coding=utf-8

#
# Copyright (c) 2020-2022 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import logging
import os
import sys
import time
import threading
import queue
from logging.handlers import RotatingFileHandler

from _core.constants import LogMode
from _core.constants import LogType
from _core.plugin import Plugin
from _core.plugin import get_plugin
from _core.exception import ParamError


__all__ = ["Log", "platform_logger", "device_logger", "shutdown",
           "add_task_file_handler", "remove_task_file_handler",
           "change_logger_level",
           "add_encrypt_file_handler", "remove_encrypt_file_handler",
           "redirect_driver_log_begin", "redirect_driver_log_end"]

_HANDLERS = []
_LOGGERS = []
MAX_LOG_LENGTH = 20 * 1024 * 1024
MAX_ENCRYPT_LOG_LENGTH = 5 * 1024 * 1024
MAX_LOG_NUMS = 1000
MAX_LOG_CACHE_SIZE = 10


def _new_file_handler(log_file, log_level, mode="a"):
    from xdevice import Variables
    handler = RotatingFileHandler(log_file, mode=mode, maxBytes=MAX_LOG_LENGTH,
                                  backupCount=MAX_LOG_NUMS, encoding="utf-8")
    handler.setFormatter(logging.Formatter(Variables.report_vars.log_format))
    handler.setLevel(log_level)
    return handler


def _query_log_level():
    log_level = getattr(sys, "log_level", logging.INFO) if hasattr(
        sys, "log_level") else logging.DEBUG
    return log_level


class DriverLogFilter(logging.Filter):

    def __init__(self, thread_id):
        super().__init__()
        self.thread_id = thread_id

    def filter(self, record):
        return record.thread == self.thread_id


class SchedulerLogFilter(logging.Filter):

    def __init__(self):
        super().__init__()
        self.driver_thread_ids = []

    def filter(self, record):
        return record.thread not in self.driver_thread_ids

    def add_driver_thread_id(self, thread_id):
        self.driver_thread_ids.append(thread_id)

    def del_driver_thread_id(self, thread_id):
        self.driver_thread_ids.remove(thread_id)


class Log:
    task_file_handler = None

    def __init__(self):
        self.level = logging.INFO
        self.handlers = []
        self.loggers = {}
        self.task_file_filter = None
        self.task_file_handler = None
        self.encrypt_file_handler = None
        self.driver_log_handler = {}
        self._lock = threading.Lock()

    def __initial__(self, log_handler_flag, log_file=None, level=None,
                    log_format=None):
        if _LOGGERS:
            return

        self.handlers = []
        if log_file and "console" in log_handler_flag:
            file_handler = RotatingFileHandler(
                log_file, mode="a", maxBytes=MAX_LOG_LENGTH, backupCount=MAX_LOG_NUMS,
                encoding="UTF-8")
            file_handler.setFormatter(logging.Formatter(log_format))
            self.handlers.append(file_handler)
        if "console" in log_handler_flag \
                and getattr(sys, LogMode.name, LogMode.default) != LogMode.no_console:
            stream_handler = logging.StreamHandler(sys.stdout)
            stream_handler.setFormatter(logging.Formatter(log_format))
            self.handlers.append(stream_handler)

        if level:
            self.level = level
        self.loggers = {}
        self.task_file_handler = None
        _HANDLERS.extend(self.handlers)

    def set_level(self, level):
        self.level = level

    def __logger__(self, name=None):
        if not name:
            return _init_global_logger(name)
        elif name in self.loggers:
            return self.loggers.get(name)
        else:
            log = self.loggers.setdefault(name, FrameworkLog(name))
            _LOGGERS.append(log)
            log.add_platform_level(self.level)
            for handler in self.handlers:
                log.add_platform_handler(handler)
            if self.task_file_handler:
                log.add_task_log(self.task_file_handler)
            return log

    def add_driver_log_handler(self, thread_id, log_file):
        log_dir = os.path.dirname(log_file)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        try:
            self._lock.acquire()
            # 1.仅输出当前驱动执行线程的日志到文件
            log_level = _query_log_level()
            handler = _new_file_handler(log_file, log_level)
            handler.addFilter(DriverLogFilter(thread_id))
            # 2.添加驱动执行线程的日志处理器，使得新建的日志对象可用
            self.handlers.append(handler)
            # 3.为已有的日志对象添加驱动执行线程日志处理器
            for _, log in self.loggers.items():
                log.add_task_log(handler)
            # 4.为调度日志对象记录器，添加当前执行线程的日志过滤标识
            if self.task_file_filter is not None \
                    and isinstance(self.task_file_filter, SchedulerLogFilter):
                self.task_file_filter.add_driver_thread_id(thread_id)
            self.driver_log_handler.setdefault(thread_id, handler)
        finally:
            self._lock.release()

    def del_driver_log_handler(self, thread_id):
        try:
            self._lock.acquire()
            # 为调度日志对象记录器，移除当前执行线程的日志过滤标识
            if self.task_file_filter is not None \
                    and isinstance(self.task_file_filter, SchedulerLogFilter):
                self.task_file_filter.del_driver_thread_id(thread_id)
            if thread_id in self.driver_log_handler.keys():
                # 关闭驱动执行线程日志处理器
                handler = self.driver_log_handler.pop(thread_id)
                handler.close()
                # 移除驱动执行线程日志处理器
                self.handlers.remove(handler)
                # 为已有的日志对象，移除驱动执行线程日志处理器
                for _, log in self.loggers.items():
                    log.remove_task_log(handler, False)
        finally:
            self._lock.release()

    def add_task_file_handler(self, log_file):
        self.task_file_filter = SchedulerLogFilter()
        log_level = _query_log_level()
        self.task_file_handler = _new_file_handler(log_file, log_level)
        self.task_file_handler.addFilter(self.task_file_filter)
        for _, log in self.loggers.items():
            log.add_task_log(self.task_file_handler)

    def remove_task_file_handler(self):
        if self.task_file_handler is None:
            return
        for _, log in self.loggers.items():
            log.remove_task_log(self.task_file_handler, True)
        self.task_file_handler.close()
        self.task_file_handler = None

    def add_encrypt_file_handler(self, log_file):
        from xdevice import Variables

        file_handler = \
            EncryptFileHandler(log_file, mode="ab",
                               max_bytes=MAX_ENCRYPT_LOG_LENGTH,
                               backup_count=MAX_LOG_NUMS, encoding="utf-8")
        file_handler.setFormatter(logging.Formatter(
            Variables.report_vars.log_format))
        self.encrypt_file_handler = file_handler
        for _, log in self.loggers.items():
            log.add_encrypt_log(self.encrypt_file_handler)

    def remove_encrypt_file_handler(self):
        if self.encrypt_file_handler is None:
            return
        for _, log in self.loggers.items():
            log.remove_encrypt_log(self.encrypt_file_handler)
        self.encrypt_file_handler.close()
        self.encrypt_file_handler = None


class FrameworkLog:

    def __init__(self, name):
        self.name = name
        self.platform_log = logging.Logger(name)
        self.task_log = None
        self.encrypt_log = None
        self.driver_log = None

    def set_level(self, level):
        # apply to dynamic change logger level, and
        # only change the level of platform log
        cache = getattr(self.platform_log, "_cache", None)
        if cache and isinstance(cache, dict):
            cache.clear()
        self.platform_log.setLevel(level)

    def add_platform_handler(self, handler):
        self.platform_log.addHandler(handler)

    def del_platform_handler(self, handler):
        self.platform_log.removeHandler(handler)

    def add_platform_level(self, level):
        self.platform_log.setLevel(level)

    def add_task_log(self, handler):
        if not self.task_log:
            self.task_log = logging.Logger(self.name)
            log_level = _query_log_level()
            self.task_log.setLevel(log_level)
        self.task_log.addHandler(handler)

    def remove_task_log(self, handler, is_destroy=False):
        if not self.task_log:
            return
        self.task_log.removeHandler(handler)
        if is_destroy:
            self.task_log = None

    def add_encrypt_log(self, handler):
        if self.encrypt_log:
            return
        self.encrypt_log = logging.Logger(self.name)
        log_level = _query_log_level()
        self.encrypt_log.setLevel(log_level)
        self.encrypt_log.addHandler(handler)

    def remove_encrypt_log(self, handler):
        if not self.encrypt_log:
            return
        self.encrypt_log.removeHandler(handler)
        self.encrypt_log = None

    def info(self, msg, *args, **kwargs):
        additional_output = self._get_additional_output(**kwargs)
        updated_msg = self._update_msg(additional_output, msg)
        self.platform_log.info(updated_msg, *args)
        if self.task_log:
            self.task_log.info(updated_msg, *args)
        if self.encrypt_log:
            self.encrypt_log.info(updated_msg, *args)

    def debug(self, msg, *args, **kwargs):
        additional_output = self._get_additional_output(**kwargs)
        updated_msg = self._update_msg(additional_output, msg)
        from _core.report.encrypt import check_pub_key_exist
        if not check_pub_key_exist():
            self.platform_log.debug(updated_msg, *args)
            if self.task_log:
                self.task_log.debug(updated_msg, *args)
        else:
            if self.encrypt_log:
                self.encrypt_log.debug(updated_msg, *args)

    def error(self, msg, *args, **kwargs):
        error_no = kwargs.get("error_no", "00000")
        additional_output = self._get_additional_output(error_no, **kwargs)
        updated_msg = self._update_msg(additional_output, msg)

        self.platform_log.error(updated_msg, *args)
        if self.task_log:
            self.task_log.error(updated_msg, *args)
        if self.encrypt_log:
            self.encrypt_log.error(updated_msg, *args)

    def warning(self, msg, *args, **kwargs):
        additional_output = self._get_additional_output(**kwargs)
        updated_msg = self._update_msg(additional_output, msg)

        self.platform_log.warning(updated_msg, *args)
        if self.task_log:
            self.task_log.warning(updated_msg, *args)
        if self.encrypt_log:
            self.encrypt_log.warning(updated_msg, *args)

    def exception(self, msg, *args, **kwargs):
        error_no = kwargs.get("error_no", "00000")
        exc_info = kwargs.get("exc_info", True)
        if exc_info is not True and exc_info is not False:
            exc_info = True
        additional_output = self._get_additional_output(error_no, **kwargs)
        updated_msg = self._update_msg(additional_output, msg)

        self.platform_log.exception(updated_msg, exc_info=exc_info, *args)
        if self.task_log:
            self.task_log.exception(updated_msg, exc_info=exc_info, *args)
        if self.encrypt_log:
            self.encrypt_log.exception(updated_msg, exc_info=exc_info, *args)

    @classmethod
    def _update_msg(cls, additional_output, msg):
        msg = "[{}]".format(msg) if msg else msg
        if msg and additional_output:
            msg = "{} [{}]".format(msg, additional_output)
        return msg

    def _get_additional_output(self, error_number=None, **kwargs):
        dict_str = self._get_dict_str(**kwargs)
        if error_number:
            additional_output = "ErrorNo=%s" % error_number
        else:
            return dict_str

        if dict_str:
            additional_output = "%s, %s" % (additional_output, dict_str)
        return additional_output

    @classmethod
    def _get_dict_str(cls, **kwargs):
        dict_str = ""
        for key, value in kwargs.items():
            if key in ["error_no", "exc_info"]:
                continue
            dict_str = "%s%s=%s, " % (dict_str, key, value)
        if dict_str:
            dict_str = dict_str[:-2]
        return dict_str


def platform_logger(name=None):
    plugins = get_plugin(Plugin.LOG, LogType.tool)
    for log_plugin in plugins:
        if log_plugin.get_plugin_config().enabled:
            return log_plugin.__logger__(name)
    return _init_global_logger(name)


def device_logger(name=None):
    plugins = get_plugin(Plugin.LOG, LogType.device)
    for log_plugin in plugins:
        if log_plugin.get_plugin_config().enabled:
            return log_plugin.__logger__(name)
    return _init_global_logger(name)


def shutdown():
    # logging will be shutdown automatically, when the program exits.
    # This function is used by testing.
    for log in _LOGGERS:
        for handler in log.handlers:
            log.removeHandler(handler)
    for handler in _HANDLERS:
        handler.close()
    _HANDLERS.clear()
    _LOGGERS.clear()


def redirect_driver_log_begin(thread_id, log_file):
    plugins = get_plugin(Plugin.LOG, LogType.tool)
    for log_plugin in plugins:
        if log_plugin.get_plugin_config().enabled:
            log_plugin.add_driver_log_handler(thread_id, log_file)


def redirect_driver_log_end(thread_id):
    plugins = get_plugin(Plugin.LOG, LogType.tool)
    for log_plugin in plugins:
        if log_plugin.get_plugin_config().enabled:
            log_plugin.del_driver_log_handler(thread_id)


def add_task_file_handler(log_file=None):
    if log_file is None:
        return
    plugins = get_plugin(Plugin.LOG, LogType.tool)
    for log_plugin in plugins:
        if log_plugin.get_plugin_config().enabled:
            log_plugin.add_task_file_handler(log_file)


def remove_task_file_handler():
    plugins = get_plugin(Plugin.LOG, LogType.tool)
    for log_plugin in plugins:
        if log_plugin.get_plugin_config().enabled:
            log_plugin.remove_task_file_handler()


def add_encrypt_file_handler(log_file=None):
    if log_file is None:
        return
    plugins = get_plugin(Plugin.LOG, LogType.tool)
    for log_plugin in plugins:
        if log_plugin.get_plugin_config().enabled:
            log_plugin.add_encrypt_file_handler(log_file)


def remove_encrypt_file_handler():
    plugins = get_plugin(Plugin.LOG, LogType.tool)
    for log_plugin in plugins:
        if log_plugin.get_plugin_config().enabled:
            log_plugin.remove_encrypt_file_handler()


def _init_global_logger(name=None):
    handler = logging.StreamHandler(sys.stdout)
    log_format = \
        "[%(asctime)s] [%(thread)d] [%(name)s] [%(levelname)s] [%(message)s]"
    handler.setFormatter(logging.Formatter(log_format))
    log = FrameworkLog(name)
    log.platform_log.setLevel(logging.INFO)
    log.platform_log.addHandler(handler)
    return log


def change_logger_level(leve_dict):
    level_map = {"debug": logging.DEBUG, "info": logging.INFO}
    if "console" in leve_dict.keys():
        level = leve_dict["console"]
        if not level:
            return
        if str(level).lower() in level_map.keys():
            logger_level = level_map.get(str(level).lower(), logging.INFO)

            # change level of loggers which will to be instantiated.
            # Actually, it changes the level attribute in ToolLog,
            # which will be used when instantiating the FrameLog object.
            plugins = get_plugin(Plugin.LOG, LogType.tool)
            for log_plugin in plugins:
                log_plugin.set_level(logger_level)
            # change level of loggers which have instantiated
            for logger in _LOGGERS:
                if getattr(logger, "setLevel", None):
                    logger.setLevel(logger_level)
                elif getattr(logger, "set_level", None):
                    logger.set_level(logger_level)

    if "file" in leve_dict.keys():
        level = leve_dict["file"]
        if not level:
            return
        if str(level).lower() in level_map.keys():
            logger_level = level_map.get(str(level).lower(), logging.INFO)
            setattr(sys, "log_level", logger_level)


class EncryptFileHandler(RotatingFileHandler):

    def __init__(self, filename, mode='ab', max_bytes=0, backup_count=0,
                 encoding=None, delay=False):
        super().__init__(filename, mode, max_bytes, backup_count, encoding, delay)
        self.mode = mode
        self.encrypt_error = None

    def _open(self):
        if not self.mode == "ab":
            self.mode = "ab"

        # baseFilename is the attribute in FileHandler
        base_file_name = getattr(self, "baseFilename", None)
        return open(base_file_name, self.mode, encoding=self.encoding)

    def emit(self, record):
        try:
            if not self._encrypt_valid():
                return

            # shouldRoller and doRoller is the method in RotatingFileHandler
            should_rollover = getattr(self, "shouldRollover", None)
            if callable(should_rollover) and should_rollover(record):
                self.doRollover()

            # stream is the attribute in StreamHandler
            if not getattr(self, "stream", None):
                setattr(self, "stream", self._open())
            msg = self.format(record)
            stream = getattr(self, "stream", self._open())
            stream.write(msg)
            self.flush()
        except RecursionError as error:  # pylint:disable=undefined-variable
            raise error

    def _encrypt_valid(self):
        from _core.report.encrypt import check_pub_key_exist
        if check_pub_key_exist() and not self.encrypt_error:
            return True
        return False

    def format(self, record):
        """
        Customize the implementation method. If the log format of the
        framework changes, update the return value format of the method
        in a timely manner.
        :param record: logging.LogRecord
        :return: bytes
        """
        from _core.report.encrypt import do_rsa_encrypt
        create_time = "{},{}".format(
            time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(record.created)),
            "{:0>3d}".format(int("%d" % record.msecs)))
        name = record.name
        level_name = record.levelname
        msg = record.msg
        if msg and "%s" in msg:
            msg = msg % record.args
        info = "[%s] [%s] [%s] [%s] %s%s" \
               % (create_time, threading.current_thread().ident, name,
                  level_name, msg, "\n")

        try:
            return do_rsa_encrypt(info)
        except ParamError as error:
            error_no_str = \
                "ErrorNo={}".format(getattr(error, "error_no", "00113"))
            info = "[%s] [%s] [%s] [%s] [%s] [%s]\n" % (
                create_time, threading.current_thread().ident,
                name, "ERROR", error, error_no_str)
            self.encrypt_error = bytes(info, "utf-8")
            return self.encrypt_error


class LogQueue:
    log = None
    max_size = 0
    queue_debug = None
    queue_info = None

    def __init__(self, log, max_size=MAX_LOG_CACHE_SIZE):
        self.log = log
        self.max_size = max_size
        self.queue_info = queue.Queue(maxsize=self.max_size)
        self.queue_debug = queue.Queue(maxsize=self.max_size)
        self.queue_error = queue.Queue(maxsize=self.max_size)

    def _put(self, log_queue, log_data, clear):
        is_print = False
        result_data = ""
        if log_queue.full() or clear:
            # make sure the last one print
            if log_queue.qsize() > 0:
                is_print = True
                result_data = "{}\n".format(log_queue.get())
            else:
                result_data = ""
            if log_data != "":
                log_queue.put(log_data)
            while not log_queue.empty():
                is_print = True
                result_data = "{} [{}] {}\n".format(result_data, threading.current_thread().ident, log_queue.get())
        else:
            if log_data != "":
                log_queue.put(log_data)
        return is_print, result_data

    def info(self, log_data, clear=False):
        is_print, result_data = self._put(self.queue_info, log_data, clear)
        if is_print:
            self.log.info(result_data)

    def debug(self, log_data, clear=False):
        is_print, result_data = self._put(self.queue_debug, log_data, clear)
        if is_print:
            self.log.debug(result_data)

    def error(self, log_data, clear=False):
        is_print, result_data = self._put(self.queue_error, log_data, clear)
        if is_print:
            self.log.error(result_data)

    def clear(self):
        self.info(log_data="", clear=True)
        self.debug(log_data="", clear=True)
        self.error(log_data="", clear=True)
