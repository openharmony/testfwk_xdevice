#!/usr/bin/env python3
# coding=utf-8

#
# Copyright (c) 2022 Huawei Device Co., Ltd.
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

import copy
import os
import sys
import traceback
from typing import Union

from xdevice import calculate_elapsed_time
from xdevice import check_result_report
from xdevice import StateRecorder
from xdevice import LifeCycle
from xdevice import ResultCode
from xdevice import get_cst_time
from xdevice import platform_logger
from xdevice import EnvPool
from xdevice import CaseEnd
from xdevice import Binder

from devicetest.runner.prepare import PrepareHandler
from devicetest.core.constants import RunResult
from devicetest.utils.util import clean_sys_resource
from devicetest.utils.util import get_base_name
from devicetest.utils.util import get_dir_path
from devicetest.utils.util import import_from_file
from devicetest.core.variables import DeccVariable
from devicetest.core.variables import ProjectVariables
from devicetest.core.variables import CurCase
from devicetest.core.exception import DeviceTestError
from devicetest.core.test_case import DeviceRoot
from devicetest.core.test_case import BaseCase
from devicetest.error import ErrorMessage
from devicetest.log.logger import DeviceTestLog as Log
from devicetest.report.generation import add_log_caching_handler
from devicetest.report.generation import del_log_caching_handler
from devicetest.report.generation import get_caching_logs
from devicetest.report.generation import generate_report


class RunnerMode:
    PIPELINE = "pipeline"
    DEBUG = "debug"


class TestRunner:
    """executes test cases and
    """

    def __init__(self):
        self.run_mode = RunnerMode.PIPELINE
        self.run_list = None
        self.no_run_list = None
        self.running = None
        self.configs = None
        self.devices = None
        self.log = Log
        self.start_time = None
        self.test_results = None
        self.upload_result_handler = None
        self.project = None
        self.prepare = None
        self.cur_case = None
        self._repeat = 1
        self._repeat_round = 1

    def init_pipeline_runner(self, run_list, configs, devices, upload_result_handler):
        self.run_list = run_list
        self.no_run_list = copy.copy(self.run_list)
        self.running = False
        self.configs = configs
        self.devices = devices
        self.start_time = get_cst_time()
        self.test_results = []
        self.upload_result_handler = upload_result_handler
        self.project = ProjectVariables(self.log)
        self.prepare = None
        self.__init_project_variables()
        self.run_mode = RunnerMode.PIPELINE
        self._repeat = self.configs.get("request").config.repeat
        self._repeat_round = self.configs.get("request").get_repeat_round()

    def init_case_runner(self, run_list: Union[BaseCase, list]):
        # simple case runner
        self.run_list = run_list
        self.run_mode = RunnerMode.DEBUG
        self.log = platform_logger("TestRunner")

    def __init_project_variables(self):
        """
        testargs：为xDevice透传过来的数据,用户调用CONFIG可获取
        :return:
        """
        self.log.debug("configs:{}".format(self.configs))
        testcases_path = self.configs.get('testcases_path', "")
        testargs = self.configs.get("testargs", {})
        self.__flash_run_list(testargs)

        self.cur_case = CurCase(self.log)
        self.project.set_project_path()
        self.project.set_testcase_path(testcases_path)
        self.project.set_task_report_dir(self.configs.get("report_path"))
        self.project.set_resource_path(self.get_local_resource_path())

    def get_local_resource_path(self):
        local_resource_path = os.path.join(
            self.project.project_path, "testcases", "DeviceTest", "resource")
        return local_resource_path

    def get_local_aw_path(self):
        local_aw_path = os.path.join(
            self.project.project_path, "testcases", "DeviceTest", "aw")
        return local_aw_path

    def __flash_run_list(self, testargs):
        """
        retry 场景更新run list
        :param testargs:
        :return:
        """
        get_test = testargs.get("test")
        self.log.info("get test:{}".format(get_test))
        retry_test_list = self.parse_retry_test_list(get_test)
        if retry_test_list is not None:
            self.run_list = retry_test_list
            self.no_run_list = copy.copy(self.run_list)
            self.log.info("retry test list:{}".format(retry_test_list))

    def parse_retry_test_list(self, retry_test_list):
        if retry_test_list is None:
            return None
        elif not isinstance(retry_test_list, list):
            err_msg = ErrorMessage.TestCase.Code_0203005
            self.log.error(err_msg)
            raise DeviceTestError(err_msg)

        elif len(retry_test_list) == 1 and "#" not in str(retry_test_list[0]):
            return None
        else:
            history_case_list = []
            history_case_dict = dict()
            retry_case_list = []
            for abd_file_path in self.run_list:
                base_file_name = get_base_name(abd_file_path)
                if base_file_name not in history_case_dict.keys():
                    history_case_dict.update({base_file_name: []})
                history_case_dict.get(base_file_name).append(abd_file_path)
                history_case_list.append(base_file_name)
            self.log.debug("history case list:{}".format(history_case_list))

            for _value in retry_test_list:
                case_id = str(_value).split("#")[0]
                if case_id in history_case_dict.keys():
                    retry_case_list.append(history_case_dict.get(case_id)[0])
            return retry_case_list

    def parse_config(self, test_configs):
        pass

    def add_value_to_configs(self):
        self.configs["log"] = self.log
        self.configs["devices"] = self.devices
        self.configs["project"] = self.project

    def run(self):
        self._pipeline_run()

    def _pipeline_run(self):
        self.running = True
        aw_path = self.add_aw_path_to_sys(self.project.aw_path)
        self.log.info("Executing run list {}.".format(self.run_list))

        self.add_value_to_configs()

        self.prepare = PrepareHandler(self.log, self.cur_case,
                                      self.project, self.configs,
                                      self.devices, self.run_list)
        # **********混合root和非root**************
        try:
            for device in self.devices:
                if hasattr(device, "is_root"):
                    DeviceRoot.is_root_device = device.is_root
                    self.log.debug(DeviceRoot.is_root_device)
                    setattr(device, "is_device_root", DeviceRoot.is_root_device)

        except Exception as _:
            self.log.error('set branch api error.')
        # **************混合root和非root end**********************
        self.prepare.run_prepare()

        for test_cls_name in self.run_list:
            case_name = get_base_name(test_cls_name)
            if self.project.record.is_shutdown(raise_exception=False):
                break
            self.log.info("Executing test class {}".format(test_cls_name))
            self.project.execute_case_name = case_name
            self.run_test_class(test_cls_name, case_name)
        self.prepare.run_prepare(is_teardown=True)
        clean_sys_resource(file_path=aw_path)
        DeccVariable.reset()

    def add_aw_path_to_sys(self, aw_path):

        sys_aw_path = os.path.dirname(aw_path)
        if os.path.exists(sys_aw_path):
            sys.path.insert(1, sys_aw_path)
            self.log.info("add {} to sys path.".format(sys_aw_path))
            return sys_aw_path
        return None

    def run_test_class(self, case_path, case_name):
        """Instantiates and executes a test class.
        If the test cases list is not None, all the test cases in the test
        class should be executed.
        Args:
            case_path: case path
            case_name: case name
        Returns:
            A tuple, with the number of cases passed at index 0, and the total
            number of test cases at index 1.
        """
        # 开始收集日志
        case_log_buffer_hdl = add_log_caching_handler()

        tests = "__init__"
        case_result = RunResult.FAILED
        start_time = get_cst_time()
        case_dir_path = get_dir_path(case_path)
        test_cls_instance = None

        # 用例测试结果的拓展内容
        result_content = None
        try:
            self.project.cur_case_full_path = case_path
            DeccVariable.set_cur_case_obj(self.cur_case)
            test_cls = import_from_file(case_dir_path, case_name)
            self.log.info("Success to import {}.".format(case_name))
            with test_cls(self.configs) as test_cls_instance:
                self.cur_case.set_case_instance(test_cls_instance)
                test_cls_instance.run()

            tests = test_cls_instance.tests
            start_time = test_cls_instance.start_time

            case_result = test_cls_instance.result
            error_msg = test_cls_instance.error_msg
            result_content = getattr(test_cls_instance, "result_content", None)
        except ImportError as exception:
            error_msg = str(exception)
            self.log.error(error_msg)
            self.log.error(traceback.format_exc())
        except Exception as exception:
            error_msg = ErrorMessage.TestCase.Code_0203002.format(exception)
            self.log.error(error_msg)
            self.log.error(traceback.format_exc())
        if test_cls_instance:
            try:
                del test_cls_instance
                self.log.debug("del test_cls_instance success.")
            except Exception as exception:
                self.log.warning("del test_cls_instance exception. {}".format(exception))

        Binder.notify_stage(CaseEnd(case_name, case_result, error_msg))

        end_time = get_cst_time()
        environment = self.configs.get("request").config.environment
        steps = self.cur_case.get_steps_info()
        # 停止收集日志
        del_log_caching_handler(case_log_buffer_hdl)
        # 生成报告
        case_info = {
            "name": case_name,
            "result": case_result,
            "begin": start_time.strftime("%Y-%m-%d %H:%M:%S"),
            "end": end_time.strftime("%Y-%m-%d %H:%M:%S"),
            'elapsed': calculate_elapsed_time(start_time, end_time),
            "error": error_msg,
            "logs": "",
            "devices": [] if environment is None else environment.get_description(),
            "steps": steps
        }
        log_content = {
            "content": get_caching_logs(case_log_buffer_hdl)
        }
        round_folder = f"round{self._repeat_round}" if self._repeat > 1 else ""
        report_path = os.path.join("details", round_folder, case_name + ".html")
        to_file = os.path.join(self.project.task_report_dir, report_path)
        generate_report(to_file, case=case_info, logs=log_content)
        steps.clear()
        del case_log_buffer_hdl
        self.cur_case.set_case_instance(None)
        self.record_current_case_result(
            case_name, tests, case_result, start_time, error_msg, report_path,
            result_content=result_content)
        return case_result, error_msg

    def record_current_case_result(self, case_name, tests, case_result,
                                   start_time, error_msg, report, **kwargs):
        test_result = self.record_cls_result(
            case_name, tests, case_result, start_time, error_msg, report, **kwargs)
        self.log.debug("test result: {}".format(test_result))
        self.test_results.append(test_result)
        self.upload_result_handler.report_handler.test_results.append(test_result)

    def stop(self):
        """
        Releases resources from test run. Should be called right after run()
        finishes.
        """
        if self.running:
            self.running = False

    @staticmethod
    def record_cls_result(case_name, tests_step, result, start_time, error, report, **kwargs):
        dict_result = {
            "case_name": case_name,
            "tests_step": tests_step or "__init__",
            "result": result or RunResult.FAILED,
            "start_time": start_time or get_cst_time(),
            "error": error,
            "end_time": get_cst_time(),
            "report": report
        }
        dict_result.update(kwargs)
        return dict_result


class TestSuiteRunner:
    """
    executes test suite cases
    """

    def __init__(self, suite, configs, devices):
        self.suite = suite
        self.running = False
        self.configs = configs
        self.devices = devices
        self.log = Log
        self.start_time = get_cst_time()
        self.listeners = self.configs["listeners"]
        self.state_machine = StateRecorder()
        self.suite_name = ""

    def add_value_to_configs(self):
        self.configs["log"] = self.log
        self.configs["devices"] = self.devices
        self.configs["suite_name"] = self.suite_name

    def run(self):
        self.running = True
        self.log.info("Executing test suite: {}.".format(self.suite))

        self.suite_name = get_base_name(self.suite)
        self.add_value_to_configs()
        self.run_test_suite(self.suite)

    def run_test_suite(self, test_cls_name):
        """Instantiates and executes a test class.
        If the test cases list is not None, all the test cases in the test
        class should be executed.
        Args:
            test_cls_name: Name of the test class to execute.
        Returns:
            A tuple, with the number of cases passed at index 0, and the total
            number of test cases at index 1.
        """
        suite_dir_path = get_dir_path(test_cls_name)
        test_cls_instance = None
        self.handle_suites_started()
        self.handle_suite_started()
        try:
            test_cls = import_from_file(suite_dir_path, self.suite_name)
            self.log.info("Success to import {}.".format(self.suite_name))
            self.configs["cur_suite"] = test_cls
            with test_cls(self.configs, suite_dir_path) as test_cls_instance:
                test_cls_instance.run()

            error_msg = test_cls_instance.error_msg
            self.handle_suite_ended(test_cls_instance)
        except Exception as e:
            error_msg = ErrorMessage.TestCase.Code_0203017.format(e)
            self.log.error(error_msg)
            self.log.error(traceback.format_exc())
        self.handle_suites_ended(error_msg)
        result_path = os.path.join(self.configs["report_path"], "result")
        report_file = os.path.join(result_path, "%s.xml" % self.suite_name)
        os.makedirs(result_path, exist_ok=True)
        check_result_report("", report_file, error_message=error_msg)
        if test_cls_instance:
            try:
                del test_cls_instance
                self.log.debug("del test suite instance success.")
            except Exception as e:
                self.log.warning("del test suite instance exception. "
                                 "Exception: {}".format(e))
        return error_msg

    def stop(self):
        """
        Releases resources from test run. Should be called right after run()
        finishes.
        """
        if self.running:
            self.running = False

    def handle_suites_started(self):
        self.state_machine.get_suites(reset=True)
        test_suites = self.state_machine.get_suites()
        test_suites.suites_name = self.suite_name
        test_suites.test_num = 0
        for listener in self.listeners:
            suite_report = copy.copy(test_suites)
            listener.__started__(LifeCycle.TestSuites, suite_report)

    def handle_suites_ended(self, error_msg):
        suites = self.state_machine.get_suites()
        suites.is_completed = True
        suites.stacktrace = error_msg
        for listener in self.listeners:
            listener.__ended__(LifeCycle.TestSuites, suites)

    def handle_suite_started(self):
        self.state_machine.suite(reset=True)
        self.state_machine.running_test_index = 0
        test_suite = self.state_machine.suite()
        test_suite.suite_name = self.suite_name
        test_suite.test_num = 0
        for listener in self.listeners:
            suite_report = copy.copy(test_suite)
            listener.__started__(LifeCycle.TestSuite, suite_report)

    def handle_suite_ended(self, testsuite_cls):
        suite = self.state_machine.suite()
        suites = self.state_machine.get_suites()
        self.handle_one_case_result(testsuite_cls)
        suite.is_completed = True
        # 设置测试套的报告路径
        suite.report = testsuite_cls.suite_report_path
        for listener in self.listeners:
            listener.__ended__(LifeCycle.TestSuite, copy.copy(suite), is_clear=True)
        suites.run_time += suite.run_time

    def handle_one_case_result(self, testsuite_cls):
        status_dict = {RunResult.PASSED: ResultCode.PASSED,
                       RunResult.FAILED: ResultCode.FAILED,
                       RunResult.BLOCKED: ResultCode.BLOCKED,
                       "ignore": ResultCode.SKIPPED}
        for case_name, case_result in testsuite_cls.case_result.items():
            result = case_result.get("result")
            error = case_result.get("error")
            run_time = case_result.get("run_time")
            report = case_result.get("report")
            result_content = case_result.get("result_content")

            test_result = self.state_machine.test(reset=True)
            test_suite = self.state_machine.suite()
            test_result.test_class = test_suite.suite_name
            test_result.test_name = case_name
            test_result.code = status_dict.get(result).value
            test_result.stacktrace = error
            test_result.run_time = run_time
            test_result.report = report
            if result_content:
                test_result.result_content = result_content
            test_result.current = self.state_machine.running_test_index + 1

            self.state_machine.suite().run_time += run_time
            for listener in self.listeners:
                listener.__started__(
                    LifeCycle.TestCase, copy.copy(test_result))
            test_suites = self.state_machine.get_suites()
            test_suites.test_num += 1
            for listener in self.listeners:
                listener.__ended__(
                    LifeCycle.TestCase, copy.copy(test_result))
            self.state_machine.running_test_index += 1
