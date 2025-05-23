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

import os
import hashlib

from _core.constants import FilePermission
from _core.error import ErrorMessage
from _core.exception import ParamError
from _core.logger import platform_logger

__all__ = ["check_pub_key_exist", "do_rsa_encrypt", "do_rsa_decrypt",
           "generate_key_file", "get_file_summary"]

PUBLIC_KEY_FILE = "config/pub.key"
PRIVATE_KEY_FILE = "config/pri.key"
LOG = platform_logger("Encrypt")


def check_pub_key_exist():
    from xdevice import Variables
    if Variables.report_vars.pub_key_string:
        return Variables.report_vars.pub_key_string

    if Variables.report_vars.pub_key_file is not None:
        if Variables.report_vars.pub_key_file == "":
            return False
        if not os.path.exists(Variables.report_vars.pub_key_file):
            Variables.report_vars.pub_key_file = None
            return False
        return True

    pub_key_path = os.path.join(Variables.exec_dir, PUBLIC_KEY_FILE)
    if os.path.exists(pub_key_path):
        Variables.report_vars.pub_key_file = pub_key_path
        return True

    pub_key_path = os.path.join(Variables.top_dir, PUBLIC_KEY_FILE)
    if os.path.exists(pub_key_path):
        Variables.report_vars.pub_key_file = pub_key_path
    else:
        Variables.report_vars.pub_key_file = ""
    return Variables.report_vars.pub_key_file


def do_rsa_encrypt(content):
    try:
        if not check_pub_key_exist() or not content:
            return content

        plain_text = content
        if not isinstance(plain_text, bytes):
            plain_text = str(content).encode(encoding='utf-8')

        import rsa
        from xdevice import Variables
        if not Variables.report_vars.pub_key_string:
            with open(Variables.report_vars.pub_key_file,
                      'rb') as key_content:
                Variables.report_vars.pub_key_string = key_content.read()

        if isinstance(Variables.report_vars.pub_key_string, str):
            Variables.report_vars.pub_key_string =\
                bytes(Variables.report_vars.pub_key_string, "utf-8")

        public_key = rsa.PublicKey.load_pkcs1_openssl_pem(
            Variables.report_vars.pub_key_string)

        max_encrypt_len = int(public_key.n.bit_length() / 8) - 11

        # encrypt
        cipher_text = b""
        for frag in _get_frags(plain_text, max_encrypt_len):
            cipher_text_frag = rsa.encrypt(frag, public_key)
            cipher_text += cipher_text_frag
        return cipher_text

    except (ModuleNotFoundError, ValueError, TypeError) as error:
        raise ParamError(ErrorMessage.Common.Code_0101025.format(error.args[0])) from error


def do_rsa_decrypt(content):
    try:
        if not check_pub_key_exist() or not content:
            return content

        cipher_text = content
        if not isinstance(cipher_text, bytes):
            cipher_text = str(content).encode()

        import rsa
        from xdevice import Variables
        pri_key_path = os.path.join(Variables.exec_dir, PRIVATE_KEY_FILE)
        if os.path.exists(pri_key_path):
            pri_key_file = pri_key_path
        else:
            pri_key_file = os.path.join(Variables.top_dir, PRIVATE_KEY_FILE)
        if not os.path.exists(pri_key_file):
            return content
        with open(pri_key_file, "rb") as key_content:
            # get params
            pri_key = rsa.PrivateKey.load_pkcs1(key_content.read())
            max_decrypt_len = int(pri_key.n.bit_length() / 8)

            try:
                # decrypt
                plain_text = b""
                for frag in _get_frags(cipher_text, max_decrypt_len):
                    plain_text_frag = rsa.decrypt(frag, pri_key)
                    plain_text += plain_text_frag
                return plain_text.decode(encoding='utf-8')
            except rsa.pkcs1.CryptoError as error:
                error_msg = ErrorMessage.Common.Code_0101026.format(error.args[0])
                LOG.error(error_msg)
                return error_msg

    except (ModuleNotFoundError, ValueError, TypeError) as error:
        error_msg = ErrorMessage.Common.Code_0101026.format(error.args[0])
        LOG.error(error_msg)
        return error_msg


def generate_key_file(length=2048):
    try:
        from rsa import key

        if int(length) not in [1024, 2048, 3072, 4096]:
            LOG.error("Length should be 1024, 2048, 3072 or 4096")
            return

        pub_key, pri_key = key.newkeys(int(length))
        pub_key_pem = pub_key.save_pkcs1().decode()
        pri_key_pem = pri_key.save_pkcs1().decode()

        file_pri_open = os.open("pri.key", os.O_WRONLY | os.O_CREAT |
                                os.O_APPEND, FilePermission.mode_755)
        file_pub_open = os.open("pub.key", os.O_WRONLY | os.O_CREAT |
                                os.O_APPEND, FilePermission.mode_755)
        with os.fdopen(file_pri_open, "w") as file_pri, \
                os.fdopen(file_pub_open, "w") as file_pub:
            file_pri.write(pri_key_pem)
            file_pri.flush()
            file_pub.write(pub_key_pem)
            file_pub.flush()
    except ModuleNotFoundError as _:
        return


def get_file_summary(src_file, algorithm="sha256", buffer_size=100 * 1024):
    if not os.path.exists(src_file):
        LOG.error("File '%s' not exists!" % src_file)
        return ""

    # if the size of file is large, use this function
    def _read_file(_src_file):
        while True:
            _data = _src_file.read(buffer_size)
            if not _data:
                break
            yield _data

    if hasattr(hashlib, algorithm):
        algorithm_object = hashlib.new(algorithm)
        try:
            with open(file=src_file, mode="rb") as _file:
                for data in _read_file(_file):
                    algorithm_object.update(data)
        except ValueError as error:
            LOG.error("Read data from '%s' error: %s " % (
                src_file, error.args))
            return ""
        return algorithm_object.hexdigest()
    else:
        LOG.error("The algorithm '%s' not in hashlib!" % algorithm)
        return ""


def _get_frags(text, max_len):
    _text = text
    while _text:
        if len(_text) > max_len:
            frag, _text = _text[:max_len], _text[max_len:]
        else:
            frag, _text = _text, ""
        yield frag
