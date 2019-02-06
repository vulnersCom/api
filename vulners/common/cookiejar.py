# -*- coding: utf-8 -*-
# ===============================
#  Persistent cookie jar for Requests by Kir Ermakov <isox@vulners.com>
#  It holds cookies in temp file after process stops. And recovers on process start.
#  Just like browsers!
#
#  Usage:
#
#  import requests
#
#  opener = requests.session()
#  opener.cookies = PersistentCookieJar()
#  opener.get("url")
#
#
#
#
# ===============================

from requests.cookies import RequestsCookieJar
import platform
import tempfile
import json
import six
import codecs
import os
import warnings
import sys
import hashlib



class PersistentCookieJar(RequestsCookieJar):
    """
        This Cookie Jar is designed to hold persistent cookies using temp dir.
    """

    def __init__(self, file_path = None, *args, **kwargs):
        """
        Additional parameter - file path location, that can be changed.
        It will hold session data there.

        :param file_path: String, expected full path with filename. If NONE is set, it will we be created dynamically.

        """
        super(PersistentCookieJar, self).__init__(*args, **kwargs)

        self.__file_path = file_path or os.path.join(self.__get_temp_dir(), self.__get_module_name())

        # Try to recover from file if it does exist
        recover_candidate = self.__recover_from_file(self.__file_path)
        if recover_candidate:
            self.update(recover_candidate)
            self.__write_down()

    def __get_temp_dir(self):
        """
        Internal method for capturing location of the temp path.
        For MacOS it's hardcoded to use /tmp
        :return: string, OS tmp path
        """
        return '/tmp' if platform.system() == 'Darwin' else tempfile.gettempdir()

    def __get_module_name(self):
        """
        Internal method for gathering Python module name. We need it to make some difference for cookie jars created by separate projects.
        We are taking sys __main__, it's file name and then takes a hash from it.
        :return: string, Python module name
        """
        keyword = six.text_type(sys.modules['__main__'].__file__ if hasattr(sys.modules['__main__'], '__file__') else 'console')
        path_hash = hashlib.sha1(keyword.encode('utf-8')).hexdigest()
        return "%s.cookiejar" % path_hash


    def __write_down(self):
        """
        Internal method for tearing data to disk.
        :return: None
        """
        with open(self.__file_path, 'wb') as cookie_file:
            cookie_file.write(codecs.encode(six.text_type(json.dumps(self.get_dict())).encode(), "base64"))

    def __recover_from_file(self, file_path):
        """
        Recovers self state object from the file. If something fails it will return none and writes down warning
        :param file_path: State file location
        :return: recovered PersistentCookieJar object
        """
        if not os.path.exists(file_path):
            # If it does not exists it's not actually a problem, we will just create a new one
            return None

        if not os.path.isfile(file_path):
            warnings.warn("%s file path %s is not a file" % (self.__class__.__name__, file_path))
            return None

        if not os.access(file_path, os.R_OK):
            warnings.warn("%s file path %s can not be read" % (self.__class__.__name__, file_path))
            return None

        with open(file_path, "rb") as cookie_file:
            try:
                cookie_jar = json.loads(codecs.decode(cookie_file.read(), "base64"))
                if not isinstance(cookie_jar, dict):
                    warnings.warn("%s recovered object, but it do mismatch with self class. Recovered type is %s" % (self.__class__.__name__, type(cookie_jar)))
                    return None
                return cookie_jar
            except Exception as exc:
                warnings.warn("%s failed to recover session from %s with error %s" % (self.__class__.__name__, file_path, exc))
                return None

    def set_cookie(self, cookie, *args, **kwargs):
        """
        This method is used to find the good moment for tearing down to the disk and save Jar state.
        On any modification it will save json object state to the disk
        """
        self.__write_down()
        return super(PersistentCookieJar, self).set_cookie(cookie, *args, **kwargs)
