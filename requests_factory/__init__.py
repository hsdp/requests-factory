from __future__ import print_function
import os
import re
import json
import ssl
import gevent
import requests
import websocket
import threading
from base64 import b64encode
from requests_toolbelt.multipart import decoder as multipart_decoder

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

try:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
except ImportError:
    from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


MIME_FORM = 'application/x-www-form-urlencoded'
MIME_JSON = 'application/json'


def _print_deprecated_message(from_name, to_name):
    print('{0} is deprecated. Please migrate to {1}'
          .format(from_name, to_name))


def _get_default_var(val, env):
    return os.getenv(env) if val is None else val


class RequestMixin(object):
    """Base class for Request and RequestFactory
    """

    headers = None
    verify_ssl = None
    base_url = None
    response_class = None
    callback = None
    custom_requests_args = None

    def __init__(self):
        self.headers = {}
        self.custom_requests_args = {}
        self.verify_ssl = True
        self.response_class = Response

    def form_urlencoded(self):
        """Sets the Content-Type to application/x-www-form-urlencoded

        Returns:
            RequestMixin
        """
        return self.set_header('Content-Type', MIME_FORM)

    def application_json(self):
        """Sets the Content-Type to application/json

        Returns:
            RequestMixin
        """
        return self.set_header('Content-Type', MIME_JSON)

    def accept_json(self):
        """Sets the Accepted response type to application/json

        Returns:
            RequestMixin
        """
        return self.set_header('Accept', MIME_JSON)

    def set_custom_requests_args(self, **kwargs):
        for k, v in kwargs.items():
            if isinstance(v, dict):
                self.custom_requests_args[k].update(v)
            elif isinstance(v, (list, tuple)):
                self.custom_requests_args[k] = [i for i in v]
            else:
                self.custom_requests_args[k] = v
        return self

    def set_validate_ssl(self, validate):
        """Sets a flag on whether to validate SSL

        Returns:
            RequestMixin
        """
        _print_deprecated_message('set_validate_ssl()', 'set_verify_ssl()')
        return self.set_verify_ssl(validate)

    def set_verify_ssl(self, verify):
        """Sets a flag on whether to verify SSL

        Returns:
            RequestMixin
        """
        self.verify_ssl = verify
        return self

    def set_basic_auth(self, username, password):
        """Encodes the username and password in Basic format and sets the
        Authorization header

        Returns:
            RequestMixin
        """
        return self.set_auth('Basic ' + b64encode(
            bytearray(':'.join([username, password]), encoding='utf-8')
        ).decode('utf-8'))

    def set_bearer_auth(self, value):
        """Sets the value in the Authorization in Bearer auth format

        Returns:
            RequestMixin
        """
        return self.set_auth(' '.join(['bearer', value]))

    def set_auth(self, value):
        """Sets the Authorization header

        Returns:
            RequestMixin
        """
        return self.set_header('Authorization', value)

    def set_header(self, name, value):
        """Sets the header name and value

        Returns:
            RequestMixin
        """
        self.headers[name.lower()] = value
        return self

    def get_header(self, name):
        """Gets the header with the given name, if it is set, else returns None

        Returns:
            object|None
        """
        for n, v in self.headers.items():
            if n.lower() == name.lower():
                return v
        return None

    def set_base_url(self, url):
        """Sets the base url for this request or factory

        Returns:
            RequestMixin
        """
        self.base_url = re.sub('/$', '', url)
        return self

    def set_response_class(self, response_class):
        """Sets the function or class that will wrap the response of this
        request

        Returns:
            RequestMixin
        """
        self.response_class = response_class
        return self

    def set_callback(self, callback, *args, **kwargs):
        """This method sets an internal callback that is invoked on every request

        Args:
            callback (callable): required function receiving args
                (req, req_args, *args, **kwargs)
            args: optional list of args to be passed to the callback

        Keyword Args:
            kwargs: optional dict of args to be passed to the callback

        Returns:
            self (RequestMixin)
        """
        self.callback = (callback, args, kwargs)
        return self

    def get_url(self, url):
        """Gets the given url with the base url prepended

        Returns:
            str
        """
        if not self.base_url:
            return url
        url = re.sub('^/', '', url)
        return '/'.join([self.base_url, url])

    def add_url(self, first, *url):
        """This appends the first url and any additional url segments to the
        base url

        Arguments:
            first: str - required url segment
            url: list - optional additional url segments

        Returns:
            RequestMixin
        """
        first = re.sub('(^/|/$)', '', first)
        url = [re.sub('(^/|/$)', '', u) for u in url]
        return self.set_base_url('/'.join(['/'.join([self.base_url, first]),
                                           '/'.join(url)]))


class RequestFactory(RequestMixin):
    """This is a base class that may be used to template request settings. For
    example, you can set the authorization on the factory and then create
    requests that clone the credentials (see self.requests()).
    """
    request_class = None

    def __init__(self):
        super(RequestFactory, self).__init__()
        self.request_class = Request

    def request(self, url, *urls):
        """Creates a request and appends the the given url(s)

        Returns:
            (Request)
        """
        req = self.request_class(self).add_url(url, *urls)
        return req

    def set_request_class(self, request_class):
        """Sets the request class or function used to create new request
        instances

        Returns:
            RequestFactory
        """
        self.request_class = request_class
        return self


class Request(RequestMixin):
    """Base class that builds and executes HTTP requests.
    """

    method = 'GET'
    params = None
    query = None
    res = None
    multipart_files = None

    def __init__(self, factory=None):
        super(Request, self).__init__()
        self.session = requests.Session()
        self.headers = {}
        self.params = {}
        self.query = []
        self.multipart_files = {}
        if isinstance(factory, RequestFactory):
            self.callback = factory.callback
            self.base_url = factory.base_url
            self.verify_ssl = factory.verify_ssl
            self.response_class = factory.response_class
            self.headers.update(factory.headers)
            self.set_custom_requests_args(**factory.custom_requests_args)

    def __repr__(self):
        method_func, url, kwargs = self.get_requests_args()

        if 'data' not in kwargs:
            body_components = ''
        else:
            if isinstance(kwargs['data'], dict):
                body_components = ''.join([
                    'dict(', ', '.join(kwargs['data'].keys()), ')'])
            elif hasattr(kwargs['data'], '__len__'):
                t = type(kwargs['data'])
                body_components = ''.join([
                    '.'.join([t.__module__, t.__name__]),
                    '(', str(len(kwargs['data'])), ')'
                ])
            else:
                body_components = type(kwargs['data']).__name__
            body_components = ''.join([
                ' [body: ', body_components, ']'])

        if 'headers' in kwargs and len(kwargs['headers']) > 0:
            header_components = ''.join([
                ' [headers: ', ', '.join(kwargs['headers'].keys()), ']'])
        else:
            header_components = ''

        return ''.join([
            '<', self.__class__.__name__, ' ',
            method_func.__name__.upper(), ' ', url,
            header_components,
            body_components, '>'
        ])

    def set_method(self, method):
        """Sets the request method

        Returns:
            Request
        """
        self.method = method
        return self

    def set_params(self, *single, **params):
        """Sets the body params

        Arguments:
            single (list): if len() >= 1 then only the first argument is set as
                the body

        Keyword Args:
            params (dict): sets this as the body directly

        Returns:
            Request
        """
        if len(single) > 0:
            self.params = single[0]
        else:
            self.params = params
        return self

    def set_query(self, *qlist, **qdict):
        """Sets the URL query parameters.

        Keyword Args:
            *qlist (tuple[tuple]): changes the query to a tuple list to allow
                multiple of the same query parameter name
            **qdict (dict): updates the query parameters with the dict params

        Returns:
            Request
        """
        self.query = list(qlist)
        for n, v in qdict.items():
            self.query.append((n, v))
        return self

    def param(self, name, value):
        """Sets the body param with name and value

        Returns:
            Request
        """
        self.params[name] = value
        return self

    def get(self):
        """Sets and executes an HTTP GET request

        Returns:
            Response: instance of response class wrapping the response
        """
        return self.set_method('GET').send()

    def put(self):
        """Sets and executes an HTTP PUT request

        Returns:
            Response: instance of response class wrapping the response
        """
        return self.set_method('PUT').send()

    def post(self):
        """Sets and executes an HTTP POST request

        Returns:
            Response: instance of response class wrapping the response
        """
        return self.set_method('POST').send()

    def delete(self):
        """Sets and executes an HTTP DELETE request

        Returns:
            Response: instance of response class wrapping the response
        """
        return self.set_method('DELETE').send()

    def patch(self):
        """Sets and executes an HTTP PATCH request

        Returns:
            Response: instance of response class wrapping the response
        """
        return self.set_method('PATCH').send()

    def add_field(self, name, value):
        """Adds a multipart/form-data field to this request

        Returns:
            Request
        """
        self.multipart_files[name] = (None, value)
        return self

    def add_file(self, fieldname, filename, file_handle, mimetype=None):
        """Adds a multipart/form-data file to this request

        Returns:
            Request
        """
        self.multipart_files[fieldname] = (filename, file_handle, mimetype)
        return self

    def get_requests_args(self):
        """Gets all the arguments required to send a request with requests lib

        Returns:
            tuple(requests_method_func, url, requests_kwargs)
        """
        url = self.base_url
        if len(self.query):
            url += '?' + urlencode(self.query)

        method = self.method.lower()
        method_func = getattr(self.session, method)

        kwargs = {}
        kwargs.update(self.custom_requests_args)
        kwargs.update(
            headers=self.headers,
            verify=self.verify_ssl,
        )
        if len(self.multipart_files):
            kwargs['files'] = self.multipart_files
            if 'content-type' in kwargs['headers']:
                del kwargs['headers']['content-type']
        elif 'content-type' in self.headers and \
                self.headers['content-type'].startswith('application/json'):
            kwargs['json'] = self.params
        else:
            kwargs['data'] = self.params

        return method_func, url, kwargs

    def send(self):
        """Executes this request

        Returns:
            Response: response class instance wrapping the response
        """

        if isinstance(self.callback, (list, tuple)):
            cb = self.callback
            cb[0](self, *cb[1], **cb[2])

        method_func, url, kwargs = self.get_requests_args()
        res = method_func(url, **kwargs)

        self.res = self.response_class(res)
        return self.res


class WebSocket(object):
    """Simple wrapper class for executing and monitoring WebSocket requests
    """
    def __init__(self, url, verify_ssl=True, **headers):
        self._end_watch = threading.Event()
        self.ws = None
        self.url = url
        self.verify_ssl = verify_ssl
        self.headers = []
        for name, value in headers.items():
            self.set_header(name, value)

    def set_verify_ssl(self, verify):
        """Indicates whether to verify SSL certs

        Args:
            verify (bool)

        Returns:
            self (WebSocket)
        """
        self.verify_ssl = verify
        return self

    def set_header(self, name, value):
        """Sets an initialization header for the websocket request

        Args:
            name (str):
            value (str):

        Returns:
            self (WebSocket)
        """
        self.headers.append(': '.join([name, value]))
        return self

    def connect(self):
        """Creates the websocket and connects

        Returns:
            self (WebSocket)
        """
        ws_kwargs = {}
        if not self.verify_ssl:
            ws_kwargs.update(sslopt=dict(cert_reqs=ssl.CERT_NONE))
        self.ws = websocket.WebSocket(**ws_kwargs)
        self.ws.connect(self.url, header=self.headers)
        return self

    def close(self):
        """Closes the internal websocket instance
        """
        self._end_watch.set()
        self.ws.close()

    def watch(self, onmessage=None):
        """Runs a simple function to monitor the websocket
        """
        if not self.ws:
            raise InvalidStateException('websocket is not connected', 500)
        ws = self.ws

        def watch():
            while True and not self._end_watch.is_set():
                try:
                    m = ws.recv()
                    if m is not None and callable(onmessage):
                        onmessage(m)
                except:
                    if not self._end_watch.is_set():
                        raise

        greenlets = [
            gevent.spawn(watch)
        ]
        gevent.joinall(greenlets)


class Response(object):
    """HTTP Response base wrapper class that provides general utilities for
    checking errors and parsing JSON responses.
    """
    success_codes = [200, 201, 202, 204]

    def __init__(self, response):
        self._response = response
        self._response_text = response.content
        self._response_parsed = None
        try:
            if response.content:
                self._response_parsed = json.loads(response.content)
            else:
                self._response_parsed = {}
        except ValueError as e:
            if response.status_code not in self.success_codes:
                print(e)

    def raise_error(self):
        """Shortcut to raise an exception using the response text
        """
        raise ResponseException(self._response_text,
                                self._response.status_code)

    def raise_for_status(self):
        """Shortcut to raise an exception if the status code is not 2xx
        """
        if self.has_error:
            self.raise_error()

    @property
    def is_json(self):
        return 'application/json' in self.headers.get('Content-Type', '')

    @property
    def has_error(self):
        """Checks if status code is not in 200 range

        Returns:
            bool
        """
        return self._response.status_code not in self.success_codes

    @property
    def is_not_found(self):
        """Checks if status code is 404

        Returns:
            bool
        """
        return 404 == self._response.status_code

    @property
    def headers(self):
        """Returns the response headers

        Returns:
            dict
        """
        return self._response.headers

    @property
    def data(self):
        """Checks and throws if there's an error else returns the body as parsed JSON

        Returns:
            dict
        """
        if self.has_error:
            return self.raise_error()
        return self._response_parsed

    @property
    def response(self):
        """Underlying response object
        """
        return self._response

    @property
    def text(self):
        """Returns the response text

        Returns:
            str
        """
        return self._response_text

    @property
    def multipart(self):
        items = multipart_decoder.MultipartDecoder.from_response(
            self._response)
        return [part.content for part in items.parts]

    @property
    def raw_data(self):
        """Returns the response as parsed JSON without checking for errors

        Returns:
            dict
        """
        return self._response_parsed or {}


class APIException(Exception):
    """Base class of all exceptions used in this library
    """
    def __init__(self, message, status_hint):
        super(APIException, self).__init__(message)
        self.code = status_hint
        self.description = message


class InvalidStateException(APIException):
    """Indicates that the library object is in an invalid state
    """
    pass


class ResponseException(APIException):
    """Indicates an unsuccessful HTTP Response from a Cloud Foundry component
    (i.e. the Cloud Controller, UAA, Doppler, etc)
    """

    error_code = None

    def __init__(self, message, status_hint):
        super(ResponseException, self).__init__(message, status_hint)
        try:
            self.raw_response = message
            parsed = json.loads(message)
            error_code = parsed.get('error_code',
                                    parsed.get('error', 'unknown'))
            description = parsed.get('error_description',
                                     parsed.get('description', 'unknown'))
            self.error_code = error_code
            self.description = ': '.join([self.error_code, description])
        except ValueError:
            pass
