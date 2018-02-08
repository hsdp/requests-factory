from unittest import TestCase
from requests_factory import MIME_JSON, MIME_FORM
from requests_factory import RequestMixin, Request, Response, RequestFactory


class CustomRequest(Request):
    pass


class CustomResponse(Response):
    pass


def my_callback(req, req_args, args1, arg2=None):
        pass


expected_callback = (my_callback, ('abc',), {'arg2': 123})


class TestRequestMixin(TestCase):
    def setUp(self):
        self.req = RequestMixin()

    def test_set_content_type_form_urlencoded(self):
        req = self.req.form_urlencoded()
        self.assertIsInstance(req, RequestMixin)
        self.assertIn('content-type', req.headers)
        self.assertEqual(req.headers['content-type'], MIME_FORM)

    def test_set_content_type_application_json(self):
        req = self.req.application_json()
        self.assertIsInstance(req, RequestMixin)
        self.assertIn('content-type', req.headers)
        self.assertEqual(req.headers['content-type'], MIME_JSON)

    def test_set_accept_json(self):
        req = self.req.accept_json()
        self.assertIsInstance(req, RequestMixin)
        self.assertIn('accept', req.headers)
        self.assertEqual(req.headers['accept'], MIME_JSON)

    def test_set_custom_requests_args(self):
        req = self.req.set_custom_requests_args(verify=False)
        self.assertIsInstance(req, RequestMixin)
        self.assertIn('verify', req.custom_requests_args)
        self.assertEqual(req.custom_requests_args['verify'], False)

    def test_set_verify_ssl(self):
        req = self.req.set_verify_ssl(False)
        self.assertIsInstance(req, RequestMixin)
        self.assertEqual(req.verify_ssl, False)

    def test_set_basic_auth(self):
        req = self.req.set_basic_auth('abc', '123')
        self.assertIsInstance(req, RequestMixin)
        self.assertIn('authorization', req.headers)
        self.assertEqual('Basic YWJjOjEyMw==', self.req.headers['authorization'])

    def test_set_bearer_auth(self):
        req = self.req.set_bearer_auth('value')
        self.assertIsInstance(req, RequestMixin)
        self.assertIn('authorization', req.headers)
        self.assertEqual('bearer value', self.req.headers['authorization'])

    def test_set_auth(self):
        req = self.req.set_auth('bearer value')
        self.assertIsInstance(req, RequestMixin)
        self.assertIn('authorization', req.headers)
        self.assertEqual('bearer value', self.req.headers['authorization'])

    def test_set_header(self):
        req = self.req.set_header('X-ABC', '123')
        self.assertIsInstance(req, RequestMixin)
        self.assertIn('x-abc', req.headers)
        self.assertEqual('123', req.headers['x-abc'])

    def test_set_base_url(self):
        req = self.req.set_base_url('http://localhost/')
        self.assertIsInstance(req, RequestMixin)
        self.assertEqual('http://localhost', req.base_url)

    def test_set_response_class(self):
        req = self.req.set_response_class(CustomResponse)
        self.assertIsInstance(req, RequestMixin)
        self.assertEqual(req.response_class, CustomResponse)

    def test_set_callback(self):
        req = self.req.set_callback(my_callback, 'abc', arg2=123)
        self.assertIsInstance(req, RequestMixin)
        self.assertTupleEqual(expected_callback, req.callback)

    def test_get_url(self):
        req = self.req.set_base_url('http://localhost/')
        url = req.get_url('')
        self.assertEqual('http://localhost/', url)
        url = req.get_url('abc')
        self.assertEqual('http://localhost/abc', url)

    def test_add_url(self):
        req = self.req.set_base_url('http://localhost/')
        req = req.add_url('/abc/')
        self.assertIsInstance(req, RequestMixin)
        url = req.get_url('/def')
        self.assertEqual('http://localhost/abc/def', url)
        url = req.get_url('/123')
        self.assertEqual('http://localhost/abc/123', url)


class TestRequestFactory(TestCase):
    def setUp(self):
        self.fact = RequestFactory().set_base_url('http://localhost/')

    def test_request(self):
        req = self.fact.request('foo', 'bar')
        self.assertIsInstance(req, Request)
        self.assertEqual('http://localhost/foo/bar/abc/def', req.get_url('abc/def'))
        self.assertEqual('http://localhost/foo/bar/abc/123', req.get_url('abc/123'))

    def test_set_request_class(self):
        fact = self.fact.set_request_class(CustomRequest)
        self.assertIsInstance(fact, RequestFactory)
        self.assertEqual(fact.request_class, CustomRequest)
        req = fact.request('abc')
        self.assertIsInstance(req, CustomRequest)

class TestRequest(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.fact = RequestFactory()\
                .set_base_url('http://localhost/')\
                .set_verify_ssl(False)\
                .set_response_class(CustomResponse)\
                .set_request_class(CustomRequest)\
                .set_basic_auth('abc', '123')\
                .set_custom_requests_args(allow_redirects=False)\
                .set_callback(my_callback, 'abc', arg2=123)

    def setUp(self):
        self.req = self.fact.request('abc')

    def test_init(self):
        self.assertIsInstance(self.req, CustomRequest)
        self.assertTupleEqual(expected_callback, self.req.callback)
        self.assertEqual('http://localhost/abc', self.req.base_url)
        self.assertEqual(self.req.verify_ssl, False)
        self.assertEqual(self.req.headers['authorization'], 'Basic YWJjOjEyMw==')
        self.assertEqual(self.req.response_class, self.fact.response_class)
        self.assertDictEqual(self.req.custom_requests_args, {'allow_redirects': False})

    def test_set_method(self):
        req = self.req.set_method('GET')
        self.assertIsInstance(req, Request)
        self.assertEqual(req.method, 'GET')

    def test_set_params(self):
        data = {'abc': 123}
        req = self.req.set_params(data)
        self.assertIsInstance(req, Request)
        self.assertDictEqual(data, self.req.params)
        self.req.set_params(**data)
        self.assertDictEqual(data, self.req.params)

    def test_set_query(self):
        qtup = [('q', '1'), ('q', '2')]
        qdic = {'q1': '1', 'q2': '2'}
        expected = [('q', '1'), ('q', '2'), ('q1', '1'), ('q2', '2')]
        req = self.req.set_query(*qtup, **qdic)
        self.assertIsInstance(req, Request)
        self.assertEqual(req.query, expected)

    def test_param(self):
        data = {'abc': 123}
        req = self.req.set_params(data)
        self.assertEqual(req.params['abc'], 123)
        req.param('abc', 'def')
        self.assertEqual(req.params['abc'], 'def')

    def test_add_field(self):
        self.req.add_field('abc', '123')
        self.assertTupleEqual(self.req.multipart_files['abc'], (None, '123'))

    def test_add_file(self):
        fh = object()
        self.req.add_file('abc', 'abc.txt', fh, 'text/plain')
        self.assertTupleEqual(self.req.multipart_files['abc'], ('abc.txt', fh, 'text/plain'))

    def test_get_requests_args(self):
        func, url, kwargs = self.req.get_requests_args()
        self.assertEqual(self.req.session.get, func)
        self.assertEqual(url, 'http://localhost/abc')
        self.assertDictEqual(kwargs, {
            'allow_redirects': False,
            'headers': {'authorization': 'Basic YWJjOjEyMw=='},
            'verify': False,
            'data': {}})
