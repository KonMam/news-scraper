from main import ArticleList, NewsScraper, Article
import requests
from bs4 import ResultSet



scraper = NewsScraper()

def test_et_response():
    # maybe should only pass page, and URL should be local
    assert type(scraper._get_response(page="vz")) == requests.Response
    assert type(scraper._get_response(page="15min")) == requests.Response
    assert type(scraper._get_response(page="delfi")) == requests.Response
    
    # when url type not in URL list
    assert type(scraper._get_response(page="dsfai")) == IndexError


def test_get_articles_in_page():
    # Test VZ
    r = scraper._get_response(page="vz")
    assert type(scraper._get_articles_in_page(r=r)) == ResultSet
    # Test 15min
    r = scraper._get_response(page="15min")
    assert type(scraper._get_articles_in_page(r=r)) == ResultSet
    # Test delfi
    r = scraper._get_response(page="delfi")
    assert type(scraper._get_articles_in_page(r=r)) == ResultSet


def test_get_article_details():
    r = scraper._get_response(page="vz")
    articles =scraper._get_articles_in_page(r)
    data =scraper._get_article_details(article=articles[0])

    assert type(data['title']) == str
    assert type(data['href']) == str


def test_get_news_articles_json():
    scraper = NewsScraper()
    scraper.get_news_articles_json(path='./results.json', page='vz', number=1)

    assert len(scraper.data) == 1
    assert len(scraper.data[0]) == 2
    assert scraper.data.keys() == ['title', 'href']

============================= test session starts =============================
platform win32 -- Python 3.10.2, pytest-7.2.0, pluggy-1.0.0
rootdir: C:\Users\mamonask\news-scraper
plugins: anyio-3.5.0
collected 6 items

test_classes.py ..                                                       [ 33%]
test_main.py FFFF                                                        [100%]

================================== FAILURES ===================================
______________________________ test_et_response _______________________________

self = <urllib3.connectionpool.HTTPSConnectionPool object at 0x0000028D06364910>
method = 'GET', url = '/visos-naujienos?pageno=0', body = None
headers = {'User-Agent': 'python-requests/2.27.1', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Connection': 'keep-alive'}
retries = Retry(total=0, connect=None, read=False, redirect=None, status=None)
redirect = False, assert_same_host = False
timeout = Timeout(connect=None, read=None, total=None), pool_timeout = None
release_conn = False, chunked = False, body_pos = None
response_kw = {'decode_content': False, 'preload_content': False}
parsed_url = Url(scheme=None, auth=None, host=None, port=None, path='/visos-naujienos', query='pageno=0', fragment=None)
destination_scheme = None, conn = None, release_this_conn = True
http_tunnel_required = False, err = None, clean_exit = False

    def urlopen(
        self,
        method,
        url,
        body=None,
        headers=None,
        retries=None,
        redirect=True,
        assert_same_host=True,
        timeout=_Default,
        pool_timeout=None,
        release_conn=None,
        chunked=False,
        body_pos=None,
        **response_kw
    ):
        """
        Get a connection from the pool and perform an HTTP request. This is the
        lowest level call for making a request, so you'll need to specify all
        the raw details.
    
        .. note::
    
           More commonly, it's appropriate to use a convenience method provided
           by :class:`.RequestMethods`, such as :meth:`request`.
    
        .. note::
    
           `release_conn` will only behave as expected if
           `preload_content=False` because we want to make
           `preload_content=False` the default behaviour someday soon without
           breaking backwards compatibility.
    
        :param method:
            HTTP request method (such as GET, POST, PUT, etc.)
    
        :param url:
            The URL to perform the request on.
    
        :param body:
            Data to send in the request body, either :class:`str`, :class:`bytes`,
            an iterable of :class:`str`/:class:`bytes`, or a file-like object.
    
        :param headers:
            Dictionary of custom headers to send, such as User-Agent,
            If-None-Match, etc. If None, pool headers are used. If provided,
            these headers completely replace any pool-specific headers.
    
        :param retries:
            Configure the number of retries to allow before raising a
            :class:`~urllib3.exceptions.MaxRetryError` exception.
    
            Pass ``None`` to retry until you receive a response. Pass a
            :class:`~urllib3.util.retry.Retry` object for fine-grained control
            over different types of retries.
            Pass an integer number to retry connection errors that many times,
            but no other types of errors. Pass zero to never retry.
    
            If ``False``, then retries are disabled and any exception is raised
            immediately. Also, instead of raising a MaxRetryError on redirects,
            the redirect response will be returned.
    
        :type retries: :class:`~urllib3.util.retry.Retry`, False, or an int.
    
        :param redirect:
            If True, automatically handle redirects (status codes 301, 302,
            303, 307, 308). Each redirect counts as a retry. Disabling retries
            will disable redirect, too.
    
        :param assert_same_host:
            If ``True``, will make sure that the host of the pool requests is
            consistent else will raise HostChangedError. When ``False``, you can
            use the pool on an HTTP proxy and request foreign hosts.
    
        :param timeout:
            If specified, overrides the default timeout for this one
            request. It may be a float (in seconds) or an instance of
            :class:`urllib3.util.Timeout`.
    
        :param pool_timeout:
            If set and the pool is set to block=True, then this method will
            block for ``pool_timeout`` seconds and raise EmptyPoolError if no
            connection is available within the time period.
    
        :param release_conn:
            If False, then the urlopen call will not release the connection
            back into the pool once a response is received (but will release if
            you read the entire contents of the response such as when
            `preload_content=True`). This is useful if you're not preloading
            the response's content immediately. You will need to call
            ``r.release_conn()`` on the response ``r`` to return the connection
            back into the pool. If None, it takes the value of
            ``response_kw.get('preload_content', True)``.
    
        :param chunked:
            If True, urllib3 will send the body using chunked transfer
            encoding. Otherwise, urllib3 will send the body using the standard
            content-length form. Defaults to False.
    
        :param int body_pos:
            Position to seek to in file-like body in the event of a retry or
            redirect. Typically this won't need to be set because urllib3 will
            auto-populate the value when needed.
    
        :param \\**response_kw:
            Additional parameters are passed to
            :meth:`urllib3.response.HTTPResponse.from_httplib`
        """
    
        parsed_url = parse_url(url)
        destination_scheme = parsed_url.scheme
    
        if headers is None:
            headers = self.headers
    
        if not isinstance(retries, Retry):
            retries = Retry.from_int(retries, redirect=redirect, default=self.retries)
    
        if release_conn is None:
            release_conn = response_kw.get("preload_content", True)
    
        # Check host
        if assert_same_host and not self.is_same_host(url):
            raise HostChangedError(self, url, retries)
    
        # Ensure that the URL we're connecting to is properly encoded
        if url.startswith("/"):
            url = six.ensure_str(_encode_target(url))
        else:
            url = six.ensure_str(parsed_url.url)
    
        conn = None
    
        # Track whether `conn` needs to be released before
        # returning/raising/recursing. Update this variable if necessary, and
        # leave `release_conn` constant throughout the function. That way, if
        # the function recurses, the original value of `release_conn` will be
        # passed down into the recursive call, and its value will be respected.
        #
        # See issue #651 [1] for details.
        #
        # [1] <https://github.com/urllib3/urllib3/issues/651>
        release_this_conn = release_conn
    
        http_tunnel_required = connection_requires_http_tunnel(
            self.proxy, self.proxy_config, destination_scheme
        )
    
        # Merge the proxy headers. Only done when not using HTTP CONNECT. We
        # have to copy the headers dict so we can safely change it without those
        # changes being reflected in anyone else's copy.
        if not http_tunnel_required:
            headers = headers.copy()
            headers.update(self.proxy_headers)
    
        # Must keep the exception bound to a separate variable or else Python 3
        # complains about UnboundLocalError.
        err = None
    
        # Keep track of whether we cleanly exited the except block. This
        # ensures we do proper cleanup in finally.
        clean_exit = False
    
        # Rewind body position, if needed. Record current position
        # for future rewinds in the event of a redirect/retry.
        body_pos = set_file_position(body, body_pos)
    
        try:
            # Request a connection from the queue.
            timeout_obj = self._get_timeout(timeout)
            conn = self._get_conn(timeout=pool_timeout)
    
            conn.timeout = timeout_obj.connect_timeout
    
            is_new_proxy_conn = self.proxy is not None and not getattr(
                conn, "sock", None
            )
            if is_new_proxy_conn and http_tunnel_required:
                self._prepare_proxy(conn)
    
            # Make the request on the httplib connection object.
>           httplib_response = self._make_request(
                conn,
                method,
                url,
                timeout=timeout_obj,
                body=body,
                headers=headers,
                chunked=chunked,
            )

..\AppData\Local\Programs\Python\Python310\lib\site-packages\urllib3\connectionpool.py:703: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

self = <urllib3.connectionpool.HTTPSConnectionPool object at 0x0000028D06364910>
conn = <urllib3.connection.HTTPSConnection object at 0x0000028D063641F0>
method = 'GET', url = '/visos-naujienos?pageno=0'
timeout = Timeout(connect=None, read=None, total=None), chunked = False
httplib_request_kw = {'body': None, 'headers': {'User-Agent': 'python-requests/2.27.1', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Connection': 'keep-alive'}}
timeout_obj = Timeout(connect=None, read=None, total=None)

    def _make_request(
        self, conn, method, url, timeout=_Default, chunked=False, **httplib_request_kw
    ):
        """
        Perform a request on a given urllib connection object taken from our
        pool.
    
        :param conn:
            a connection from one of our connection pools
    
        :param timeout:
            Socket timeout in seconds for the request. This can be a
            float or integer, which will set the same timeout value for
            the socket connect and the socket read, or an instance of
            :class:`urllib3.util.Timeout`, which gives you more fine-grained
            control over your timeouts.
        """
        self.num_requests += 1
    
        timeout_obj = self._get_timeout(timeout)
        timeout_obj.start_connect()
        conn.timeout = timeout_obj.connect_timeout
    
        # Trigger any extra validation we need to do.
        try:
>           self._validate_conn(conn)

..\AppData\Local\Programs\Python\Python310\lib\site-packages\urllib3\connectionpool.py:386: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

self = <urllib3.connectionpool.HTTPSConnectionPool object at 0x0000028D06364910>
conn = <urllib3.connection.HTTPSConnection object at 0x0000028D063641F0>

    def _validate_conn(self, conn):
        """
        Called right before a request is made, after the socket is created.
        """
        super(HTTPSConnectionPool, self)._validate_conn(conn)
    
        # Force connect early to allow us to validate the connection.
        if not getattr(conn, "sock", None):  # AppEngine might not have  `.sock`
>           conn.connect()

..\AppData\Local\Programs\Python\Python310\lib\site-packages\urllib3\connectionpool.py:1040: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

self = <urllib3.connection.HTTPSConnection object at 0x0000028D063641F0>

    def connect(self):
        # Add certificate verification
        self.sock = conn = self._new_conn()
        hostname = self.host
        tls_in_tls = False
    
        if self._is_using_tunnel():
            if self.tls_in_tls_required:
                self.sock = conn = self._connect_tls_proxy(hostname, conn)
                tls_in_tls = True
    
            # Calls self._set_hostport(), so self.host is
            # self._tunnel_host below.
            self._tunnel()
            # Mark this connection as not reusable
            self.auto_open = 0
    
            # Override the host with the one we're requesting data from.
            hostname = self._tunnel_host
    
        server_hostname = hostname
        if self.server_hostname is not None:
            server_hostname = self.server_hostname
    
        is_time_off = datetime.date.today() < RECENT_DATE
        if is_time_off:
            warnings.warn(
                (
                    "System time is way off (before {0}). This will probably "
                    "lead to SSL verification errors"
                ).format(RECENT_DATE),
                SystemTimeWarning,
            )
    
        # Wrap socket using verification with the root certs in
        # trusted_root_certs
        default_ssl_context = False
        if self.ssl_context is None:
            default_ssl_context = True
            self.ssl_context = create_urllib3_context(
                ssl_version=resolve_ssl_version(self.ssl_version),
                cert_reqs=resolve_cert_reqs(self.cert_reqs),
            )
    
        context = self.ssl_context
        context.verify_mode = resolve_cert_reqs(self.cert_reqs)
    
        # Try to load OS default certs if none are given.
        # Works well on Windows (requires Python3.4+)
        if (
            not self.ca_certs
            and not self.ca_cert_dir
            and not self.ca_cert_data
            and default_ssl_context
            and hasattr(context, "load_default_certs")
        ):
            context.load_default_certs()
    
>       self.sock = ssl_wrap_socket(
            sock=conn,
            keyfile=self.key_file,
            certfile=self.cert_file,
            key_password=self.key_password,
            ca_certs=self.ca_certs,
            ca_cert_dir=self.ca_cert_dir,
            ca_cert_data=self.ca_cert_data,
            server_hostname=server_hostname,
            ssl_context=context,
            tls_in_tls=tls_in_tls,
        )

..\AppData\Local\Programs\Python\Python310\lib\site-packages\urllib3\connection.py:414: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

sock = <socket.socket [closed] fd=-1, family=AddressFamily.AF_INET, type=SocketKind.SOCK_STREAM, proto=0>
keyfile = None, certfile = None, cert_reqs = None
ca_certs = 'C:\\Users\\mamonask\\AppData\\Local\\Programs\\Python\\Python310\\lib\\site-packages\\certifi\\cacert.pem'
server_hostname = 'www.vz.lt', ssl_version = None, ciphers = None
ssl_context = <ssl.SSLContext object at 0x0000028D060A5F40>, ca_cert_dir = None
key_password = None, ca_cert_data = None, tls_in_tls = False

    def ssl_wrap_socket(
        sock,
        keyfile=None,
        certfile=None,
        cert_reqs=None,
        ca_certs=None,
        server_hostname=None,
        ssl_version=None,
        ciphers=None,
        ssl_context=None,
        ca_cert_dir=None,
        key_password=None,
        ca_cert_data=None,
        tls_in_tls=False,
    ):
        """
        All arguments except for server_hostname, ssl_context, and ca_cert_dir have
        the same meaning as they do when using :func:`ssl.wrap_socket`.
    
        :param server_hostname:
            When SNI is supported, the expected hostname of the certificate
        :param ssl_context:
            A pre-made :class:`SSLContext` object. If none is provided, one will
            be created using :func:`create_urllib3_context`.
        :param ciphers:
            A string of ciphers we wish the client to support.
        :param ca_cert_dir:
            A directory containing CA certificates in multiple separate files, as
            supported by OpenSSL's -CApath flag or the capath argument to
            SSLContext.load_verify_locations().
        :param key_password:
            Optional password if the keyfile is encrypted.
        :param ca_cert_data:
            Optional string containing CA certificates in PEM format suitable for
            passing as the cadata parameter to SSLContext.load_verify_locations()
        :param tls_in_tls:
            Use SSLTransport to wrap the existing socket.
        """
        context = ssl_context
        if context is None:
            # Note: This branch of code and all the variables in it are no longer
            # used by urllib3 itself. We should consider deprecating and removing
            # this code.
            context = create_urllib3_context(ssl_version, cert_reqs, ciphers=ciphers)
    
        if ca_certs or ca_cert_dir or ca_cert_data:
            try:
                context.load_verify_locations(ca_certs, ca_cert_dir, ca_cert_data)
            except (IOError, OSError) as e:
                raise SSLError(e)
    
        elif ssl_context is None and hasattr(context, "load_default_certs"):
            # try to load OS default certs; works well on Windows (require Python3.4+)
            context.load_default_certs()
    
        # Attempt to detect if we get the goofy behavior of the
        # keyfile being encrypted and OpenSSL asking for the
        # passphrase via the terminal and instead error out.
        if keyfile and key_password is None and _is_key_file_encrypted(keyfile):
            raise SSLError("Client private key is encrypted, password is required")
    
        if certfile:
            if key_password is None:
                context.load_cert_chain(certfile, keyfile)
            else:
                context.load_cert_chain(certfile, keyfile, key_password)
    
        try:
            if hasattr(context, "set_alpn_protocols"):
                context.set_alpn_protocols(ALPN_PROTOCOLS)
        except NotImplementedError:  # Defensive: in CI, we always have set_alpn_protocols
            pass
    
        # If we detect server_hostname is an IP address then the SNI
        # extension should not be used according to RFC3546 Section 3.1
        use_sni_hostname = server_hostname and not is_ipaddress(server_hostname)
        # SecureTransport uses server_hostname in certificate verification.
        send_sni = (use_sni_hostname and HAS_SNI) or (
            IS_SECURETRANSPORT and server_hostname
        )
        # Do not warn the user if server_hostname is an invalid SNI hostname.
        if not HAS_SNI and use_sni_hostname:
            warnings.warn(
                "An HTTPS request has been made, but the SNI (Server Name "
                "Indication) extension to TLS is not available on this platform. "
                "This may cause the server to present an incorrect TLS "
                "certificate, which can cause validation failures. You can upgrade to "
                "a newer version of Python to solve this. For more information, see "
                "https://urllib3.readthedocs.io/en/1.26.x/advanced-usage.html"
                "#ssl-warnings",
                SNIMissingWarning,
            )
    
        if send_sni:
>           ssl_sock = _ssl_wrap_socket_impl(
                sock, context, tls_in_tls, server_hostname=server_hostname
            )

..\AppData\Local\Programs\Python\Python310\lib\site-packages\urllib3\util\ssl_.py:449: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

sock = <socket.socket [closed] fd=-1, family=AddressFamily.AF_INET, type=SocketKind.SOCK_STREAM, proto=0>
ssl_context = <ssl.SSLContext object at 0x0000028D060A5F40>, tls_in_tls = False
server_hostname = 'www.vz.lt'

    def _ssl_wrap_socket_impl(sock, ssl_context, tls_in_tls, server_hostname=None):
        if tls_in_tls:
            if not SSLTransport:
                # Import error, ssl is not available.
                raise ProxySchemeUnsupported(
                    "TLS in TLS requires support for the 'ssl' module"
                )
    
            SSLTransport._validate_ssl_context_for_tls_in_tls(ssl_context)
            return SSLTransport(sock, ssl_context, server_hostname)
    
        if server_hostname:
>           return ssl_context.wrap_socket(sock, server_hostname=server_hostname)

..\AppData\Local\Programs\Python\Python310\lib\site-packages\urllib3\util\ssl_.py:493: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

self = <ssl.SSLContext object at 0x0000028D060A5F40>
sock = <socket.socket [closed] fd=-1, family=AddressFamily.AF_INET, type=SocketKind.SOCK_STREAM, proto=0>
server_side = False, do_handshake_on_connect = True, suppress_ragged_eofs = True
server_hostname = 'www.vz.lt', session = None

    def wrap_socket(self, sock, server_side=False,
                    do_handshake_on_connect=True,
                    suppress_ragged_eofs=True,
                    server_hostname=None, session=None):
        # SSLSocket class handles server_hostname encoding before it calls
        # ctx._wrap_socket()
>       return self.sslsocket_class._create(
            sock=sock,
            server_side=server_side,
            do_handshake_on_connect=do_handshake_on_connect,
            suppress_ragged_eofs=suppress_ragged_eofs,
            server_hostname=server_hostname,
            context=self,
            session=session
        )

..\AppData\Local\Programs\Python\Python310\lib\ssl.py:512: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

cls = <class 'ssl.SSLSocket'>
sock = <socket.socket [closed] fd=-1, family=AddressFamily.AF_INET, type=SocketKind.SOCK_STREAM, proto=0>
server_side = False, do_handshake_on_connect = True, suppress_ragged_eofs = True
server_hostname = 'www.vz.lt'
context = <ssl.SSLContext object at 0x0000028D060A5F40>, session = None

    @classmethod
    def _create(cls, sock, server_side=False, do_handshake_on_connect=True,
                suppress_ragged_eofs=True, server_hostname=None,
                context=None, session=None):
        if sock.getsockopt(SOL_SOCKET, SO_TYPE) != SOCK_STREAM:
            raise NotImplementedError("only stream sockets are supported")
        if server_side:
            if server_hostname:
                raise ValueError("server_hostname can only be specified "
                                 "in client mode")
            if session is not None:
                raise ValueError("session can only be specified in "
                                 "client mode")
        if context.check_hostname and not server_hostname:
            raise ValueError("check_hostname requires server_hostname")
    
        kwargs = dict(
            family=sock.family, type=sock.type, proto=sock.proto,
            fileno=sock.fileno()
        )
        self = cls.__new__(cls, **kwargs)
        super(SSLSocket, self).__init__(**kwargs)
        self.settimeout(sock.gettimeout())
        sock.detach()
    
        self._context = context
        self._session = session
        self._closed = False
        self._sslobj = None
        self.server_side = server_side
        self.server_hostname = context._encode_hostname(server_hostname)
        self.do_handshake_on_connect = do_handshake_on_connect
        self.suppress_ragged_eofs = suppress_ragged_eofs
    
        # See if we are connected
        try:
            self.getpeername()
        except OSError as e:
            if e.errno != errno.ENOTCONN:
                raise
            connected = False
        else:
            connected = True
    
        self._connected = connected
        if connected:
            # create the SSL object
            try:
                self._sslobj = self._context._wrap_socket(
                    self, server_side, self.server_hostname,
                    owner=self, session=self._session,
                )
                if do_handshake_on_connect:
                    timeout = self.gettimeout()
                    if timeout == 0.0:
                        # non-blocking
                        raise ValueError("do_handshake_on_connect should not be specified for non-blocking sockets")
>                   self.do_handshake()

..\AppData\Local\Programs\Python\Python310\lib\ssl.py:1070: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

self = <ssl.SSLSocket [closed] fd=-1, family=AddressFamily.AF_INET, type=SocketKind.SOCK_STREAM, proto=0>
block = False

    @_sslcopydoc
    def do_handshake(self, block=False):
        self._check_connected()
        timeout = self.gettimeout()
        try:
            if timeout == 0.0 and block:
                self.settimeout(None)
>           self._sslobj.do_handshake()
E           ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:997)

..\AppData\Local\Programs\Python\Python310\lib\ssl.py:1341: SSLCertVerificationError

During handling of the above exception, another exception occurred:

self = <requests.adapters.HTTPAdapter object at 0x0000028D06364B80>
request = <PreparedRequest [GET]>, stream = False
timeout = Timeout(connect=None, read=None, total=None), verify = True
cert = None, proxies = OrderedDict()

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        """Sends PreparedRequest object. Returns Response object.
    
        :param request: The :class:`PreparedRequest <PreparedRequest>` being sent.
        :param stream: (optional) Whether to stream the request content.
        :param timeout: (optional) How long to wait for the server to send
            data before giving up, as a float, or a :ref:`(connect timeout,
            read timeout) <timeouts>` tuple.
        :type timeout: float or tuple or urllib3 Timeout object
        :param verify: (optional) Either a boolean, in which case it controls whether
            we verify the server's TLS certificate, or a string, in which case it
            must be a path to a CA bundle to use
        :param cert: (optional) Any user-provided SSL certificate to be trusted.
        :param proxies: (optional) The proxies dictionary to apply to the request.
        :rtype: requests.Response
        """
    
        try:
            conn = self.get_connection(request.url, proxies)
        except LocationValueError as e:
            raise InvalidURL(e, request=request)
    
        self.cert_verify(conn, request.url, verify, cert)
        url = self.request_url(request, proxies)
        self.add_headers(request, stream=stream, timeout=timeout, verify=verify, cert=cert, proxies=proxies)
    
        chunked = not (request.body is None or 'Content-Length' in request.headers)
    
        if isinstance(timeout, tuple):
            try:
                connect, read = timeout
                timeout = TimeoutSauce(connect=connect, read=read)
            except ValueError as e:
                # this may raise a string formatting error.
                err = ("Invalid timeout {}. Pass a (connect, read) "
                       "timeout tuple, or a single float to set "
                       "both timeouts to the same value".format(timeout))
                raise ValueError(err)
        elif isinstance(timeout, TimeoutSauce):
            pass
        else:
            timeout = TimeoutSauce(connect=timeout, read=timeout)
    
        try:
            if not chunked:
>               resp = conn.urlopen(
                    method=request.method,
                    url=url,
                    body=request.body,
                    headers=request.headers,
                    redirect=False,
                    assert_same_host=False,
                    preload_content=False,
                    decode_content=False,
                    retries=self.max_retries,
                    timeout=timeout
                )

..\AppData\Local\Programs\Python\Python310\lib\site-packages\requests\adapters.py:440: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

self = <urllib3.connectionpool.HTTPSConnectionPool object at 0x0000028D06364910>
method = 'GET', url = '/visos-naujienos?pageno=0', body = None
headers = {'User-Agent': 'python-requests/2.27.1', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Connection': 'keep-alive'}
retries = Retry(total=0, connect=None, read=False, redirect=None, status=None)
redirect = False, assert_same_host = False
timeout = Timeout(connect=None, read=None, total=None), pool_timeout = None
release_conn = False, chunked = False, body_pos = None
response_kw = {'decode_content': False, 'preload_content': False}
parsed_url = Url(scheme=None, auth=None, host=None, port=None, path='/visos-naujienos', query='pageno=0', fragment=None)
destination_scheme = None, conn = None, release_this_conn = True
http_tunnel_required = False, err = None, clean_exit = False

    def urlopen(
        self,
        method,
        url,
        body=None,
        headers=None,
        retries=None,
        redirect=True,
        assert_same_host=True,
        timeout=_Default,
        pool_timeout=None,
        release_conn=None,
        chunked=False,
        body_pos=None,
        **response_kw
    ):
        """
        Get a connection from the pool and perform an HTTP request. This is the
        lowest level call for making a request, so you'll need to specify all
        the raw details.
    
        .. note::
    
           More commonly, it's appropriate to use a convenience method provided
           by :class:`.RequestMethods`, such as :meth:`request`.
    
        .. note::
    
           `release_conn` will only behave as expected if
           `preload_content=False` because we want to make
           `preload_content=False` the default behaviour someday soon without
           breaking backwards compatibility.
    
        :param method:
            HTTP request method (such as GET, POST, PUT, etc.)
    
        :param url:
            The URL to perform the request on.
    
        :param body:
            Data to send in the request body, either :class:`str`, :class:`bytes`,
            an iterable of :class:`str`/:class:`bytes`, or a file-like object.
    
        :param headers:
            Dictionary of custom headers to send, such as User-Agent,
            If-None-Match, etc. If None, pool headers are used. If provided,
            these headers completely replace any pool-specific headers.
    
        :param retries:
            Configure the number of retries to allow before raising a
            :class:`~urllib3.exceptions.MaxRetryError` exception.
    
            Pass ``None`` to retry until you receive a response. Pass a
            :class:`~urllib3.util.retry.Retry` object for fine-grained control
            over different types of retries.
            Pass an integer number to retry connection errors that many times,
            but no other types of errors. Pass zero to never retry.
    
            If ``False``, then retries are disabled and any exception is raised
            immediately. Also, instead of raising a MaxRetryError on redirects,
            the redirect response will be returned.
    
        :type retries: :class:`~urllib3.util.retry.Retry`, False, or an int.
    
        :param redirect:
            If True, automatically handle redirects (status codes 301, 302,
            303, 307, 308). Each redirect counts as a retry. Disabling retries
            will disable redirect, too.
    
        :param assert_same_host:
            If ``True``, will make sure that the host of the pool requests is
            consistent else will raise HostChangedError. When ``False``, you can
            use the pool on an HTTP proxy and request foreign hosts.
    
        :param timeout:
            If specified, overrides the default timeout for this one
            request. It may be a float (in seconds) or an instance of
            :class:`urllib3.util.Timeout`.
    
        :param pool_timeout:
            If set and the pool is set to block=True, then this method will
            block for ``pool_timeout`` seconds and raise EmptyPoolError if no
            connection is available within the time period.
    
        :param release_conn:
            If False, then the urlopen call will not release the connection
            back into the pool once a response is received (but will release if
            you read the entire contents of the response such as when
            `preload_content=True`). This is useful if you're not preloading
            the response's content immediately. You will need to call
            ``r.release_conn()`` on the response ``r`` to return the connection
            back into the pool. If None, it takes the value of
            ``response_kw.get('preload_content', True)``.
    
        :param chunked:
            If True, urllib3 will send the body using chunked transfer
            encoding. Otherwise, urllib3 will send the body using the standard
            content-length form. Defaults to False.
    
        :param int body_pos:
            Position to seek to in file-like body in the event of a retry or
            redirect. Typically this won't need to be set because urllib3 will
            auto-populate the value when needed.
    
        :param \\**response_kw:
            Additional parameters are passed to
            :meth:`urllib3.response.HTTPResponse.from_httplib`
        """
    
        parsed_url = parse_url(url)
        destination_scheme = parsed_url.scheme
    
        if headers is None:
            headers = self.headers
    
        if not isinstance(retries, Retry):
            retries = Retry.from_int(retries, redirect=redirect, default=self.retries)
    
        if release_conn is None:
            release_conn = response_kw.get("preload_content", True)
    
        # Check host
        if assert_same_host and not self.is_same_host(url):
            raise HostChangedError(self, url, retries)
    
        # Ensure that the URL we're connecting to is properly encoded
        if url.startswith("/"):
            url = six.ensure_str(_encode_target(url))
        else:
            url = six.ensure_str(parsed_url.url)
    
        conn = None
    
        # Track whether `conn` needs to be released before
        # returning/raising/recursing. Update this variable if necessary, and
        # leave `release_conn` constant throughout the function. That way, if
        # the function recurses, the original value of `release_conn` will be
        # passed down into the recursive call, and its value will be respected.
        #
        # See issue #651 [1] for details.
        #
        # [1] <https://github.com/urllib3/urllib3/issues/651>
        release_this_conn = release_conn
    
        http_tunnel_required = connection_requires_http_tunnel(
            self.proxy, self.proxy_config, destination_scheme
        )
    
        # Merge the proxy headers. Only done when not using HTTP CONNECT. We
        # have to copy the headers dict so we can safely change it without those
        # changes being reflected in anyone else's copy.
        if not http_tunnel_required:
            headers = headers.copy()
            headers.update(self.proxy_headers)
    
        # Must keep the exception bound to a separate variable or else Python 3
        # complains about UnboundLocalError.
        err = None
    
        # Keep track of whether we cleanly exited the except block. This
        # ensures we do proper cleanup in finally.
        clean_exit = False
    
        # Rewind body position, if needed. Record current position
        # for future rewinds in the event of a redirect/retry.
        body_pos = set_file_position(body, body_pos)
    
        try:
            # Request a connection from the queue.
            timeout_obj = self._get_timeout(timeout)
            conn = self._get_conn(timeout=pool_timeout)
    
            conn.timeout = timeout_obj.connect_timeout
    
            is_new_proxy_conn = self.proxy is not None and not getattr(
                conn, "sock", None
            )
            if is_new_proxy_conn and http_tunnel_required:
                self._prepare_proxy(conn)
    
            # Make the request on the httplib connection object.
            httplib_response = self._make_request(
                conn,
                method,
                url,
                timeout=timeout_obj,
                body=body,
                headers=headers,
                chunked=chunked,
            )
    
            # If we're going to release the connection in ``finally:``, then
            # the response doesn't need to know about the connection. Otherwise
            # it will also try to release it and we'll have a double-release
            # mess.
            response_conn = conn if not release_conn else None
    
            # Pass method to Response for length checking
            response_kw["request_method"] = method
    
            # Import httplib's response into our own wrapper object
            response = self.ResponseCls.from_httplib(
                httplib_response,
                pool=self,
                connection=response_conn,
                retries=retries,
                **response_kw
            )
    
            # Everything went great!
            clean_exit = True
    
        except EmptyPoolError:
            # Didn't get a connection from the pool, no need to clean up
            clean_exit = True
            release_this_conn = False
            raise
    
        except (
            TimeoutError,
            HTTPException,
            SocketError,
            ProtocolError,
            BaseSSLError,
            SSLError,
            CertificateError,
        ) as e:
            # Discard the connection for these exceptions. It will be
            # replaced during the next _get_conn() call.
            clean_exit = False
    
            def _is_ssl_error_message_from_http_proxy(ssl_error):
                # We're trying to detect the message 'WRONG_VERSION_NUMBER' but
                # SSLErrors are kinda all over the place when it comes to the message,
                # so we try to cover our bases here!
                message = " ".join(re.split("[^a-z]", str(ssl_error).lower()))
                return (
                    "wrong version number" in message or "unknown protocol" in message
                )
    
            # Try to detect a common user error with proxies which is to
            # set an HTTP proxy to be HTTPS when it should be 'http://'
            # (ie {'http': 'http://proxy', 'https': 'https://proxy'})
            # Instead we add a nice error message and point to a URL.
            if (
                isinstance(e, BaseSSLError)
                and self.proxy
                and _is_ssl_error_message_from_http_proxy(e)
            ):
                e = ProxyError(
                    "Your proxy appears to only use HTTP and not HTTPS, "
                    "try changing your proxy URL to be HTTP. See: "
                    "https://urllib3.readthedocs.io/en/1.26.x/advanced-usage.html"
                    "#https-proxy-error-http-proxy",
                    SSLError(e),
                )
            elif isinstance(e, (BaseSSLError, CertificateError)):
                e = SSLError(e)
            elif isinstance(e, (SocketError, NewConnectionError)) and self.proxy:
                e = ProxyError("Cannot connect to proxy.", e)
            elif isinstance(e, (SocketError, HTTPException)):
                e = ProtocolError("Connection aborted.", e)
    
>           retries = retries.increment(
                method, url, error=e, _pool=self, _stacktrace=sys.exc_info()[2]
            )

..\AppData\Local\Programs\Python\Python310\lib\site-packages\urllib3\connectionpool.py:785: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

self = Retry(total=0, connect=None, read=False, redirect=None, status=None)
method = 'GET', url = '/visos-naujienos?pageno=0', response = None
error = SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:997)'))
_pool = <urllib3.connectionpool.HTTPSConnectionPool object at 0x0000028D06364910>
_stacktrace = <traceback object at 0x0000028D06398580>

    def increment(
        self,
        method=None,
        url=None,
        response=None,
        error=None,
        _pool=None,
        _stacktrace=None,
    ):
        """Return a new Retry object with incremented retry counters.
    
        :param response: A response object, or None, if the server did not
            return a response.
        :type response: :class:`~urllib3.response.HTTPResponse`
        :param Exception error: An error encountered during the request, or
            None if the response was received successfully.
    
        :return: A new ``Retry`` object.
        """
        if self.total is False and error:
            # Disabled, indicate to re-raise the error.
            raise six.reraise(type(error), error, _stacktrace)
    
        total = self.total
        if total is not None:
            total -= 1
    
        connect = self.connect
        read = self.read
        redirect = self.redirect
        status_count = self.status
        other = self.other
        cause = "unknown"
        status = None
        redirect_location = None
    
        if error and self._is_connection_error(error):
            # Connect retry?
            if connect is False:
                raise six.reraise(type(error), error, _stacktrace)
            elif connect is not None:
                connect -= 1
    
        elif error and self._is_read_error(error):
            # Read retry?
            if read is False or not self._is_method_retryable(method):
                raise six.reraise(type(error), error, _stacktrace)
            elif read is not None:
                read -= 1
    
        elif error:
            # Other retry?
            if other is not None:
                other -= 1
    
        elif response and response.get_redirect_location():
            # Redirect retry?
            if redirect is not None:
                redirect -= 1
            cause = "too many redirects"
            redirect_location = response.get_redirect_location()
            status = response.status
    
        else:
            # Incrementing because of a server error like a 500 in
            # status_forcelist and the given method is in the allowed_methods
            cause = ResponseError.GENERIC_ERROR
            if response and response.status:
                if status_count is not None:
                    status_count -= 1
                cause = ResponseError.SPECIFIC_ERROR.format(status_code=response.status)
                status = response.status
    
        history = self.history + (
            RequestHistory(method, url, error, status, redirect_location),
        )
    
        new_retry = self.new(
            total=total,
            connect=connect,
            read=read,
            redirect=redirect,
            status=status_count,
            other=other,
            history=history,
        )
    
        if new_retry.is_exhausted():
>           raise MaxRetryError(_pool, url, error or ResponseError(cause))
E           urllib3.exceptions.MaxRetryError: HTTPSConnectionPool(host='www.vz.lt', port=443): Max retries exceeded with url: /visos-naujienos?pageno=0 (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:997)')))

..\AppData\Local\Programs\Python\Python310\lib\site-packages\urllib3\util\retry.py:592: MaxRetryError

During handling of the above exception, another exception occurred:

    def test_et_response():
        # maybe should only pass page, and URL should be local
>       assert type(scraper._get_response(page="vz")) == requests.Response

test_main.py:11: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _
main.py:35: in _get_response
    r = requests.get(url=self.URL[page])
..\AppData\Local\Programs\Python\Python310\lib\site-packages\requests\api.py:75: in get
    return request('get', url, params=params, **kwargs)
..\AppData\Local\Programs\Python\Python310\lib\site-packages\requests\api.py:61: in request
    return session.request(method=method, url=url, **kwargs)
..\AppData\Local\Programs\Python\Python310\lib\site-packages\requests\sessions.py:529: in request
    resp = self.send(prep, **send_kwargs)
..\AppData\Local\Programs\Python\Python310\lib\site-packages\requests\sessions.py:645: in send
    r = adapter.send(request, **kwargs)
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

self = <requests.adapters.HTTPAdapter object at 0x0000028D06364B80>
request = <PreparedRequest [GET]>, stream = False
timeout = Timeout(connect=None, read=None, total=None), verify = True
cert = None, proxies = OrderedDict()

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        """Sends PreparedRequest object. Returns Response object.
    
        :param request: The :class:`PreparedRequest <PreparedRequest>` being sent.
        :param stream: (optional) Whether to stream the request content.
        :param timeout: (optional) How long to wait for the server to send
            data before giving up, as a float, or a :ref:`(connect timeout,
            read timeout) <timeouts>` tuple.
        :type timeout: float or tuple or urllib3 Timeout object
        :param verify: (optional) Either a boolean, in which case it controls whether
            we verify the server's TLS certificate, or a string, in which case it
            must be a path to a CA bundle to use
        :param cert: (optional) Any user-provided SSL certificate to be trusted.
        :param proxies: (optional) The proxies dictionary to apply to the request.
        :rtype: requests.Response
        """
    
        try:
            conn = self.get_connection(request.url, proxies)
        except LocationValueError as e:
            raise InvalidURL(e, request=request)
    
        self.cert_verify(conn, request.url, verify, cert)
        url = self.request_url(request, proxies)
        self.add_headers(request, stream=stream, timeout=timeout, verify=verify, cert=cert, proxies=proxies)
    
        chunked = not (request.body is None or 'Content-Length' in request.headers)
    
        if isinstance(timeout, tuple):
            try:
                connect, read = timeout
                timeout = TimeoutSauce(connect=connect, read=read)
            except ValueError as e:
                # this may raise a string formatting error.
                err = ("Invalid timeout {}. Pass a (connect, read) "
                       "timeout tuple, or a single float to set "
                       "both timeouts to the same value".format(timeout))
                raise ValueError(err)
        elif isinstance(timeout, TimeoutSauce):
            pass
        else:
            timeout = TimeoutSauce(connect=timeout, read=timeout)
    
        try:
            if not chunked:
                resp = conn.urlopen(
                    method=request.method,
                    url=url,
                    body=request.body,
                    headers=request.headers,
                    redirect=False,
                    assert_same_host=False,
                    preload_content=False,
                    decode_content=False,
                    retries=self.max_retries,
                    timeout=timeout
                )
    
            # Send the request.
            else:
                if hasattr(conn, 'proxy_pool'):
                    conn = conn.proxy_pool
    
                low_conn = conn._get_conn(timeout=DEFAULT_POOL_TIMEOUT)
    
                try:
                    skip_host = 'Host' in request.headers
                    low_conn.putrequest(request.method,
                                        url,
                                        skip_accept_encoding=True,
                                        skip_host=skip_host)
    
                    for header, value in request.headers.items():
                        low_conn.putheader(header, value)
    
                    low_conn.endheaders()
    
                    for i in request.body:
                        low_conn.send(hex(len(i))[2:].encode('utf-8'))
                        low_conn.send(b'\r\n')
                        low_conn.send(i)
                        low_conn.send(b'\r\n')
                    low_conn.send(b'0\r\n\r\n')
    
                    # Receive the response from the server
                    try:
                        # For Python 2.7, use buffering of HTTP responses
                        r = low_conn.getresponse(buffering=True)
                    except TypeError:
                        # For compatibility with Python 3.3+
                        r = low_conn.getresponse()
    
                    resp = HTTPResponse.from_httplib(
                        r,
                        pool=conn,
                        connection=low_conn,
                        preload_content=False,
                        decode_content=False
                    )
                except:
                    # If we hit any problems here, clean up the connection.
                    # Then, reraise so that we can handle the actual exception.
                    low_conn.close()
                    raise
    
        except (ProtocolError, socket.error) as err:
            raise ConnectionError(err, request=request)
    
        except MaxRetryError as e:
            if isinstance(e.reason, ConnectTimeoutError):
                # TODO: Remove this in 3.0.0: see #2811
                if not isinstance(e.reason, NewConnectionError):
                    raise ConnectTimeout(e, request=request)
    
            if isinstance(e.reason, ResponseError):
                raise RetryError(e, request=request)
    
            if isinstance(e.reason, _ProxyError):
                raise ProxyError(e, request=request)
    
            if isinstance(e.reason, _SSLError):
                # This branch is for urllib3 v1.22 and later.
>               raise SSLError(e, request=request)
E               requests.exceptions.SSLError: HTTPSConnectionPool(host='www.vz.lt', port=443): Max retries exceeded with url: /visos-naujienos?pageno=0 (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:997)')))

..\AppData\Local\Programs\Python\Python310\lib\site-packages\requests\adapters.py:517: SSLError
__________________________ test_get_articles_in_page __________________________

self = <urllib3.connectionpool.HTTPSConnectionPool object at 0x0000028D06DDCA30>
method = 'GET', url = '/visos-naujienos?pageno=0', body = None
headers = {'User-Agent': 'python-requests/2.27.1', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Connection': 'keep-alive'}
retries = Retry(total=0, connect=None, read=False, redirect=None, status=None)
redirect = False, assert_same_host = False
timeout = Timeout(connect=None, read=None, total=None), pool_timeout = None
release_conn = False, chunked = False, body_pos = None
response_kw = {'decode_content': False, 'preload_content': False}
parsed_url = Url(scheme=None, auth=None, host=None, port=None, path='/visos-naujienos', query='pageno=0', fragment=None)
destination_scheme = None, conn = None, release_this_conn = True
http_tunnel_required = False, err = None, clean_exit = False

    def urlopen(
        self,
        method,
        url,
        body=None,
        headers=None,
        retries=None,
        redirect=True,
        assert_same_host=True,
        timeout=_Default,
        pool_timeout=None,
        release_conn=None,
        chunked=False,
        body_pos=None,
        **response_kw
    ):
        """
        Get a connection from the pool and perform an HTTP request. This is the
        lowest level call for making a request, so you'll need to specify all
        the raw details.
    
        .. note::
    
           More commonly, it's appropriate to use a convenience method provided
           by :class:`.RequestMethods`, such as :meth:`request`.
    
        .. note::
    
           `release_conn` will only behave as expected if
           `preload_content=False` because we want to make
           `preload_content=False` the default behaviour someday soon without
           breaking backwards compatibility.
    
        :param method:
            HTTP request method (such as GET, POST, PUT, etc.)
    
        :param url:
            The URL to perform the request on.
    
        :param body:
            Data to send in the request body, either :class:`str`, :class:`bytes`,
            an iterable of :class:`str`/:class:`bytes`, or a file-like object.
    
        :param headers:
            Dictionary of custom headers to send, such as User-Agent,
            If-None-Match, etc. If None, pool headers are used. If provided,
            these headers completely replace any pool-specific headers.
    
        :param retries:
            Configure the number of retries to allow before raising a
            :class:`~urllib3.exceptions.MaxRetryError` exception.
    
            Pass ``None`` to retry until you receive a response. Pass a
            :class:`~urllib3.util.retry.Retry` object for fine-grained control
            over different types of retries.
            Pass an integer number to retry connection errors that many times,
            but no other types of errors. Pass zero to never retry.
    
            If ``False``, then retries are disabled and any exception is raised
            immediately. Also, instead of raising a MaxRetryError on redirects,
            the redirect response will be returned.
    
        :type retries: :class:`~urllib3.util.retry.Retry`, False, or an int.
    
        :param redirect:
            If True, automatically handle redirects (status codes 301, 302,
            303, 307, 308). Each redirect counts as a retry. Disabling retries
            will disable redirect, too.
    
        :param assert_same_host:
            If ``True``, will make sure that the host of the pool requests is
            consistent else will raise HostChangedError. When ``False``, you can
            use the pool on an HTTP proxy and request foreign hosts.
    
        :param timeout:
            If specified, overrides the default timeout for this one
            request. It may be a float (in seconds) or an instance of
            :class:`urllib3.util.Timeout`.
    
        :param pool_timeout:
            If set and the pool is set to block=True, then this method will
            block for ``pool_timeout`` seconds and raise EmptyPoolError if no
            connection is available within the time period.
    
        :param release_conn:
            If False, then the urlopen call will not release the connection
            back into the pool once a response is received (but will release if
            you read the entire contents of the response such as when
            `preload_content=True`). This is useful if you're not preloading
            the response's content immediately. You will need to call
            ``r.release_conn()`` on the response ``r`` to return the connection
            back into the pool. If None, it takes the value of
            ``response_kw.get('preload_content', True)``.
    
        :param chunked:
            If True, urllib3 will send the body using chunked transfer
            encoding. Otherwise, urllib3 will send the body using the standard
            content-length form. Defaults to False.
    
        :param int body_pos:
            Position to seek to in file-like body in the event of a retry or
            redirect. Typically this won't need to be set because urllib3 will
            auto-populate the value when needed.
    
        :param \\**response_kw:
            Additional parameters are passed to
            :meth:`urllib3.response.HTTPResponse.from_httplib`
        """
    
        parsed_url = parse_url(url)
        destination_scheme = parsed_url.scheme
    
        if headers is None:
            headers = self.headers
    
        if not isinstance(retries, Retry):
            retries = Retry.from_int(retries, redirect=redirect, default=self.retries)
    
        if release_conn is None:
            release_conn = response_kw.get("preload_content", True)
    
        # Check host
        if assert_same_host and not self.is_same_host(url):
            raise HostChangedError(self, url, retries)
    
        # Ensure that the URL we're connecting to is properly encoded
        if url.startswith("/"):
            url = six.ensure_str(_encode_target(url))
        else:
            url = six.ensure_str(parsed_url.url)
    
        conn = None
    
        # Track whether `conn` needs to be released before
        # returning/raising/recursing. Update this variable if necessary, and
        # leave `release_conn` constant throughout the function. That way, if
        # the function recurses, the original value of `release_conn` will be
        # passed down into the recursive call, and its value will be respected.
        #
        # See issue #651 [1] for details.
        #
        # [1] <https://github.com/urllib3/urllib3/issues/651>
        release_this_conn = release_conn
    
        http_tunnel_required = connection_requires_http_tunnel(
            self.proxy, self.proxy_config, destination_scheme
        )
    
        # Merge the proxy headers. Only done when not using HTTP CONNECT. We
        # have to copy the headers dict so we can safely change it without those
        # changes being reflected in anyone else's copy.
        if not http_tunnel_required:
            headers = headers.copy()
            headers.update(self.proxy_headers)
    
        # Must keep the exception bound to a separate variable or else Python 3
        # complains about UnboundLocalError.
        err = None
    
        # Keep track of whether we cleanly exited the except block. This
        # ensures we do proper cleanup in finally.
        clean_exit = False
    
        # Rewind body position, if needed. Record current position
        # for future rewinds in the event of a redirect/retry.
        body_pos = set_file_position(body, body_pos)
    
        try:
            # Request a connection from the queue.
            timeout_obj = self._get_timeout(timeout)
            conn = self._get_conn(timeout=pool_timeout)
    
            conn.timeout = timeout_obj.connect_timeout
    
            is_new_proxy_conn = self.proxy is not None and not getattr(
                conn, "sock", None
            )
            if is_new_proxy_conn and http_tunnel_required:
                self._prepare_proxy(conn)
    
            # Make the request on the httplib connection object.
>           httplib_response = self._make_request(
                conn,
                method,
                url,
                timeout=timeout_obj,
                body=body,
                headers=headers,
                chunked=chunked,
            )

..\AppData\Local\Programs\Python\Python310\lib\site-packages\urllib3\connectionpool.py:703: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

self = <urllib3.connectionpool.HTTPSConnectionPool object at 0x0000028D06DDCA30>
conn = <urllib3.connection.HTTPSConnection object at 0x0000028D06DDC220>
method = 'GET', url = '/visos-naujienos?pageno=0'
timeout = Timeout(connect=None, read=None, total=None), chunked = False
httplib_request_kw = {'body': None, 'headers': {'User-Agent': 'python-requests/2.27.1', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Connection': 'keep-alive'}}
timeout_obj = Timeout(connect=None, read=None, total=None)

    def _make_request(
        self, conn, method, url, timeout=_Default, chunked=False, **httplib_request_kw
    ):
        """
        Perform a request on a given urllib connection object taken from our
        pool.
    
        :param conn:
            a connection from one of our connection pools
    
        :param timeout:
            Socket timeout in seconds for the request. This can be a
            float or integer, which will set the same timeout value for
            the socket connect and the socket read, or an instance of
            :class:`urllib3.util.Timeout`, which gives you more fine-grained
            control over your timeouts.
        """
        self.num_requests += 1
    
        timeout_obj = self._get_timeout(timeout)
        timeout_obj.start_connect()
        conn.timeout = timeout_obj.connect_timeout
    
        # Trigger any extra validation we need to do.
        try:
>           self._validate_conn(conn)

..\AppData\Local\Programs\Python\Python310\lib\site-packages\urllib3\connectionpool.py:386: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

self = <urllib3.connectionpool.HTTPSConnectionPool object at 0x0000028D06DDCA30>
conn = <urllib3.connection.HTTPSConnection object at 0x0000028D06DDC220>

    def _validate_conn(self, conn):
        """
        Called right before a request is made, after the socket is created.
        """
        super(HTTPSConnectionPool, self)._validate_conn(conn)
    
        # Force connect early to allow us to validate the connection.
        if not getattr(conn, "sock", None):  # AppEngine might not have  `.sock`
>           conn.connect()

..\AppData\Local\Programs\Python\Python310\lib\site-packages\urllib3\connectionpool.py:1040: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

self = <urllib3.connection.HTTPSConnection object at 0x0000028D06DDC220>

    def connect(self):
        # Add certificate verification
        self.sock = conn = self._new_conn()
        hostname = self.host
        tls_in_tls = False
    
        if self._is_using_tunnel():
            if self.tls_in_tls_required:
                self.sock = conn = self._connect_tls_proxy(hostname, conn)
                tls_in_tls = True
    
            # Calls self._set_hostport(), so self.host is
            # self._tunnel_host below.
            self._tunnel()
            # Mark this connection as not reusable
            self.auto_open = 0
    
            # Override the host with the one we're requesting data from.
            hostname = self._tunnel_host
    
        server_hostname = hostname
        if self.server_hostname is not None:
            server_hostname = self.server_hostname
    
        is_time_off = datetime.date.today() < RECENT_DATE
        if is_time_off:
            warnings.warn(
                (
                    "System time is way off (before {0}). This will probably "
                    "lead to SSL verification errors"
                ).format(RECENT_DATE),
                SystemTimeWarning,
            )
    
        # Wrap socket using verification with the root certs in
        # trusted_root_certs
        default_ssl_context = False
        if self.ssl_context is None:
            default_ssl_context = True
            self.ssl_context = create_urllib3_context(
                ssl_version=resolve_ssl_version(self.ssl_version),
                cert_reqs=resolve_cert_reqs(self.cert_reqs),
            )
    
        context = self.ssl_context
        context.verify_mode = resolve_cert_reqs(self.cert_reqs)
    
        # Try to load OS default certs if none are given.
        # Works well on Windows (requires Python3.4+)
        if (
            not self.ca_certs
            and not self.ca_cert_dir
            and not self.ca_cert_data
            and default_ssl_context
            and hasattr(context, "load_default_certs")
        ):
            context.load_default_certs()
    
>       self.sock = ssl_wrap_socket(
            sock=conn,
            keyfile=self.key_file,
            certfile=self.cert_file,
            key_password=self.key_password,
            ca_certs=self.ca_certs,
            ca_cert_dir=self.ca_cert_dir,
            ca_cert_data=self.ca_cert_data,
            server_hostname=server_hostname,
            ssl_context=context,
            tls_in_tls=tls_in_tls,
        )

..\AppData\Local\Programs\Python\Python310\lib\site-packages\urllib3\connection.py:414: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

sock = <socket.socket [closed] fd=-1, family=AddressFamily.AF_INET, type=SocketKind.SOCK_STREAM, proto=0>
keyfile = None, certfile = None, cert_reqs = None
ca_certs = 'C:\\Users\\mamonask\\AppData\\Local\\Programs\\Python\\Python310\\lib\\site-packages\\certifi\\cacert.pem'
server_hostname = 'www.vz.lt', ssl_version = None, ciphers = None
ssl_context = <ssl.SSLContext object at 0x0000028D06439D40>, ca_cert_dir = None
key_password = None, ca_cert_data = None, tls_in_tls = False

    def ssl_wrap_socket(
        sock,
        keyfile=None,
        certfile=None,
        cert_reqs=None,
        ca_certs=None,
        server_hostname=None,
        ssl_version=None,
        ciphers=None,
        ssl_context=None,
        ca_cert_dir=None,
        key_password=None,
        ca_cert_data=None,
        tls_in_tls=False,
    ):
        """
        All arguments except for server_hostname, ssl_context, and ca_cert_dir have
        the same meaning as they do when using :func:`ssl.wrap_socket`.
    
        :param server_hostname:
            When SNI is supported, the expected hostname of the certificate
        :param ssl_context:
            A pre-made :class:`SSLContext` object. If none is provided, one will
            be created using :func:`create_urllib3_context`.
        :param ciphers:
            A string of ciphers we wish the client to support.
        :param ca_cert_dir:
            A directory containing CA certificates in multiple separate files, as
            supported by OpenSSL's -CApath flag or the capath argument to
            SSLContext.load_verify_locations().
        :param key_password:
            Optional password if the keyfile is encrypted.
        :param ca_cert_data:
            Optional string containing CA certificates in PEM format suitable for
            passing as the cadata parameter to SSLContext.load_verify_locations()
        :param tls_in_tls:
            Use SSLTransport to wrap the existing socket.
        """
        context = ssl_context
        if context is None:
            # Note: This branch of code and all the variables in it are no longer
            # used by urllib3 itself. We should consider deprecating and removing
            # this code.
            context = create_urllib3_context(ssl_version, cert_reqs, ciphers=ciphers)
    
        if ca_certs or ca_cert_dir or ca_cert_data:
            try:
                context.load_verify_locations(ca_certs, ca_cert_dir, ca_cert_data)
            except (IOError, OSError) as e:
                raise SSLError(e)
    
        elif ssl_context is None and hasattr(context, "load_default_certs"):
            # try to load OS default certs; works well on Windows (require Python3.4+)
            context.load_default_certs()
    
        # Attempt to detect if we get the goofy behavior of the
        # keyfile being encrypted and OpenSSL asking for the
        # passphrase via the terminal and instead error out.
        if keyfile and key_password is None and _is_key_file_encrypted(keyfile):
            raise SSLError("Client private key is encrypted, password is required")
    
        if certfile:
            if key_password is None:
                context.load_cert_chain(certfile, keyfile)
            else:
                context.load_cert_chain(certfile, keyfile, key_password)
    
        try:
            if hasattr(context, "set_alpn_protocols"):
                context.set_alpn_protocols(ALPN_PROTOCOLS)
        except NotImplementedError:  # Defensive: in CI, we always have set_alpn_protocols
            pass
    
        # If we detect server_hostname is an IP address then the SNI
        # extension should not be used according to RFC3546 Section 3.1
        use_sni_hostname = server_hostname and not is_ipaddress(server_hostname)
        # SecureTransport uses server_hostname in certificate verification.
        send_sni = (use_sni_hostname and HAS_SNI) or (
            IS_SECURETRANSPORT and server_hostname
        )
        # Do not warn the user if server_hostname is an invalid SNI hostname.
        if not HAS_SNI and use_sni_hostname:
            warnings.warn(
                "An HTTPS request has been made, but the SNI (Server Name "
                "Indication) extension to TLS is not available on this platform. "
                "This may cause the server to present an incorrect TLS "
                "certificate, which can cause validation failures. You can upgrade to "
                "a newer version of Python to solve this. For more information, see "
                "https://urllib3.readthedocs.io/en/1.26.x/advanced-usage.html"
                "#ssl-warnings",
                SNIMissingWarning,
            )
    
        if send_sni:
>           ssl_sock = _ssl_wrap_socket_impl(
                sock, context, tls_in_tls, server_hostname=server_hostname
            )

..\AppData\Local\Programs\Python\Python310\lib\site-packages\urllib3\util\ssl_.py:449: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

sock = <socket.socket [closed] fd=-1, family=AddressFamily.AF_INET, type=SocketKind.SOCK_STREAM, proto=0>
ssl_context = <ssl.SSLContext object at 0x0000028D06439D40>, tls_in_tls = False
server_hostname = 'www.vz.lt'

    def _ssl_wrap_socket_impl(sock, ssl_context, tls_in_tls, server_hostname=None):
        if tls_in_tls:
            if not SSLTransport:
                # Import error, ssl is not available.
                raise ProxySchemeUnsupported(
                    "TLS in TLS requires support for the 'ssl' module"
                )
    
            SSLTransport._validate_ssl_context_for_tls_in_tls(ssl_context)
            return SSLTransport(sock, ssl_context, server_hostname)
    
        if server_hostname:
>           return ssl_context.wrap_socket(sock, server_hostname=server_hostname)

..\AppData\Local\Programs\Python\Python310\lib\site-packages\urllib3\util\ssl_.py:493: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

self = <ssl.SSLContext object at 0x0000028D06439D40>
sock = <socket.socket [closed] fd=-1, family=AddressFamily.AF_INET, type=SocketKind.SOCK_STREAM, proto=0>
server_side = False, do_handshake_on_connect = True, suppress_ragged_eofs = True
server_hostname = 'www.vz.lt', session = None

    def wrap_socket(self, sock, server_side=False,
                    do_handshake_on_connect=True,
                    suppress_ragged_eofs=True,
                    server_hostname=None, session=None):
        # SSLSocket class handles server_hostname encoding before it calls
        # ctx._wrap_socket()
>       return self.sslsocket_class._create(
            sock=sock,
            server_side=server_side,
            do_handshake_on_connect=do_handshake_on_connect,
            suppress_ragged_eofs=suppress_ragged_eofs,
            server_hostname=server_hostname,
            context=self,
            session=session
        )

..\AppData\Local\Programs\Python\Python310\lib\ssl.py:512: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

cls = <class 'ssl.SSLSocket'>
sock = <socket.socket [closed] fd=-1, family=AddressFamily.AF_INET, type=SocketKind.SOCK_STREAM, proto=0>
server_side = False, do_handshake_on_connect = True, suppress_ragged_eofs = True
server_hostname = 'www.vz.lt'
context = <ssl.SSLContext object at 0x0000028D06439D40>, session = None

    @classmethod
    def _create(cls, sock, server_side=False, do_handshake_on_connect=True,
                suppress_ragged_eofs=True, server_hostname=None,
                context=None, session=None):
        if sock.getsockopt(SOL_SOCKET, SO_TYPE) != SOCK_STREAM:
            raise NotImplementedError("only stream sockets are supported")
        if server_side:
            if server_hostname:
                raise ValueError("server_hostname can only be specified "
                                 "in client mode")
            if session is not None:
                raise ValueError("session can only be specified in "
                                 "client mode")
        if context.check_hostname and not server_hostname:
            raise ValueError("check_hostname requires server_hostname")
    
        kwargs = dict(
            family=sock.family, type=sock.type, proto=sock.proto,
            fileno=sock.fileno()
        )
        self = cls.__new__(cls, **kwargs)
        super(SSLSocket, self).__init__(**kwargs)
        self.settimeout(sock.gettimeout())
        sock.detach()
    
        self._context = context
        self._session = session
        self._closed = False
        self._sslobj = None
        self.server_side = server_side
        self.server_hostname = context._encode_hostname(server_hostname)
        self.do_handshake_on_connect = do_handshake_on_connect
        self.suppress_ragged_eofs = suppress_ragged_eofs
    
        # See if we are connected
        try:
            self.getpeername()
        except OSError as e:
            if e.errno != errno.ENOTCONN:
                raise
            connected = False
        else:
            connected = True
    
        self._connected = connected
        if connected:
            # create the SSL object
            try:
                self._sslobj = self._context._wrap_socket(
                    self, server_side, self.server_hostname,
                    owner=self, session=self._session,
                )
                if do_handshake_on_connect:
                    timeout = self.gettimeout()
                    if timeout == 0.0:
                        # non-blocking
                        raise ValueError("do_handshake_on_connect should not be specified for non-blocking sockets")
>                   self.do_handshake()

..\AppData\Local\Programs\Python\Python310\lib\ssl.py:1070: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

self = <ssl.SSLSocket [closed] fd=-1, family=AddressFamily.AF_INET, type=SocketKind.SOCK_STREAM, proto=0>
block = False

    @_sslcopydoc
    def do_handshake(self, block=False):
        self._check_connected()
        timeout = self.gettimeout()
        try:
            if timeout == 0.0 and block:
                self.settimeout(None)
>           self._sslobj.do_handshake()
E           ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:997)

..\AppData\Local\Programs\Python\Python310\lib\ssl.py:1341: SSLCertVerificationError

During handling of the above exception, another exception occurred:

self = <requests.adapters.HTTPAdapter object at 0x0000028D06DDCA00>
request = <PreparedRequest [GET]>, stream = False
timeout = Timeout(connect=None, read=None, total=None), verify = True
cert = None, proxies = OrderedDict()

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        """Sends PreparedRequest object. Returns Response object.
    
        :param request: The :class:`PreparedRequest <PreparedRequest>` being sent.
        :param stream: (optional) Whether to stream the request content.
        :param timeout: (optional) How long to wait for the server to send
            data before giving up, as a float, or a :ref:`(connect timeout,
            read timeout) <timeouts>` tuple.
        :type timeout: float or tuple or urllib3 Timeout object
        :param verify: (optional) Either a boolean, in which case it controls whether
            we verify the server's TLS certificate, or a string, in which case it
            must be a path to a CA bundle to use
        :param cert: (optional) Any user-provided SSL certificate to be trusted.
        :param proxies: (optional) The proxies dictionary to apply to the request.
        :rtype: requests.Response
        """
    
        try:
            conn = self.get_connection(request.url, proxies)
        except LocationValueError as e:
            raise InvalidURL(e, request=request)
    
        self.cert_verify(conn, request.url, verify, cert)
        url = self.request_url(request, proxies)
        self.add_headers(request, stream=stream, timeout=timeout, verify=verify, cert=cert, proxies=proxies)
    
        chunked = not (request.body is None or 'Content-Length' in request.headers)
    
        if isinstance(timeout, tuple):
            try:
                connect, read = timeout
                timeout = TimeoutSauce(connect=connect, read=read)
            except ValueError as e:
                # this may raise a string formatting error.
                err = ("Invalid timeout {}. Pass a (connect, read) "
                       "timeout tuple, or a single float to set "
                       "both timeouts to the same value".format(timeout))
                raise ValueError(err)
        elif isinstance(timeout, TimeoutSauce):
            pass
        else:
            timeout = TimeoutSauce(connect=timeout, read=timeout)
    
        try:
            if not chunked:
>               resp = conn.urlopen(
                    method=request.method,
                    url=url,
                    body=request.body,
                    headers=request.headers,
                    redirect=False,
                    assert_same_host=False,
                    preload_content=False,
                    decode_content=False,
                    retries=self.max_retries,
                    timeout=timeout
                )

..\AppData\Local\Programs\Python\Python310\lib\site-packages\requests\adapters.py:440: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

self = <urllib3.connectionpool.HTTPSConnectionPool object at 0x0000028D06DDCA30>
method = 'GET', url = '/visos-naujienos?pageno=0', body = None
headers = {'User-Agent': 'python-requests/2.27.1', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Connection': 'keep-alive'}
retries = Retry(total=0, connect=None, read=False, redirect=None, status=None)
redirect = False, assert_same_host = False
timeout = Timeout(connect=None, read=None, total=None), pool_timeout = None
release_conn = False, chunked = False, body_pos = None
response_kw = {'decode_content': False, 'preload_content': False}
parsed_url = Url(scheme=None, auth=None, host=None, port=None, path='/visos-naujienos', query='pageno=0', fragment=None)
destination_scheme = None, conn = None, release_this_conn = True
http_tunnel_required = False, err = None, clean_exit = False

    def urlopen(
        self,
        method,
        url,
        body=None,
        headers=None,
        retries=None,
        redirect=True,
        assert_same_host=True,
        timeout=_Default,
        pool_timeout=None,
        release_conn=None,
        chunked=False,
        body_pos=None,
        **response_kw
    ):
        """
        Get a connection from the pool and perform an HTTP request. This is the
        lowest level call for making a request, so you'll need to specify all
        the raw details.
    
        .. note::
    
           More commonly, it's appropriate to use a convenience method provided
           by :class:`.RequestMethods`, such as :meth:`request`.
    
        .. note::
    
           `release_conn` will only behave as expected if
           `preload_content=False` because we want to make
           `preload_content=False` the default behaviour someday soon without
           breaking backwards compatibility.
    
        :param method:
            HTTP request method (such as GET, POST, PUT, etc.)
    
        :param url:
            The URL to perform the request on.
    
        :param body:
            Data to send in the request body, either :class:`str`, :class:`bytes`,
            an iterable of :class:`str`/:class:`bytes`, or a file-like object.
    
        :param headers:
            Dictionary of custom headers to send, such as User-Agent,
            If-None-Match, etc. If None, pool headers are used. If provided,
            these headers completely replace any pool-specific headers.
    
        :param retries:
            Configure the number of retries to allow before raising a
            :class:`~urllib3.exceptions.MaxRetryError` exception.
    
            Pass ``None`` to retry until you receive a response. Pass a
            :class:`~urllib3.util.retry.Retry` object for fine-grained control
            over different types of retries.
            Pass an integer number to retry connection errors that many times,
            but no other types of errors. Pass zero to never retry.
    
            If ``False``, then retries are disabled and any exception is raised
            immediately. Also, instead of raising a MaxRetryError on redirects,
            the redirect response will be returned.
    
        :type retries: :class:`~urllib3.util.retry.Retry`, False, or an int.
    
        :param redirect:
            If True, automatically handle redirects (status codes 301, 302,
            303, 307, 308). Each redirect counts as a retry. Disabling retries
            will disable redirect, too.
    
        :param assert_same_host:
            If ``True``, will make sure that the host of the pool requests is
            consistent else will raise HostChangedError. When ``False``, you can
            use the pool on an HTTP proxy and request foreign hosts.
    
        :param timeout:
            If specified, overrides the default timeout for this one
            request. It may be a float (in seconds) or an instance of
            :class:`urllib3.util.Timeout`.
    
        :param pool_timeout:
            If set and the pool is set to block=True, then this method will
            block for ``pool_timeout`` seconds and raise EmptyPoolError if no
            connection is available within the time period.
    
        :param release_conn:
            If False, then the urlopen call will not release the connection
            back into the pool once a response is received (but will release if
            you read the entire contents of the response such as when
            `preload_content=True`). This is useful if you're not preloading
            the response's content immediately. You will need to call
            ``r.release_conn()`` on the response ``r`` to return the connection
            back into the pool. If None, it takes the value of
            ``response_kw.get('preload_content', True)``.
    
        :param chunked:
            If True, urllib3 will send the body using chunked transfer
            encoding. Otherwise, urllib3 will send the body using the standard
            content-length form. Defaults to False.
    
        :param int body_pos:
            Position to seek to in file-like body in the event of a retry or
            redirect. Typically this won't need to be set because urllib3 will
            auto-populate the value when needed.
    
        :param \\**response_kw:
            Additional parameters are passed to
            :meth:`urllib3.response.HTTPResponse.from_httplib`
        """
    
        parsed_url = parse_url(url)
        destination_scheme = parsed_url.scheme
    
        if headers is None:
            headers = self.headers
    
        if not isinstance(retries, Retry):
            retries = Retry.from_int(retries, redirect=redirect, default=self.retries)
    
        if release_conn is None:
            release_conn = response_kw.get("preload_content", True)
    
        # Check host
        if assert_same_host and not self.is_same_host(url):
            raise HostChangedError(self, url, retries)
    
        # Ensure that the URL we're connecting to is properly encoded
        if url.startswith("/"):
            url = six.ensure_str(_encode_target(url))
        else:
            url = six.ensure_str(parsed_url.url)
    
        conn = None
    
        # Track whether `conn` needs to be released before
        # returning/raising/recursing. Update this variable if necessary, and
        # leave `release_conn` constant throughout the function. That way, if
        # the function recurses, the original value of `release_conn` will be
        # passed down into the recursive call, and its value will be respected.
        #
        # See issue #651 [1] for details.
        #
        # [1] <https://github.com/urllib3/urllib3/issues/651>
        release_this_conn = release_conn
    
        http_tunnel_required = connection_requires_http_tunnel(
            self.proxy, self.proxy_config, destination_scheme
        )
    
        # Merge the proxy headers. Only done when not using HTTP CONNECT. We
        # have to copy the headers dict so we can safely change it without those
        # changes being reflected in anyone else's copy.
        if not http_tunnel_required:
            headers = headers.copy()
            headers.update(self.proxy_headers)
    
        # Must keep the exception bound to a separate variable or else Python 3
        # complains about UnboundLocalError.
        err = None
    
        # Keep track of whether we cleanly exited the except block. This
        # ensures we do proper cleanup in finally.
        clean_exit = False
    
        # Rewind body position, if needed. Record current position
        # for future rewinds in the event of a redirect/retry.
        body_pos = set_file_position(body, body_pos)
    
        try:
            # Request a connection from the queue.
            timeout_obj = self._get_timeout(timeout)
            conn = self._get_conn(timeout=pool_timeout)
    
            conn.timeout = timeout_obj.connect_timeout
    
            is_new_proxy_conn = self.proxy is not None and not getattr(
                conn, "sock", None
            )
            if is_new_proxy_conn and http_tunnel_required:
                self._prepare_proxy(conn)
    
            # Make the request on the httplib connection object.
            httplib_response = self._make_request(
                conn,
                method,
                url,
                timeout=timeout_obj,
                body=body,
                headers=headers,
                chunked=chunked,
            )
    
            # If we're going to release the connection in ``finally:``, then
            # the response doesn't need to know about the connection. Otherwise
            # it will also try to release it and we'll have a double-release
            # mess.
            response_conn = conn if not release_conn else None
    
            # Pass method to Response for length checking
            response_kw["request_method"] = method
    
            # Import httplib's response into our own wrapper object
            response = self.ResponseCls.from_httplib(
                httplib_response,
                pool=self,
                connection=response_conn,
                retries=retries,
                **response_kw
            )
    
            # Everything went great!
            clean_exit = True
    
        except EmptyPoolError:
            # Didn't get a connection from the pool, no need to clean up
            clean_exit = True
            release_this_conn = False
            raise
    
        except (
            TimeoutError,
            HTTPException,
            SocketError,
            ProtocolError,
            BaseSSLError,
            SSLError,
            CertificateError,
        ) as e:
            # Discard the connection for these exceptions. It will be
            # replaced during the next _get_conn() call.
            clean_exit = False
    
            def _is_ssl_error_message_from_http_proxy(ssl_error):
                # We're trying to detect the message 'WRONG_VERSION_NUMBER' but
                # SSLErrors are kinda all over the place when it comes to the message,
                # so we try to cover our bases here!
                message = " ".join(re.split("[^a-z]", str(ssl_error).lower()))
                return (
                    "wrong version number" in message or "unknown protocol" in message
                )
    
            # Try to detect a common user error with proxies which is to
            # set an HTTP proxy to be HTTPS when it should be 'http://'
            # (ie {'http': 'http://proxy', 'https': 'https://proxy'})
            # Instead we add a nice error message and point to a URL.
            if (
                isinstance(e, BaseSSLError)
                and self.proxy
                and _is_ssl_error_message_from_http_proxy(e)
            ):
                e = ProxyError(
                    "Your proxy appears to only use HTTP and not HTTPS, "
                    "try changing your proxy URL to be HTTP. See: "
                    "https://urllib3.readthedocs.io/en/1.26.x/advanced-usage.html"
                    "#https-proxy-error-http-proxy",
                    SSLError(e),
                )
            elif isinstance(e, (BaseSSLError, CertificateError)):
                e = SSLError(e)
            elif isinstance(e, (SocketError, NewConnectionError)) and self.proxy:
                e = ProxyError("Cannot connect to proxy.", e)
            elif isinstance(e, (SocketError, HTTPException)):
                e = ProtocolError("Connection aborted.", e)
    
>           retries = retries.increment(
                method, url, error=e, _pool=self, _stacktrace=sys.exc_info()[2]
            )

..\AppData\Local\Programs\Python\Python310\lib\site-packages\urllib3\connectionpool.py:785: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

self = Retry(total=0, connect=None, read=False, redirect=None, status=None)
method = 'GET', url = '/visos-naujienos?pageno=0', response = None
error = SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:997)'))
_pool = <urllib3.connectionpool.HTTPSConnectionPool object at 0x0000028D06DDCA30>
_stacktrace = <traceback object at 0x0000028D06D450C0>

    def increment(
        self,
        method=None,
        url=None,
        response=None,
        error=None,
        _pool=None,
        _stacktrace=None,
    ):
        """Return a new Retry object with incremented retry counters.
    
        :param response: A response object, or None, if the server did not
            return a response.
        :type response: :class:`~urllib3.response.HTTPResponse`
        :param Exception error: An error encountered during the request, or
            None if the response was received successfully.
    
        :return: A new ``Retry`` object.
        """
        if self.total is False and error:
            # Disabled, indicate to re-raise the error.
            raise six.reraise(type(error), error, _stacktrace)
    
        total = self.total
        if total is not None:
            total -= 1
    
        connect = self.connect
        read = self.read
        redirect = self.redirect
        status_count = self.status
        other = self.other
        cause = "unknown"
        status = None
        redirect_location = None
    
        if error and self._is_connection_error(error):
            # Connect retry?
            if connect is False:
                raise six.reraise(type(error), error, _stacktrace)
            elif connect is not None:
                connect -= 1
    
        elif error and self._is_read_error(error):
            # Read retry?
            if read is False or not self._is_method_retryable(method):
                raise six.reraise(type(error), error, _stacktrace)
            elif read is not None:
                read -= 1
    
        elif error:
            # Other retry?
            if other is not None:
                other -= 1
    
        elif response and response.get_redirect_location():
            # Redirect retry?
            if redirect is not None:
                redirect -= 1
            cause = "too many redirects"
            redirect_location = response.get_redirect_location()
            status = response.status
    
        else:
            # Incrementing because of a server error like a 500 in
            # status_forcelist and the given method is in the allowed_methods
            cause = ResponseError.GENERIC_ERROR
            if response and response.status:
                if status_count is not None:
                    status_count -= 1
                cause = ResponseError.SPECIFIC_ERROR.format(status_code=response.status)
                status = response.status
    
        history = self.history + (
            RequestHistory(method, url, error, status, redirect_location),
        )
    
        new_retry = self.new(
            total=total,
            connect=connect,
            read=read,
            redirect=redirect,
            status=status_count,
            other=other,
            history=history,
        )
    
        if new_retry.is_exhausted():
>           raise MaxRetryError(_pool, url, error or ResponseError(cause))
E           urllib3.exceptions.MaxRetryError: HTTPSConnectionPool(host='www.vz.lt', port=443): Max retries exceeded with url: /visos-naujienos?pageno=0 (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:997)')))

..\AppData\Local\Programs\Python\Python310\lib\site-packages\urllib3\util\retry.py:592: MaxRetryError

During handling of the above exception, another exception occurred:

    def test_get_articles_in_page():
        # Test VZ
>       r = scraper._get_response(page="vz")

test_main.py:21: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _
main.py:35: in _get_response
    r = requests.get(url=self.URL[page])
..\AppData\Local\Programs\Python\Python310\lib\site-packages\requests\api.py:75: in get
    return request('get', url, params=params, **kwargs)
..\AppData\Local\Programs\Python\Python310\lib\site-packages\requests\api.py:61: in request
    return session.request(method=method, url=url, **kwargs)
..\AppData\Local\Programs\Python\Python310\lib\site-packages\requests\sessions.py:529: in request
    resp = self.send(prep, **send_kwargs)
..\AppData\Local\Programs\Python\Python310\lib\site-packages\requests\sessions.py:645: in send
    r = adapter.send(request, **kwargs)
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

self = <requests.adapters.HTTPAdapter object at 0x0000028D06DDCA00>
request = <PreparedRequest [GET]>, stream = False
timeout = Timeout(connect=None, read=None, total=None), verify = True
cert = None, proxies = OrderedDict()

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        """Sends PreparedRequest object. Returns Response object.
    
        :param request: The :class:`PreparedRequest <PreparedRequest>` being sent.
        :param stream: (optional) Whether to stream the request content.
        :param timeout: (optional) How long to wait for the server to send
            data before giving up, as a float, or a :ref:`(connect timeout,
            read timeout) <timeouts>` tuple.
        :type timeout: float or tuple or urllib3 Timeout object
        :param verify: (optional) Either a boolean, in which case it controls whether
            we verify the server's TLS certificate, or a string, in which case it
            must be a path to a CA bundle to use
        :param cert: (optional) Any user-provided SSL certificate to be trusted.
        :param proxies: (optional) The proxies dictionary to apply to the request.
        :rtype: requests.Response
        """
    
        try:
            conn = self.get_connection(request.url, proxies)
        except LocationValueError as e:
            raise InvalidURL(e, request=request)
    
        self.cert_verify(conn, request.url, verify, cert)
        url = self.request_url(request, proxies)
        self.add_headers(request, stream=stream, timeout=timeout, verify=verify, cert=cert, proxies=proxies)
    
        chunked = not (request.body is None or 'Content-Length' in request.headers)
    
        if isinstance(timeout, tuple):
            try:
                connect, read = timeout
                timeout = TimeoutSauce(connect=connect, read=read)
            except ValueError as e:
                # this may raise a string formatting error.
                err = ("Invalid timeout {}. Pass a (connect, read) "
                       "timeout tuple, or a single float to set "
                       "both timeouts to the same value".format(timeout))
                raise ValueError(err)
        elif isinstance(timeout, TimeoutSauce):
            pass
        else:
            timeout = TimeoutSauce(connect=timeout, read=timeout)
    
        try:
            if not chunked:
                resp = conn.urlopen(
                    method=request.method,
                    url=url,
                    body=request.body,
                    headers=request.headers,
                    redirect=False,
                    assert_same_host=False,
                    preload_content=False,
                    decode_content=False,
                    retries=self.max_retries,
                    timeout=timeout
                )
    
            # Send the request.
            else:
                if hasattr(conn, 'proxy_pool'):
                    conn = conn.proxy_pool
    
                low_conn = conn._get_conn(timeout=DEFAULT_POOL_TIMEOUT)
    
                try:
                    skip_host = 'Host' in request.headers
                    low_conn.putrequest(request.method,
                                        url,
                                        skip_accept_encoding=True,
                                        skip_host=skip_host)
    
                    for header, value in request.headers.items():
                        low_conn.putheader(header, value)
    
                    low_conn.endheaders()
    
                    for i in request.body:
                        low_conn.send(hex(len(i))[2:].encode('utf-8'))
                        low_conn.send(b'\r\n')
                        low_conn.send(i)
                        low_conn.send(b'\r\n')
                    low_conn.send(b'0\r\n\r\n')
    
                    # Receive the response from the server
                    try:
                        # For Python 2.7, use buffering of HTTP responses
                        r = low_conn.getresponse(buffering=True)
                    except TypeError:
                        # For compatibility with Python 3.3+
                        r = low_conn.getresponse()
    
                    resp = HTTPResponse.from_httplib(
                        r,
                        pool=conn,
                        connection=low_conn,
                        preload_content=False,
                        decode_content=False
                    )
                except:
                    # If we hit any problems here, clean up the connection.
                    # Then, reraise so that we can handle the actual exception.
                    low_conn.close()
                    raise
    
        except (ProtocolError, socket.error) as err:
            raise ConnectionError(err, request=request)
    
        except MaxRetryError as e:
            if isinstance(e.reason, ConnectTimeoutError):
                # TODO: Remove this in 3.0.0: see #2811
                if not isinstance(e.reason, NewConnectionError):
                    raise ConnectTimeout(e, request=request)
    
            if isinstance(e.reason, ResponseError):
                raise RetryError(e, request=request)
    
            if isinstance(e.reason, _ProxyError):
                raise ProxyError(e, request=request)
    
            if isinstance(e.reason, _SSLError):
                # This branch is for urllib3 v1.22 and later.
>               raise SSLError(e, request=request)
E               requests.exceptions.SSLError: HTTPSConnectionPool(host='www.vz.lt', port=443): Max retries exceeded with url: /visos-naujienos?pageno=0 (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:997)')))

..\AppData\Local\Programs\Python\Python310\lib\site-packages\requests\adapters.py:517: SSLError
__________________________ test_get_article_details ___________________________

self = <urllib3.connectionpool.HTTPSConnectionPool object at 0x0000028D06CFBBB0>
method = 'GET', url = '/visos-naujienos?pageno=0', body = None
headers = {'User-Agent': 'python-requests/2.27.1', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Connection': 'keep-alive'}
retries = Retry(total=0, connect=None, read=False, redirect=None, status=None)
redirect = False, assert_same_host = False
timeout = Timeout(connect=None, read=None, total=None), pool_timeout = None
release_conn = False, chunked = False, body_pos = None
response_kw = {'decode_content': False, 'preload_content': False}
parsed_url = Url(scheme=None, auth=None, host=None, port=None, path='/visos-naujienos', query='pageno=0', fragment=None)
destination_scheme = None, conn = None, release_this_conn = True
http_tunnel_required = False, err = None, clean_exit = False

    def urlopen(
        self,
        method,
        url,
        body=None,
        headers=None,
        retries=None,
        redirect=True,
        assert_same_host=True,
        timeout=_Default,
        pool_timeout=None,
        release_conn=None,
        chunked=False,
        body_pos=None,
        **response_kw
    ):
        """
        Get a connection from the pool and perform an HTTP request. This is the
        lowest level call for making a request, so you'll need to specify all
        the raw details.
    
        .. note::
    
           More commonly, it's appropriate to use a convenience method provided
           by :class:`.RequestMethods`, such as :meth:`request`.
    
        .. note::
    
           `release_conn` will only behave as expected if
           `preload_content=False` because we want to make
           `preload_content=False` the default behaviour someday soon without
           breaking backwards compatibility.
    
        :param method:
            HTTP request method (such as GET, POST, PUT, etc.)
    
        :param url:
            The URL to perform the request on.
    
        :param body:
            Data to send in the request body, either :class:`str`, :class:`bytes`,
            an iterable of :class:`str`/:class:`bytes`, or a file-like object.
    
        :param headers:
            Dictionary of custom headers to send, such as User-Agent,
            If-None-Match, etc. If None, pool headers are used. If provided,
            these headers completely replace any pool-specific headers.
    
        :param retries:
            Configure the number of retries to allow before raising a
            :class:`~urllib3.exceptions.MaxRetryError` exception.
    
            Pass ``None`` to retry until you receive a response. Pass a
            :class:`~urllib3.util.retry.Retry` object for fine-grained control
            over different types of retries.
            Pass an integer number to retry connection errors that many times,
            but no other types of errors. Pass zero to never retry.
    
            If ``False``, then retries are disabled and any exception is raised
            immediately. Also, instead of raising a MaxRetryError on redirects,
            the redirect response will be returned.
    
        :type retries: :class:`~urllib3.util.retry.Retry`, False, or an int.
    
        :param redirect:
            If True, automatically handle redirects (status codes 301, 302,
            303, 307, 308). Each redirect counts as a retry. Disabling retries
            will disable redirect, too.
    
        :param assert_same_host:
            If ``True``, will make sure that the host of the pool requests is
            consistent else will raise HostChangedError. When ``False``, you can
            use the pool on an HTTP proxy and request foreign hosts.
    
        :param timeout:
            If specified, overrides the default timeout for this one
            request. It may be a float (in seconds) or an instance of
            :class:`urllib3.util.Timeout`.
    
        :param pool_timeout:
            If set and the pool is set to block=True, then this method will
            block for ``pool_timeout`` seconds and raise EmptyPoolError if no
            connection is available within the time period.
    
        :param release_conn:
            If False, then the urlopen call will not release the connection
            back into the pool once a response is received (but will release if
            you read the entire contents of the response such as when
            `preload_content=True`). This is useful if you're not preloading
            the response's content immediately. You will need to call
            ``r.release_conn()`` on the response ``r`` to return the connection
            back into the pool. If None, it takes the value of
            ``response_kw.get('preload_content', True)``.
    
        :param chunked:
            If True, urllib3 will send the body using chunked transfer
            encoding. Otherwise, urllib3 will send the body using the standard
            content-length form. Defaults to False.
    
        :param int body_pos:
            Position to seek to in file-like body in the event of a retry or
            redirect. Typically this won't need to be set because urllib3 will
            auto-populate the value when needed.
    
        :param \\**response_kw:
            Additional parameters are passed to
            :meth:`urllib3.response.HTTPResponse.from_httplib`
        """
    
        parsed_url = parse_url(url)
        destination_scheme = parsed_url.scheme
    
        if headers is None:
            headers = self.headers
    
        if not isinstance(retries, Retry):
            retries = Retry.from_int(retries, redirect=redirect, default=self.retries)
    
        if release_conn is None:
            release_conn = response_kw.get("preload_content", True)
    
        # Check host
        if assert_same_host and not self.is_same_host(url):
            raise HostChangedError(self, url, retries)
    
        # Ensure that the URL we're connecting to is properly encoded
        if url.startswith("/"):
            url = six.ensure_str(_encode_target(url))
        else:
            url = six.ensure_str(parsed_url.url)
    
        conn = None
    
        # Track whether `conn` needs to be released before
        # returning/raising/recursing. Update this variable if necessary, and
        # leave `release_conn` constant throughout the function. That way, if
        # the function recurses, the original value of `release_conn` will be
        # passed down into the recursive call, and its value will be respected.
        #
        # See issue #651 [1] for details.
        #
        # [1] <https://github.com/urllib3/urllib3/issues/651>
        release_this_conn = release_conn
    
        http_tunnel_required = connection_requires_http_tunnel(
            self.proxy, self.proxy_config, destination_scheme
        )
    
        # Merge the proxy headers. Only done when not using HTTP CONNECT. We
        # have to copy the headers dict so we can safely change it without those
        # changes being reflected in anyone else's copy.
        if not http_tunnel_required:
            headers = headers.copy()
            headers.update(self.proxy_headers)
    
        # Must keep the exception bound to a separate variable or else Python 3
        # complains about UnboundLocalError.
        err = None
    
        # Keep track of whether we cleanly exited the except block. This
        # ensures we do proper cleanup in finally.
        clean_exit = False
    
        # Rewind body position, if needed. Record current position
        # for future rewinds in the event of a redirect/retry.
        body_pos = set_file_position(body, body_pos)
    
        try:
            # Request a connection from the queue.
            timeout_obj = self._get_timeout(timeout)
            conn = self._get_conn(timeout=pool_timeout)
    
            conn.timeout = timeout_obj.connect_timeout
    
            is_new_proxy_conn = self.proxy is not None and not getattr(
                conn, "sock", None
            )
            if is_new_proxy_conn and http_tunnel_required:
                self._prepare_proxy(conn)
    
            # Make the request on the httplib connection object.
>           httplib_response = self._make_request(
                conn,
                method,
                url,
                timeout=timeout_obj,
                body=body,
                headers=headers,
                chunked=chunked,
            )

..\AppData\Local\Programs\Python\Python310\lib\site-packages\urllib3\connectionpool.py:703: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

self = <urllib3.connectionpool.HTTPSConnectionPool object at 0x0000028D06CFBBB0>
conn = <urllib3.connection.HTTPSConnection object at 0x0000028D06CF81F0>
method = 'GET', url = '/visos-naujienos?pageno=0'
timeout = Timeout(connect=None, read=None, total=None), chunked = False
httplib_request_kw = {'body': None, 'headers': {'User-Agent': 'python-requests/2.27.1', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Connection': 'keep-alive'}}
timeout_obj = Timeout(connect=None, read=None, total=None)

    def _make_request(
        self, conn, method, url, timeout=_Default, chunked=False, **httplib_request_kw
    ):
        """
        Perform a request on a given urllib connection object taken from our
        pool.
    
        :param conn:
            a connection from one of our connection pools
    
        :param timeout:
            Socket timeout in seconds for the request. This can be a
            float or integer, which will set the same timeout value for
            the socket connect and the socket read, or an instance of
            :class:`urllib3.util.Timeout`, which gives you more fine-grained
            control over your timeouts.
        """
        self.num_requests += 1
    
        timeout_obj = self._get_timeout(timeout)
        timeout_obj.start_connect()
        conn.timeout = timeout_obj.connect_timeout
    
        # Trigger any extra validation we need to do.
        try:
>           self._validate_conn(conn)

..\AppData\Local\Programs\Python\Python310\lib\site-packages\urllib3\connectionpool.py:386: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

self = <urllib3.connectionpool.HTTPSConnectionPool object at 0x0000028D06CFBBB0>
conn = <urllib3.connection.HTTPSConnection object at 0x0000028D06CF81F0>

    def _validate_conn(self, conn):
        """
        Called right before a request is made, after the socket is created.
        """
        super(HTTPSConnectionPool, self)._validate_conn(conn)
    
        # Force connect early to allow us to validate the connection.
        if not getattr(conn, "sock", None):  # AppEngine might not have  `.sock`
>           conn.connect()

..\AppData\Local\Programs\Python\Python310\lib\site-packages\urllib3\connectionpool.py:1040: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

self = <urllib3.connection.HTTPSConnection object at 0x0000028D06CF81F0>

    def connect(self):
        # Add certificate verification
        self.sock = conn = self._new_conn()
        hostname = self.host
        tls_in_tls = False
    
        if self._is_using_tunnel():
            if self.tls_in_tls_required:
                self.sock = conn = self._connect_tls_proxy(hostname, conn)
                tls_in_tls = True
    
            # Calls self._set_hostport(), so self.host is
            # self._tunnel_host below.
            self._tunnel()
            # Mark this connection as not reusable
            self.auto_open = 0
    
            # Override the host with the one we're requesting data from.
            hostname = self._tunnel_host
    
        server_hostname = hostname
        if self.server_hostname is not None:
            server_hostname = self.server_hostname
    
        is_time_off = datetime.date.today() < RECENT_DATE
        if is_time_off:
            warnings.warn(
                (
                    "System time is way off (before {0}). This will probably "
                    "lead to SSL verification errors"
                ).format(RECENT_DATE),
                SystemTimeWarning,
            )
    
        # Wrap socket using verification with the root certs in
        # trusted_root_certs
        default_ssl_context = False
        if self.ssl_context is None:
            default_ssl_context = True
            self.ssl_context = create_urllib3_context(
                ssl_version=resolve_ssl_version(self.ssl_version),
                cert_reqs=resolve_cert_reqs(self.cert_reqs),
            )
    
        context = self.ssl_context
        context.verify_mode = resolve_cert_reqs(self.cert_reqs)
    
        # Try to load OS default certs if none are given.
        # Works well on Windows (requires Python3.4+)
        if (
            not self.ca_certs
            and not self.ca_cert_dir
            and not self.ca_cert_data
            and default_ssl_context
            and hasattr(context, "load_default_certs")
        ):
            context.load_default_certs()
    
>       self.sock = ssl_wrap_socket(
            sock=conn,
            keyfile=self.key_file,
            certfile=self.cert_file,
            key_password=self.key_password,
            ca_certs=self.ca_certs,
            ca_cert_dir=self.ca_cert_dir,
            ca_cert_data=self.ca_cert_data,
            server_hostname=server_hostname,
            ssl_context=context,
            tls_in_tls=tls_in_tls,
        )

..\AppData\Local\Programs\Python\Python310\lib\site-packages\urllib3\connection.py:414: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

sock = <socket.socket [closed] fd=-1, family=AddressFamily.AF_INET, type=SocketKind.SOCK_STREAM, proto=0>
keyfile = None, certfile = None, cert_reqs = None
ca_certs = 'C:\\Users\\mamonask\\AppData\\Local\\Programs\\Python\\Python310\\lib\\site-packages\\certifi\\cacert.pem'
server_hostname = 'www.vz.lt', ssl_version = None, ciphers = None
ssl_context = <ssl.SSLContext object at 0x0000028D06444740>, ca_cert_dir = None
key_password = None, ca_cert_data = None, tls_in_tls = False

    def ssl_wrap_socket(
        sock,
        keyfile=None,
        certfile=None,
        cert_reqs=None,
        ca_certs=None,
        server_hostname=None,
        ssl_version=None,
        ciphers=None,
        ssl_context=None,
        ca_cert_dir=None,
        key_password=None,
        ca_cert_data=None,
        tls_in_tls=False,
    ):
        """
        All arguments except for server_hostname, ssl_context, and ca_cert_dir have
        the same meaning as they do when using :func:`ssl.wrap_socket`.
    
        :param server_hostname:
            When SNI is supported, the expected hostname of the certificate
        :param ssl_context:
            A pre-made :class:`SSLContext` object. If none is provided, one will
            be created using :func:`create_urllib3_context`.
        :param ciphers:
            A string of ciphers we wish the client to support.
        :param ca_cert_dir:
            A directory containing CA certificates in multiple separate files, as
            supported by OpenSSL's -CApath flag or the capath argument to
            SSLContext.load_verify_locations().
        :param key_password:
            Optional password if the keyfile is encrypted.
        :param ca_cert_data:
            Optional string containing CA certificates in PEM format suitable for
            passing as the cadata parameter to SSLContext.load_verify_locations()
        :param tls_in_tls:
            Use SSLTransport to wrap the existing socket.
        """
        context = ssl_context
        if context is None:
            # Note: This branch of code and all the variables in it are no longer
            # used by urllib3 itself. We should consider deprecating and removing
            # this code.
            context = create_urllib3_context(ssl_version, cert_reqs, ciphers=ciphers)
    
        if ca_certs or ca_cert_dir or ca_cert_data:
            try:
                context.load_verify_locations(ca_certs, ca_cert_dir, ca_cert_data)
            except (IOError, OSError) as e:
                raise SSLError(e)
    
        elif ssl_context is None and hasattr(context, "load_default_certs"):
            # try to load OS default certs; works well on Windows (require Python3.4+)
            context.load_default_certs()
    
        # Attempt to detect if we get the goofy behavior of the
        # keyfile being encrypted and OpenSSL asking for the
        # passphrase via the terminal and instead error out.
        if keyfile and key_password is None and _is_key_file_encrypted(keyfile):
            raise SSLError("Client private key is encrypted, password is required")
    
        if certfile:
            if key_password is None:
                context.load_cert_chain(certfile, keyfile)
            else:
                context.load_cert_chain(certfile, keyfile, key_password)
    
        try:
            if hasattr(context, "set_alpn_protocols"):
                context.set_alpn_protocols(ALPN_PROTOCOLS)
        except NotImplementedError:  # Defensive: in CI, we always have set_alpn_protocols
            pass
    
        # If we detect server_hostname is an IP address then the SNI
        # extension should not be used according to RFC3546 Section 3.1
        use_sni_hostname = server_hostname and not is_ipaddress(server_hostname)
        # SecureTransport uses server_hostname in certificate verification.
        send_sni = (use_sni_hostname and HAS_SNI) or (
            IS_SECURETRANSPORT and server_hostname
        )
        # Do not warn the user if server_hostname is an invalid SNI hostname.
        if not HAS_SNI and use_sni_hostname:
            warnings.warn(
                "An HTTPS request has been made, but the SNI (Server Name "
                "Indication) extension to TLS is not available on this platform. "
                "This may cause the server to present an incorrect TLS "
                "certificate, which can cause validation failures. You can upgrade to "
                "a newer version of Python to solve this. For more information, see "
                "https://urllib3.readthedocs.io/en/1.26.x/advanced-usage.html"
                "#ssl-warnings",
                SNIMissingWarning,
            )
    
        if send_sni:
>           ssl_sock = _ssl_wrap_socket_impl(
                sock, context, tls_in_tls, server_hostname=server_hostname
            )

..\AppData\Local\Programs\Python\Python310\lib\site-packages\urllib3\util\ssl_.py:449: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

sock = <socket.socket [closed] fd=-1, family=AddressFamily.AF_INET, type=SocketKind.SOCK_STREAM, proto=0>
ssl_context = <ssl.SSLContext object at 0x0000028D06444740>, tls_in_tls = False
server_hostname = 'www.vz.lt'

    def _ssl_wrap_socket_impl(sock, ssl_context, tls_in_tls, server_hostname=None):
        if tls_in_tls:
            if not SSLTransport:
                # Import error, ssl is not available.
                raise ProxySchemeUnsupported(
                    "TLS in TLS requires support for the 'ssl' module"
                )
    
            SSLTransport._validate_ssl_context_for_tls_in_tls(ssl_context)
            return SSLTransport(sock, ssl_context, server_hostname)
    
        if server_hostname:
>           return ssl_context.wrap_socket(sock, server_hostname=server_hostname)

..\AppData\Local\Programs\Python\Python310\lib\site-packages\urllib3\util\ssl_.py:493: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

self = <ssl.SSLContext object at 0x0000028D06444740>
sock = <socket.socket [closed] fd=-1, family=AddressFamily.AF_INET, type=SocketKind.SOCK_STREAM, proto=0>
server_side = False, do_handshake_on_connect = True, suppress_ragged_eofs = True
server_hostname = 'www.vz.lt', session = None

    def wrap_socket(self, sock, server_side=False,
                    do_handshake_on_connect=True,
                    suppress_ragged_eofs=True,
                    server_hostname=None, session=None):
        # SSLSocket class handles server_hostname encoding before it calls
        # ctx._wrap_socket()
>       return self.sslsocket_class._create(
            sock=sock,
            server_side=server_side,
            do_handshake_on_connect=do_handshake_on_connect,
            suppress_ragged_eofs=suppress_ragged_eofs,
            server_hostname=server_hostname,
            context=self,
            session=session
        )

..\AppData\Local\Programs\Python\Python310\lib\ssl.py:512: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

cls = <class 'ssl.SSLSocket'>
sock = <socket.socket [closed] fd=-1, family=AddressFamily.AF_INET, type=SocketKind.SOCK_STREAM, proto=0>
server_side = False, do_handshake_on_connect = True, suppress_ragged_eofs = True
server_hostname = 'www.vz.lt'
context = <ssl.SSLContext object at 0x0000028D06444740>, session = None

    @classmethod
    def _create(cls, sock, server_side=False, do_handshake_on_connect=True,
                suppress_ragged_eofs=True, server_hostname=None,
                context=None, session=None):
        if sock.getsockopt(SOL_SOCKET, SO_TYPE) != SOCK_STREAM:
            raise NotImplementedError("only stream sockets are supported")
        if server_side:
            if server_hostname:
                raise ValueError("server_hostname can only be specified "
                                 "in client mode")
            if session is not None:
                raise ValueError("session can only be specified in "
                                 "client mode")
        if context.check_hostname and not server_hostname:
            raise ValueError("check_hostname requires server_hostname")
    
        kwargs = dict(
            family=sock.family, type=sock.type, proto=sock.proto,
            fileno=sock.fileno()
        )
        self = cls.__new__(cls, **kwargs)
        super(SSLSocket, self).__init__(**kwargs)
        self.settimeout(sock.gettimeout())
        sock.detach()
    
        self._context = context
        self._session = session
        self._closed = False
        self._sslobj = None
        self.server_side = server_side
        self.server_hostname = context._encode_hostname(server_hostname)
        self.do_handshake_on_connect = do_handshake_on_connect
        self.suppress_ragged_eofs = suppress_ragged_eofs
    
        # See if we are connected
        try:
            self.getpeername()
        except OSError as e:
            if e.errno != errno.ENOTCONN:
                raise
            connected = False
        else:
            connected = True
    
        self._connected = connected
        if connected:
            # create the SSL object
            try:
                self._sslobj = self._context._wrap_socket(
                    self, server_side, self.server_hostname,
                    owner=self, session=self._session,
                )
                if do_handshake_on_connect:
                    timeout = self.gettimeout()
                    if timeout == 0.0:
                        # non-blocking
                        raise ValueError("do_handshake_on_connect should not be specified for non-blocking sockets")
>                   self.do_handshake()

..\AppData\Local\Programs\Python\Python310\lib\ssl.py:1070: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

self = <ssl.SSLSocket [closed] fd=-1, family=AddressFamily.AF_INET, type=SocketKind.SOCK_STREAM, proto=0>
block = False

    @_sslcopydoc
    def do_handshake(self, block=False):
        self._check_connected()
        timeout = self.gettimeout()
        try:
            if timeout == 0.0 and block:
                self.settimeout(None)
>           self._sslobj.do_handshake()
E           ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:997)

..\AppData\Local\Programs\Python\Python310\lib\ssl.py:1341: SSLCertVerificationError

During handling of the above exception, another exception occurred:

self = <requests.adapters.HTTPAdapter object at 0x0000028D06CFA740>
request = <PreparedRequest [GET]>, stream = False
timeout = Timeout(connect=None, read=None, total=None), verify = True
cert = None, proxies = OrderedDict()

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        """Sends PreparedRequest object. Returns Response object.
    
        :param request: The :class:`PreparedRequest <PreparedRequest>` being sent.
        :param stream: (optional) Whether to stream the request content.
        :param timeout: (optional) How long to wait for the server to send
            data before giving up, as a float, or a :ref:`(connect timeout,
            read timeout) <timeouts>` tuple.
        :type timeout: float or tuple or urllib3 Timeout object
        :param verify: (optional) Either a boolean, in which case it controls whether
            we verify the server's TLS certificate, or a string, in which case it
            must be a path to a CA bundle to use
        :param cert: (optional) Any user-provided SSL certificate to be trusted.
        :param proxies: (optional) The proxies dictionary to apply to the request.
        :rtype: requests.Response
        """
    
        try:
            conn = self.get_connection(request.url, proxies)
        except LocationValueError as e:
            raise InvalidURL(e, request=request)
    
        self.cert_verify(conn, request.url, verify, cert)
        url = self.request_url(request, proxies)
        self.add_headers(request, stream=stream, timeout=timeout, verify=verify, cert=cert, proxies=proxies)
    
        chunked = not (request.body is None or 'Content-Length' in request.headers)
    
        if isinstance(timeout, tuple):
            try:
                connect, read = timeout
                timeout = TimeoutSauce(connect=connect, read=read)
            except ValueError as e:
                # this may raise a string formatting error.
                err = ("Invalid timeout {}. Pass a (connect, read) "
                       "timeout tuple, or a single float to set "
                       "both timeouts to the same value".format(timeout))
                raise ValueError(err)
        elif isinstance(timeout, TimeoutSauce):
            pass
        else:
            timeout = TimeoutSauce(connect=timeout, read=timeout)
    
        try:
            if not chunked:
>               resp = conn.urlopen(
                    method=request.method,
                    url=url,
                    body=request.body,
                    headers=request.headers,
                    redirect=False,
                    assert_same_host=False,
                    preload_content=False,
                    decode_content=False,
                    retries=self.max_retries,
                    timeout=timeout
                )

..\AppData\Local\Programs\Python\Python310\lib\site-packages\requests\adapters.py:440: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

self = <urllib3.connectionpool.HTTPSConnectionPool object at 0x0000028D06CFBBB0>
method = 'GET', url = '/visos-naujienos?pageno=0', body = None
headers = {'User-Agent': 'python-requests/2.27.1', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Connection': 'keep-alive'}
retries = Retry(total=0, connect=None, read=False, redirect=None, status=None)
redirect = False, assert_same_host = False
timeout = Timeout(connect=None, read=None, total=None), pool_timeout = None
release_conn = False, chunked = False, body_pos = None
response_kw = {'decode_content': False, 'preload_content': False}
parsed_url = Url(scheme=None, auth=None, host=None, port=None, path='/visos-naujienos', query='pageno=0', fragment=None)
destination_scheme = None, conn = None, release_this_conn = True
http_tunnel_required = False, err = None, clean_exit = False

    def urlopen(
        self,
        method,
        url,
        body=None,
        headers=None,
        retries=None,
        redirect=True,
        assert_same_host=True,
        timeout=_Default,
        pool_timeout=None,
        release_conn=None,
        chunked=False,
        body_pos=None,
        **response_kw
    ):
        """
        Get a connection from the pool and perform an HTTP request. This is the
        lowest level call for making a request, so you'll need to specify all
        the raw details.
    
        .. note::
    
           More commonly, it's appropriate to use a convenience method provided
           by :class:`.RequestMethods`, such as :meth:`request`.
    
        .. note::
    
           `release_conn` will only behave as expected if
           `preload_content=False` because we want to make
           `preload_content=False` the default behaviour someday soon without
           breaking backwards compatibility.
    
        :param method:
            HTTP request method (such as GET, POST, PUT, etc.)
    
        :param url:
            The URL to perform the request on.
    
        :param body:
            Data to send in the request body, either :class:`str`, :class:`bytes`,
            an iterable of :class:`str`/:class:`bytes`, or a file-like object.
    
        :param headers:
            Dictionary of custom headers to send, such as User-Agent,
            If-None-Match, etc. If None, pool headers are used. If provided,
            these headers completely replace any pool-specific headers.
    
        :param retries:
            Configure the number of retries to allow before raising a
            :class:`~urllib3.exceptions.MaxRetryError` exception.
    
            Pass ``None`` to retry until you receive a response. Pass a
            :class:`~urllib3.util.retry.Retry` object for fine-grained control
            over different types of retries.
            Pass an integer number to retry connection errors that many times,
            but no other types of errors. Pass zero to never retry.
    
            If ``False``, then retries are disabled and any exception is raised
            immediately. Also, instead of raising a MaxRetryError on redirects,
            the redirect response will be returned.
    
        :type retries: :class:`~urllib3.util.retry.Retry`, False, or an int.
    
        :param redirect:
            If True, automatically handle redirects (status codes 301, 302,
            303, 307, 308). Each redirect counts as a retry. Disabling retries
            will disable redirect, too.
    
        :param assert_same_host:
            If ``True``, will make sure that the host of the pool requests is
            consistent else will raise HostChangedError. When ``False``, you can
            use the pool on an HTTP proxy and request foreign hosts.
    
        :param timeout:
            If specified, overrides the default timeout for this one
            request. It may be a float (in seconds) or an instance of
            :class:`urllib3.util.Timeout`.
    
        :param pool_timeout:
            If set and the pool is set to block=True, then this method will
            block for ``pool_timeout`` seconds and raise EmptyPoolError if no
            connection is available within the time period.
    
        :param release_conn:
            If False, then the urlopen call will not release the connection
            back into the pool once a response is received (but will release if
            you read the entire contents of the response such as when
            `preload_content=True`). This is useful if you're not preloading
            the response's content immediately. You will need to call
            ``r.release_conn()`` on the response ``r`` to return the connection
            back into the pool. If None, it takes the value of
            ``response_kw.get('preload_content', True)``.
    
        :param chunked:
            If True, urllib3 will send the body using chunked transfer
            encoding. Otherwise, urllib3 will send the body using the standard
            content-length form. Defaults to False.
    
        :param int body_pos:
            Position to seek to in file-like body in the event of a retry or
            redirect. Typically this won't need to be set because urllib3 will
            auto-populate the value when needed.
    
        :param \\**response_kw:
            Additional parameters are passed to
            :meth:`urllib3.response.HTTPResponse.from_httplib`
        """
    
        parsed_url = parse_url(url)
        destination_scheme = parsed_url.scheme
    
        if headers is None:
            headers = self.headers
    
        if not isinstance(retries, Retry):
            retries = Retry.from_int(retries, redirect=redirect, default=self.retries)
    
        if release_conn is None:
            release_conn = response_kw.get("preload_content", True)
    
        # Check host
        if assert_same_host and not self.is_same_host(url):
            raise HostChangedError(self, url, retries)
    
        # Ensure that the URL we're connecting to is properly encoded
        if url.startswith("/"):
            url = six.ensure_str(_encode_target(url))
        else:
            url = six.ensure_str(parsed_url.url)
    
        conn = None
    
        # Track whether `conn` needs to be released before
        # returning/raising/recursing. Update this variable if necessary, and
        # leave `release_conn` constant throughout the function. That way, if
        # the function recurses, the original value of `release_conn` will be
        # passed down into the recursive call, and its value will be respected.
        #
        # See issue #651 [1] for details.
        #
        # [1] <https://github.com/urllib3/urllib3/issues/651>
        release_this_conn = release_conn
    
        http_tunnel_required = connection_requires_http_tunnel(
            self.proxy, self.proxy_config, destination_scheme
        )
    
        # Merge the proxy headers. Only done when not using HTTP CONNECT. We
        # have to copy the headers dict so we can safely change it without those
        # changes being reflected in anyone else's copy.
        if not http_tunnel_required:
            headers = headers.copy()
            headers.update(self.proxy_headers)
    
        # Must keep the exception bound to a separate variable or else Python 3
        # complains about UnboundLocalError.
        err = None
    
        # Keep track of whether we cleanly exited the except block. This
        # ensures we do proper cleanup in finally.
        clean_exit = False
    
        # Rewind body position, if needed. Record current position
        # for future rewinds in the event of a redirect/retry.
        body_pos = set_file_position(body, body_pos)
    
        try:
            # Request a connection from the queue.
            timeout_obj = self._get_timeout(timeout)
            conn = self._get_conn(timeout=pool_timeout)
    
            conn.timeout = timeout_obj.connect_timeout
    
            is_new_proxy_conn = self.proxy is not None and not getattr(
                conn, "sock", None
            )
            if is_new_proxy_conn and http_tunnel_required:
                self._prepare_proxy(conn)
    
            # Make the request on the httplib connection object.
            httplib_response = self._make_request(
                conn,
                method,
                url,
                timeout=timeout_obj,
                body=body,
                headers=headers,
                chunked=chunked,
            )
    
            # If we're going to release the connection in ``finally:``, then
            # the response doesn't need to know about the connection. Otherwise
            # it will also try to release it and we'll have a double-release
            # mess.
            response_conn = conn if not release_conn else None
    
            # Pass method to Response for length checking
            response_kw["request_method"] = method
    
            # Import httplib's response into our own wrapper object
            response = self.ResponseCls.from_httplib(
                httplib_response,
                pool=self,
                connection=response_conn,
                retries=retries,
                **response_kw
            )
    
            # Everything went great!
            clean_exit = True
    
        except EmptyPoolError:
            # Didn't get a connection from the pool, no need to clean up
            clean_exit = True
            release_this_conn = False
            raise
    
        except (
            TimeoutError,
            HTTPException,
            SocketError,
            ProtocolError,
            BaseSSLError,
            SSLError,
            CertificateError,
        ) as e:
            # Discard the connection for these exceptions. It will be
            # replaced during the next _get_conn() call.
            clean_exit = False
    
            def _is_ssl_error_message_from_http_proxy(ssl_error):
                # We're trying to detect the message 'WRONG_VERSION_NUMBER' but
                # SSLErrors are kinda all over the place when it comes to the message,
                # so we try to cover our bases here!
                message = " ".join(re.split("[^a-z]", str(ssl_error).lower()))
                return (
                    "wrong version number" in message or "unknown protocol" in message
                )
    
            # Try to detect a common user error with proxies which is to
            # set an HTTP proxy to be HTTPS when it should be 'http://'
            # (ie {'http': 'http://proxy', 'https': 'https://proxy'})
            # Instead we add a nice error message and point to a URL.
            if (
                isinstance(e, BaseSSLError)
                and self.proxy
                and _is_ssl_error_message_from_http_proxy(e)
            ):
                e = ProxyError(
                    "Your proxy appears to only use HTTP and not HTTPS, "
                    "try changing your proxy URL to be HTTP. See: "
                    "https://urllib3.readthedocs.io/en/1.26.x/advanced-usage.html"
                    "#https-proxy-error-http-proxy",
                    SSLError(e),
                )
            elif isinstance(e, (BaseSSLError, CertificateError)):
                e = SSLError(e)
            elif isinstance(e, (SocketError, NewConnectionError)) and self.proxy:
                e = ProxyError("Cannot connect to proxy.", e)
            elif isinstance(e, (SocketError, HTTPException)):
                e = ProtocolError("Connection aborted.", e)
    
>           retries = retries.increment(
                method, url, error=e, _pool=self, _stacktrace=sys.exc_info()[2]
            )

..\AppData\Local\Programs\Python\Python310\lib\site-packages\urllib3\connectionpool.py:785: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

self = Retry(total=0, connect=None, read=False, redirect=None, status=None)
method = 'GET', url = '/visos-naujienos?pageno=0', response = None
error = SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:997)'))
_pool = <urllib3.connectionpool.HTTPSConnectionPool object at 0x0000028D06CFBBB0>
_stacktrace = <traceback object at 0x0000028D06D3A9C0>

    def increment(
        self,
        method=None,
        url=None,
        response=None,
        error=None,
        _pool=None,
        _stacktrace=None,
    ):
        """Return a new Retry object with incremented retry counters.
    
        :param response: A response object, or None, if the server did not
            return a response.
        :type response: :class:`~urllib3.response.HTTPResponse`
        :param Exception error: An error encountered during the request, or
            None if the response was received successfully.
    
        :return: A new ``Retry`` object.
        """
        if self.total is False and error:
            # Disabled, indicate to re-raise the error.
            raise six.reraise(type(error), error, _stacktrace)
    
        total = self.total
        if total is not None:
            total -= 1
    
        connect = self.connect
        read = self.read
        redirect = self.redirect
        status_count = self.status
        other = self.other
        cause = "unknown"
        status = None
        redirect_location = None
    
        if error and self._is_connection_error(error):
            # Connect retry?
            if connect is False:
                raise six.reraise(type(error), error, _stacktrace)
            elif connect is not None:
                connect -= 1
    
        elif error and self._is_read_error(error):
            # Read retry?
            if read is False or not self._is_method_retryable(method):
                raise six.reraise(type(error), error, _stacktrace)
            elif read is not None:
                read -= 1
    
        elif error:
            # Other retry?
            if other is not None:
                other -= 1
    
        elif response and response.get_redirect_location():
            # Redirect retry?
            if redirect is not None:
                redirect -= 1
            cause = "too many redirects"
            redirect_location = response.get_redirect_location()
            status = response.status
    
        else:
            # Incrementing because of a server error like a 500 in
            # status_forcelist and the given method is in the allowed_methods
            cause = ResponseError.GENERIC_ERROR
            if response and response.status:
                if status_count is not None:
                    status_count -= 1
                cause = ResponseError.SPECIFIC_ERROR.format(status_code=response.status)
                status = response.status
    
        history = self.history + (
            RequestHistory(method, url, error, status, redirect_location),
        )
    
        new_retry = self.new(
            total=total,
            connect=connect,
            read=read,
            redirect=redirect,
            status=status_count,
            other=other,
            history=history,
        )
    
        if new_retry.is_exhausted():
>           raise MaxRetryError(_pool, url, error or ResponseError(cause))
E           urllib3.exceptions.MaxRetryError: HTTPSConnectionPool(host='www.vz.lt', port=443): Max retries exceeded with url: /visos-naujienos?pageno=0 (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:997)')))

..\AppData\Local\Programs\Python\Python310\lib\site-packages\urllib3\util\retry.py:592: MaxRetryError

During handling of the above exception, another exception occurred:

    def test_get_article_details():
>       r = scraper._get_response(page="vz")

test_main.py:32: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _
main.py:35: in _get_response
    r = requests.get(url=self.URL[page])
..\AppData\Local\Programs\Python\Python310\lib\site-packages\requests\api.py:75: in get
    return request('get', url, params=params, **kwargs)
..\AppData\Local\Programs\Python\Python310\lib\site-packages\requests\api.py:61: in request
    return session.request(method=method, url=url, **kwargs)
..\AppData\Local\Programs\Python\Python310\lib\site-packages\requests\sessions.py:529: in request
    resp = self.send(prep, **send_kwargs)
..\AppData\Local\Programs\Python\Python310\lib\site-packages\requests\sessions.py:645: in send
    r = adapter.send(request, **kwargs)
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

self = <requests.adapters.HTTPAdapter object at 0x0000028D06CFA740>
request = <PreparedRequest [GET]>, stream = False
timeout = Timeout(connect=None, read=None, total=None), verify = True
cert = None, proxies = OrderedDict()

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        """Sends PreparedRequest object. Returns Response object.
    
        :param request: The :class:`PreparedRequest <PreparedRequest>` being sent.
        :param stream: (optional) Whether to stream the request content.
        :param timeout: (optional) How long to wait for the server to send
            data before giving up, as a float, or a :ref:`(connect timeout,
            read timeout) <timeouts>` tuple.
        :type timeout: float or tuple or urllib3 Timeout object
        :param verify: (optional) Either a boolean, in which case it controls whether
            we verify the server's TLS certificate, or a string, in which case it
            must be a path to a CA bundle to use
        :param cert: (optional) Any user-provided SSL certificate to be trusted.
        :param proxies: (optional) The proxies dictionary to apply to the request.
        :rtype: requests.Response
        """
    
        try:
            conn = self.get_connection(request.url, proxies)
        except LocationValueError as e:
            raise InvalidURL(e, request=request)
    
        self.cert_verify(conn, request.url, verify, cert)
        url = self.request_url(request, proxies)
        self.add_headers(request, stream=stream, timeout=timeout, verify=verify, cert=cert, proxies=proxies)
    
        chunked = not (request.body is None or 'Content-Length' in request.headers)
    
        if isinstance(timeout, tuple):
            try:
                connect, read = timeout
                timeout = TimeoutSauce(connect=connect, read=read)
            except ValueError as e:
                # this may raise a string formatting error.
                err = ("Invalid timeout {}. Pass a (connect, read) "
                       "timeout tuple, or a single float to set "
                       "both timeouts to the same value".format(timeout))
                raise ValueError(err)
        elif isinstance(timeout, TimeoutSauce):
            pass
        else:
            timeout = TimeoutSauce(connect=timeout, read=timeout)
    
        try:
            if not chunked:
                resp = conn.urlopen(
                    method=request.method,
                    url=url,
                    body=request.body,
                    headers=request.headers,
                    redirect=False,
                    assert_same_host=False,
                    preload_content=False,
                    decode_content=False,
                    retries=self.max_retries,
                    timeout=timeout
                )
    
            # Send the request.
            else:
                if hasattr(conn, 'proxy_pool'):
                    conn = conn.proxy_pool
    
                low_conn = conn._get_conn(timeout=DEFAULT_POOL_TIMEOUT)
    
                try:
                    skip_host = 'Host' in request.headers
                    low_conn.putrequest(request.method,
                                        url,
                                        skip_accept_encoding=True,
                                        skip_host=skip_host)
    
                    for header, value in request.headers.items():
                        low_conn.putheader(header, value)
    
                    low_conn.endheaders()
    
                    for i in request.body:
                        low_conn.send(hex(len(i))[2:].encode('utf-8'))
                        low_conn.send(b'\r\n')
                        low_conn.send(i)
                        low_conn.send(b'\r\n')
                    low_conn.send(b'0\r\n\r\n')
    
                    # Receive the response from the server
                    try:
                        # For Python 2.7, use buffering of HTTP responses
                        r = low_conn.getresponse(buffering=True)
                    except TypeError:
                        # For compatibility with Python 3.3+
                        r = low_conn.getresponse()
    
                    resp = HTTPResponse.from_httplib(
                        r,
                        pool=conn,
                        connection=low_conn,
                        preload_content=False,
                        decode_content=False
                    )
                except:
                    # If we hit any problems here, clean up the connection.
                    # Then, reraise so that we can handle the actual exception.
                    low_conn.close()
                    raise
    
        except (ProtocolError, socket.error) as err:
            raise ConnectionError(err, request=request)
    
        except MaxRetryError as e:
            if isinstance(e.reason, ConnectTimeoutError):
                # TODO: Remove this in 3.0.0: see #2811
                if not isinstance(e.reason, NewConnectionError):
                    raise ConnectTimeout(e, request=request)
    
            if isinstance(e.reason, ResponseError):
                raise RetryError(e, request=request)
    
            if isinstance(e.reason, _ProxyError):
                raise ProxyError(e, request=request)
    
            if isinstance(e.reason, _SSLError):
                # This branch is for urllib3 v1.22 and later.
>               raise SSLError(e, request=request)
E               requests.exceptions.SSLError: HTTPSConnectionPool(host='www.vz.lt', port=443): Max retries exceeded with url: /visos-naujienos?pageno=0 (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:997)')))

..\AppData\Local\Programs\Python\Python310\lib\site-packages\requests\adapters.py:517: SSLError
_________________________ test_get_news_articles_json _________________________

self = <urllib3.connectionpool.HTTPSConnectionPool object at 0x0000028D06D11EA0>
method = 'GET', url = '/visos-naujienos?pageno=0', body = None
headers = {'User-Agent': 'python-requests/2.27.1', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Connection': 'keep-alive'}
retries = Retry(total=0, connect=None, read=False, redirect=None, status=None)
redirect = False, assert_same_host = False
timeout = Timeout(connect=None, read=None, total=None), pool_timeout = None
release_conn = False, chunked = False, body_pos = None
response_kw = {'decode_content': False, 'preload_content': False}
parsed_url = Url(scheme=None, auth=None, host=None, port=None, path='/visos-naujienos', query='pageno=0', fragment=None)
destination_scheme = None, conn = None, release_this_conn = True
http_tunnel_required = False, err = None, clean_exit = False

    def urlopen(
        self,
        method,
        url,
        body=None,
        headers=None,
        retries=None,
        redirect=True,
        assert_same_host=True,
        timeout=_Default,
        pool_timeout=None,
        release_conn=None,
        chunked=False,
        body_pos=None,
        **response_kw
    ):
        """
        Get a connection from the pool and perform an HTTP request. This is the
        lowest level call for making a request, so you'll need to specify all
        the raw details.
    
        .. note::
    
           More commonly, it's appropriate to use a convenience method provided
           by :class:`.RequestMethods`, such as :meth:`request`.
    
        .. note::
    
           `release_conn` will only behave as expected if
           `preload_content=False` because we want to make
           `preload_content=False` the default behaviour someday soon without
           breaking backwards compatibility.
    
        :param method:
            HTTP request method (such as GET, POST, PUT, etc.)
    
        :param url:
            The URL to perform the request on.
    
        :param body:
            Data to send in the request body, either :class:`str`, :class:`bytes`,
            an iterable of :class:`str`/:class:`bytes`, or a file-like object.
    
        :param headers:
            Dictionary of custom headers to send, such as User-Agent,
            If-None-Match, etc. If None, pool headers are used. If provided,
            these headers completely replace any pool-specific headers.
    
        :param retries:
            Configure the number of retries to allow before raising a
            :class:`~urllib3.exceptions.MaxRetryError` exception.
    
            Pass ``None`` to retry until you receive a response. Pass a
            :class:`~urllib3.util.retry.Retry` object for fine-grained control
            over different types of retries.
            Pass an integer number to retry connection errors that many times,
            but no other types of errors. Pass zero to never retry.
    
            If ``False``, then retries are disabled and any exception is raised
            immediately. Also, instead of raising a MaxRetryError on redirects,
            the redirect response will be returned.
    
        :type retries: :class:`~urllib3.util.retry.Retry`, False, or an int.
    
        :param redirect:
            If True, automatically handle redirects (status codes 301, 302,
            303, 307, 308). Each redirect counts as a retry. Disabling retries
            will disable redirect, too.
    
        :param assert_same_host:
            If ``True``, will make sure that the host of the pool requests is
            consistent else will raise HostChangedError. When ``False``, you can
            use the pool on an HTTP proxy and request foreign hosts.
    
        :param timeout:
            If specified, overrides the default timeout for this one
            request. It may be a float (in seconds) or an instance of
            :class:`urllib3.util.Timeout`.
    
        :param pool_timeout:
            If set and the pool is set to block=True, then this method will
            block for ``pool_timeout`` seconds and raise EmptyPoolError if no
            connection is available within the time period.
    
        :param release_conn:
            If False, then the urlopen call will not release the connection
            back into the pool once a response is received (but will release if
            you read the entire contents of the response such as when
            `preload_content=True`). This is useful if you're not preloading
            the response's content immediately. You will need to call
            ``r.release_conn()`` on the response ``r`` to return the connection
            back into the pool. If None, it takes the value of
            ``response_kw.get('preload_content', True)``.
    
        :param chunked:
            If True, urllib3 will send the body using chunked transfer
            encoding. Otherwise, urllib3 will send the body using the standard
            content-length form. Defaults to False.
    
        :param int body_pos:
            Position to seek to in file-like body in the event of a retry or
            redirect. Typically this won't need to be set because urllib3 will
            auto-populate the value when needed.
    
        :param \\**response_kw:
            Additional parameters are passed to
            :meth:`urllib3.response.HTTPResponse.from_httplib`
        """
    
        parsed_url = parse_url(url)
        destination_scheme = parsed_url.scheme
    
        if headers is None:
            headers = self.headers
    
        if not isinstance(retries, Retry):
            retries = Retry.from_int(retries, redirect=redirect, default=self.retries)
    
        if release_conn is None:
            release_conn = response_kw.get("preload_content", True)
    
        # Check host
        if assert_same_host and not self.is_same_host(url):
            raise HostChangedError(self, url, retries)
    
        # Ensure that the URL we're connecting to is properly encoded
        if url.startswith("/"):
            url = six.ensure_str(_encode_target(url))
        else:
            url = six.ensure_str(parsed_url.url)
    
        conn = None
    
        # Track whether `conn` needs to be released before
        # returning/raising/recursing. Update this variable if necessary, and
        # leave `release_conn` constant throughout the function. That way, if
        # the function recurses, the original value of `release_conn` will be
        # passed down into the recursive call, and its value will be respected.
        #
        # See issue #651 [1] for details.
        #
        # [1] <https://github.com/urllib3/urllib3/issues/651>
        release_this_conn = release_conn
    
        http_tunnel_required = connection_requires_http_tunnel(
            self.proxy, self.proxy_config, destination_scheme
        )
    
        # Merge the proxy headers. Only done when not using HTTP CONNECT. We
        # have to copy the headers dict so we can safely change it without those
        # changes being reflected in anyone else's copy.
        if not http_tunnel_required:
            headers = headers.copy()
            headers.update(self.proxy_headers)
    
        # Must keep the exception bound to a separate variable or else Python 3
        # complains about UnboundLocalError.
        err = None
    
        # Keep track of whether we cleanly exited the except block. This
        # ensures we do proper cleanup in finally.
        clean_exit = False
    
        # Rewind body position, if needed. Record current position
        # for future rewinds in the event of a redirect/retry.
        body_pos = set_file_position(body, body_pos)
    
        try:
            # Request a connection from the queue.
            timeout_obj = self._get_timeout(timeout)
            conn = self._get_conn(timeout=pool_timeout)
    
            conn.timeout = timeout_obj.connect_timeout
    
            is_new_proxy_conn = self.proxy is not None and not getattr(
                conn, "sock", None
            )
            if is_new_proxy_conn and http_tunnel_required:
                self._prepare_proxy(conn)
    
            # Make the request on the httplib connection object.
>           httplib_response = self._make_request(
                conn,
                method,
                url,
                timeout=timeout_obj,
                body=body,
                headers=headers,
                chunked=chunked,
            )

..\AppData\Local\Programs\Python\Python310\lib\site-packages\urllib3\connectionpool.py:703: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

self = <urllib3.connectionpool.HTTPSConnectionPool object at 0x0000028D06D11EA0>
conn = <urllib3.connection.HTTPSConnection object at 0x0000028D06D12590>
method = 'GET', url = '/visos-naujienos?pageno=0'
timeout = Timeout(connect=None, read=None, total=None), chunked = False
httplib_request_kw = {'body': None, 'headers': {'User-Agent': 'python-requests/2.27.1', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Connection': 'keep-alive'}}
timeout_obj = Timeout(connect=None, read=None, total=None)

    def _make_request(
        self, conn, method, url, timeout=_Default, chunked=False, **httplib_request_kw
    ):
        """
        Perform a request on a given urllib connection object taken from our
        pool.
    
        :param conn:
            a connection from one of our connection pools
    
        :param timeout:
            Socket timeout in seconds for the request. This can be a
            float or integer, which will set the same timeout value for
            the socket connect and the socket read, or an instance of
            :class:`urllib3.util.Timeout`, which gives you more fine-grained
            control over your timeouts.
        """
        self.num_requests += 1
    
        timeout_obj = self._get_timeout(timeout)
        timeout_obj.start_connect()
        conn.timeout = timeout_obj.connect_timeout
    
        # Trigger any extra validation we need to do.
        try:
>           self._validate_conn(conn)

..\AppData\Local\Programs\Python\Python310\lib\site-packages\urllib3\connectionpool.py:386: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

self = <urllib3.connectionpool.HTTPSConnectionPool object at 0x0000028D06D11EA0>
conn = <urllib3.connection.HTTPSConnection object at 0x0000028D06D12590>

    def _validate_conn(self, conn):
        """
        Called right before a request is made, after the socket is created.
        """
        super(HTTPSConnectionPool, self)._validate_conn(conn)
    
        # Force connect early to allow us to validate the connection.
        if not getattr(conn, "sock", None):  # AppEngine might not have  `.sock`
>           conn.connect()

..\AppData\Local\Programs\Python\Python310\lib\site-packages\urllib3\connectionpool.py:1040: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

self = <urllib3.connection.HTTPSConnection object at 0x0000028D06D12590>

    def connect(self):
        # Add certificate verification
        self.sock = conn = self._new_conn()
        hostname = self.host
        tls_in_tls = False
    
        if self._is_using_tunnel():
            if self.tls_in_tls_required:
                self.sock = conn = self._connect_tls_proxy(hostname, conn)
                tls_in_tls = True
    
            # Calls self._set_hostport(), so self.host is
            # self._tunnel_host below.
            self._tunnel()
            # Mark this connection as not reusable
            self.auto_open = 0
    
            # Override the host with the one we're requesting data from.
            hostname = self._tunnel_host
    
        server_hostname = hostname
        if self.server_hostname is not None:
            server_hostname = self.server_hostname
    
        is_time_off = datetime.date.today() < RECENT_DATE
        if is_time_off:
            warnings.warn(
                (
                    "System time is way off (before {0}). This will probably "
                    "lead to SSL verification errors"
                ).format(RECENT_DATE),
                SystemTimeWarning,
            )
    
        # Wrap socket using verification with the root certs in
        # trusted_root_certs
        default_ssl_context = False
        if self.ssl_context is None:
            default_ssl_context = True
            self.ssl_context = create_urllib3_context(
                ssl_version=resolve_ssl_version(self.ssl_version),
                cert_reqs=resolve_cert_reqs(self.cert_reqs),
            )
    
        context = self.ssl_context
        context.verify_mode = resolve_cert_reqs(self.cert_reqs)
    
        # Try to load OS default certs if none are given.
        # Works well on Windows (requires Python3.4+)
        if (
            not self.ca_certs
            and not self.ca_cert_dir
            and not self.ca_cert_data
            and default_ssl_context
            and hasattr(context, "load_default_certs")
        ):
            context.load_default_certs()
    
>       self.sock = ssl_wrap_socket(
            sock=conn,
            keyfile=self.key_file,
            certfile=self.cert_file,
            key_password=self.key_password,
            ca_certs=self.ca_certs,
            ca_cert_dir=self.ca_cert_dir,
            ca_cert_data=self.ca_cert_data,
            server_hostname=server_hostname,
            ssl_context=context,
            tls_in_tls=tls_in_tls,
        )

..\AppData\Local\Programs\Python\Python310\lib\site-packages\urllib3\connection.py:414: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

sock = <socket.socket [closed] fd=-1, family=AddressFamily.AF_INET, type=SocketKind.SOCK_STREAM, proto=0>
keyfile = None, certfile = None, cert_reqs = None
ca_certs = 'C:\\Users\\mamonask\\AppData\\Local\\Programs\\Python\\Python310\\lib\\site-packages\\certifi\\cacert.pem'
server_hostname = 'www.vz.lt', ssl_version = None, ciphers = None
ssl_context = <ssl.SSLContext object at 0x0000028D064728C0>, ca_cert_dir = None
key_password = None, ca_cert_data = None, tls_in_tls = False

    def ssl_wrap_socket(
        sock,
        keyfile=None,
        certfile=None,
        cert_reqs=None,
        ca_certs=None,
        server_hostname=None,
        ssl_version=None,
        ciphers=None,
        ssl_context=None,
        ca_cert_dir=None,
        key_password=None,
        ca_cert_data=None,
        tls_in_tls=False,
    ):
        """
        All arguments except for server_hostname, ssl_context, and ca_cert_dir have
        the same meaning as they do when using :func:`ssl.wrap_socket`.
    
        :param server_hostname:
            When SNI is supported, the expected hostname of the certificate
        :param ssl_context:
            A pre-made :class:`SSLContext` object. If none is provided, one will
            be created using :func:`create_urllib3_context`.
        :param ciphers:
            A string of ciphers we wish the client to support.
        :param ca_cert_dir:
            A directory containing CA certificates in multiple separate files, as
            supported by OpenSSL's -CApath flag or the capath argument to
            SSLContext.load_verify_locations().
        :param key_password:
            Optional password if the keyfile is encrypted.
        :param ca_cert_data:
            Optional string containing CA certificates in PEM format suitable for
            passing as the cadata parameter to SSLContext.load_verify_locations()
        :param tls_in_tls:
            Use SSLTransport to wrap the existing socket.
        """
        context = ssl_context
        if context is None:
            # Note: This branch of code and all the variables in it are no longer
            # used by urllib3 itself. We should consider deprecating and removing
            # this code.
            context = create_urllib3_context(ssl_version, cert_reqs, ciphers=ciphers)
    
        if ca_certs or ca_cert_dir or ca_cert_data:
            try:
                context.load_verify_locations(ca_certs, ca_cert_dir, ca_cert_data)
            except (IOError, OSError) as e:
                raise SSLError(e)
    
        elif ssl_context is None and hasattr(context, "load_default_certs"):
            # try to load OS default certs; works well on Windows (require Python3.4+)
            context.load_default_certs()
    
        # Attempt to detect if we get the goofy behavior of the
        # keyfile being encrypted and OpenSSL asking for the
        # passphrase via the terminal and instead error out.
        if keyfile and key_password is None and _is_key_file_encrypted(keyfile):
            raise SSLError("Client private key is encrypted, password is required")
    
        if certfile:
            if key_password is None:
                context.load_cert_chain(certfile, keyfile)
            else:
                context.load_cert_chain(certfile, keyfile, key_password)
    
        try:
            if hasattr(context, "set_alpn_protocols"):
                context.set_alpn_protocols(ALPN_PROTOCOLS)
        except NotImplementedError:  # Defensive: in CI, we always have set_alpn_protocols
            pass
    
        # If we detect server_hostname is an IP address then the SNI
        # extension should not be used according to RFC3546 Section 3.1
        use_sni_hostname = server_hostname and not is_ipaddress(server_hostname)
        # SecureTransport uses server_hostname in certificate verification.
        send_sni = (use_sni_hostname and HAS_SNI) or (
            IS_SECURETRANSPORT and server_hostname
        )
        # Do not warn the user if server_hostname is an invalid SNI hostname.
        if not HAS_SNI and use_sni_hostname:
            warnings.warn(
                "An HTTPS request has been made, but the SNI (Server Name "
                "Indication) extension to TLS is not available on this platform. "
                "This may cause the server to present an incorrect TLS "
                "certificate, which can cause validation failures. You can upgrade to "
                "a newer version of Python to solve this. For more information, see "
                "https://urllib3.readthedocs.io/en/1.26.x/advanced-usage.html"
                "#ssl-warnings",
                SNIMissingWarning,
            )
    
        if send_sni:
>           ssl_sock = _ssl_wrap_socket_impl(
                sock, context, tls_in_tls, server_hostname=server_hostname
            )

..\AppData\Local\Programs\Python\Python310\lib\site-packages\urllib3\util\ssl_.py:449: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

sock = <socket.socket [closed] fd=-1, family=AddressFamily.AF_INET, type=SocketKind.SOCK_STREAM, proto=0>
ssl_context = <ssl.SSLContext object at 0x0000028D064728C0>, tls_in_tls = False
server_hostname = 'www.vz.lt'

    def _ssl_wrap_socket_impl(sock, ssl_context, tls_in_tls, server_hostname=None):
        if tls_in_tls:
            if not SSLTransport:
                # Import error, ssl is not available.
                raise ProxySchemeUnsupported(
                    "TLS in TLS requires support for the 'ssl' module"
                )
    
            SSLTransport._validate_ssl_context_for_tls_in_tls(ssl_context)
            return SSLTransport(sock, ssl_context, server_hostname)
    
        if server_hostname:
>           return ssl_context.wrap_socket(sock, server_hostname=server_hostname)

..\AppData\Local\Programs\Python\Python310\lib\site-packages\urllib3\util\ssl_.py:493: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

self = <ssl.SSLContext object at 0x0000028D064728C0>
sock = <socket.socket [closed] fd=-1, family=AddressFamily.AF_INET, type=SocketKind.SOCK_STREAM, proto=0>
server_side = False, do_handshake_on_connect = True, suppress_ragged_eofs = True
server_hostname = 'www.vz.lt', session = None

    def wrap_socket(self, sock, server_side=False,
                    do_handshake_on_connect=True,
                    suppress_ragged_eofs=True,
                    server_hostname=None, session=None):
        # SSLSocket class handles server_hostname encoding before it calls
        # ctx._wrap_socket()
>       return self.sslsocket_class._create(
            sock=sock,
            server_side=server_side,
            do_handshake_on_connect=do_handshake_on_connect,
            suppress_ragged_eofs=suppress_ragged_eofs,
            server_hostname=server_hostname,
            context=self,
            session=session
        )

..\AppData\Local\Programs\Python\Python310\lib\ssl.py:512: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

cls = <class 'ssl.SSLSocket'>
sock = <socket.socket [closed] fd=-1, family=AddressFamily.AF_INET, type=SocketKind.SOCK_STREAM, proto=0>
server_side = False, do_handshake_on_connect = True, suppress_ragged_eofs = True
server_hostname = 'www.vz.lt'
context = <ssl.SSLContext object at 0x0000028D064728C0>, session = None

    @classmethod
    def _create(cls, sock, server_side=False, do_handshake_on_connect=True,
                suppress_ragged_eofs=True, server_hostname=None,
                context=None, session=None):
        if sock.getsockopt(SOL_SOCKET, SO_TYPE) != SOCK_STREAM:
            raise NotImplementedError("only stream sockets are supported")
        if server_side:
            if server_hostname:
                raise ValueError("server_hostname can only be specified "
                                 "in client mode")
            if session is not None:
                raise ValueError("session can only be specified in "
                                 "client mode")
        if context.check_hostname and not server_hostname:
            raise ValueError("check_hostname requires server_hostname")
    
        kwargs = dict(
            family=sock.family, type=sock.type, proto=sock.proto,
            fileno=sock.fileno()
        )
        self = cls.__new__(cls, **kwargs)
        super(SSLSocket, self).__init__(**kwargs)
        self.settimeout(sock.gettimeout())
        sock.detach()
    
        self._context = context
        self._session = session
        self._closed = False
        self._sslobj = None
        self.server_side = server_side
        self.server_hostname = context._encode_hostname(server_hostname)
        self.do_handshake_on_connect = do_handshake_on_connect
        self.suppress_ragged_eofs = suppress_ragged_eofs
    
        # See if we are connected
        try:
            self.getpeername()
        except OSError as e:
            if e.errno != errno.ENOTCONN:
                raise
            connected = False
        else:
            connected = True
    
        self._connected = connected
        if connected:
            # create the SSL object
            try:
                self._sslobj = self._context._wrap_socket(
                    self, server_side, self.server_hostname,
                    owner=self, session=self._session,
                )
                if do_handshake_on_connect:
                    timeout = self.gettimeout()
                    if timeout == 0.0:
                        # non-blocking
                        raise ValueError("do_handshake_on_connect should not be specified for non-blocking sockets")
>                   self.do_handshake()

..\AppData\Local\Programs\Python\Python310\lib\ssl.py:1070: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

self = <ssl.SSLSocket [closed] fd=-1, family=AddressFamily.AF_INET, type=SocketKind.SOCK_STREAM, proto=0>
block = False

    @_sslcopydoc
    def do_handshake(self, block=False):
        self._check_connected()
        timeout = self.gettimeout()
        try:
            if timeout == 0.0 and block:
                self.settimeout(None)
>           self._sslobj.do_handshake()
E           ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:997)

..\AppData\Local\Programs\Python\Python310\lib\ssl.py:1341: SSLCertVerificationError

During handling of the above exception, another exception occurred:

self = <requests.adapters.HTTPAdapter object at 0x0000028D06D11C60>
request = <PreparedRequest [GET]>, stream = False
timeout = Timeout(connect=None, read=None, total=None), verify = True
cert = None, proxies = OrderedDict()

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        """Sends PreparedRequest object. Returns Response object.
    
        :param request: The :class:`PreparedRequest <PreparedRequest>` being sent.
        :param stream: (optional) Whether to stream the request content.
        :param timeout: (optional) How long to wait for the server to send
            data before giving up, as a float, or a :ref:`(connect timeout,
            read timeout) <timeouts>` tuple.
        :type timeout: float or tuple or urllib3 Timeout object
        :param verify: (optional) Either a boolean, in which case it controls whether
            we verify the server's TLS certificate, or a string, in which case it
            must be a path to a CA bundle to use
        :param cert: (optional) Any user-provided SSL certificate to be trusted.
        :param proxies: (optional) The proxies dictionary to apply to the request.
        :rtype: requests.Response
        """
    
        try:
            conn = self.get_connection(request.url, proxies)
        except LocationValueError as e:
            raise InvalidURL(e, request=request)
    
        self.cert_verify(conn, request.url, verify, cert)
        url = self.request_url(request, proxies)
        self.add_headers(request, stream=stream, timeout=timeout, verify=verify, cert=cert, proxies=proxies)
    
        chunked = not (request.body is None or 'Content-Length' in request.headers)
    
        if isinstance(timeout, tuple):
            try:
                connect, read = timeout
                timeout = TimeoutSauce(connect=connect, read=read)
            except ValueError as e:
                # this may raise a string formatting error.
                err = ("Invalid timeout {}. Pass a (connect, read) "
                       "timeout tuple, or a single float to set "
                       "both timeouts to the same value".format(timeout))
                raise ValueError(err)
        elif isinstance(timeout, TimeoutSauce):
            pass
        else:
            timeout = TimeoutSauce(connect=timeout, read=timeout)
    
        try:
            if not chunked:
>               resp = conn.urlopen(
                    method=request.method,
                    url=url,
                    body=request.body,
                    headers=request.headers,
                    redirect=False,
                    assert_same_host=False,
                    preload_content=False,
                    decode_content=False,
                    retries=self.max_retries,
                    timeout=timeout
                )

..\AppData\Local\Programs\Python\Python310\lib\site-packages\requests\adapters.py:440: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

self = <urllib3.connectionpool.HTTPSConnectionPool object at 0x0000028D06D11EA0>
method = 'GET', url = '/visos-naujienos?pageno=0', body = None
headers = {'User-Agent': 'python-requests/2.27.1', 'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Connection': 'keep-alive'}
retries = Retry(total=0, connect=None, read=False, redirect=None, status=None)
redirect = False, assert_same_host = False
timeout = Timeout(connect=None, read=None, total=None), pool_timeout = None
release_conn = False, chunked = False, body_pos = None
response_kw = {'decode_content': False, 'preload_content': False}
parsed_url = Url(scheme=None, auth=None, host=None, port=None, path='/visos-naujienos', query='pageno=0', fragment=None)
destination_scheme = None, conn = None, release_this_conn = True
http_tunnel_required = False, err = None, clean_exit = False

    def urlopen(
        self,
        method,
        url,
        body=None,
        headers=None,
        retries=None,
        redirect=True,
        assert_same_host=True,
        timeout=_Default,
        pool_timeout=None,
        release_conn=None,
        chunked=False,
        body_pos=None,
        **response_kw
    ):
        """
        Get a connection from the pool and perform an HTTP request. This is the
        lowest level call for making a request, so you'll need to specify all
        the raw details.
    
        .. note::
    
           More commonly, it's appropriate to use a convenience method provided
           by :class:`.RequestMethods`, such as :meth:`request`.
    
        .. note::
    
           `release_conn` will only behave as expected if
           `preload_content=False` because we want to make
           `preload_content=False` the default behaviour someday soon without
           breaking backwards compatibility.
    
        :param method:
            HTTP request method (such as GET, POST, PUT, etc.)
    
        :param url:
            The URL to perform the request on.
    
        :param body:
            Data to send in the request body, either :class:`str`, :class:`bytes`,
            an iterable of :class:`str`/:class:`bytes`, or a file-like object.
    
        :param headers:
            Dictionary of custom headers to send, such as User-Agent,
            If-None-Match, etc. If None, pool headers are used. If provided,
            these headers completely replace any pool-specific headers.
    
        :param retries:
            Configure the number of retries to allow before raising a
            :class:`~urllib3.exceptions.MaxRetryError` exception.
    
            Pass ``None`` to retry until you receive a response. Pass a
            :class:`~urllib3.util.retry.Retry` object for fine-grained control
            over different types of retries.
            Pass an integer number to retry connection errors that many times,
            but no other types of errors. Pass zero to never retry.
    
            If ``False``, then retries are disabled and any exception is raised
            immediately. Also, instead of raising a MaxRetryError on redirects,
            the redirect response will be returned.
    
        :type retries: :class:`~urllib3.util.retry.Retry`, False, or an int.
    
        :param redirect:
            If True, automatically handle redirects (status codes 301, 302,
            303, 307, 308). Each redirect counts as a retry. Disabling retries
            will disable redirect, too.
    
        :param assert_same_host:
            If ``True``, will make sure that the host of the pool requests is
            consistent else will raise HostChangedError. When ``False``, you can
            use the pool on an HTTP proxy and request foreign hosts.
    
        :param timeout:
            If specified, overrides the default timeout for this one
            request. It may be a float (in seconds) or an instance of
            :class:`urllib3.util.Timeout`.
    
        :param pool_timeout:
            If set and the pool is set to block=True, then this method will
            block for ``pool_timeout`` seconds and raise EmptyPoolError if no
            connection is available within the time period.
    
        :param release_conn:
            If False, then the urlopen call will not release the connection
            back into the pool once a response is received (but will release if
            you read the entire contents of the response such as when
            `preload_content=True`). This is useful if you're not preloading
            the response's content immediately. You will need to call
            ``r.release_conn()`` on the response ``r`` to return the connection
            back into the pool. If None, it takes the value of
            ``response_kw.get('preload_content', True)``.
    
        :param chunked:
            If True, urllib3 will send the body using chunked transfer
            encoding. Otherwise, urllib3 will send the body using the standard
            content-length form. Defaults to False.
    
        :param int body_pos:
            Position to seek to in file-like body in the event of a retry or
            redirect. Typically this won't need to be set because urllib3 will
            auto-populate the value when needed.
    
        :param \\**response_kw:
            Additional parameters are passed to
            :meth:`urllib3.response.HTTPResponse.from_httplib`
        """
    
        parsed_url = parse_url(url)
        destination_scheme = parsed_url.scheme
    
        if headers is None:
            headers = self.headers
    
        if not isinstance(retries, Retry):
            retries = Retry.from_int(retries, redirect=redirect, default=self.retries)
    
        if release_conn is None:
            release_conn = response_kw.get("preload_content", True)
    
        # Check host
        if assert_same_host and not self.is_same_host(url):
            raise HostChangedError(self, url, retries)
    
        # Ensure that the URL we're connecting to is properly encoded
        if url.startswith("/"):
            url = six.ensure_str(_encode_target(url))
        else:
            url = six.ensure_str(parsed_url.url)
    
        conn = None
    
        # Track whether `conn` needs to be released before
        # returning/raising/recursing. Update this variable if necessary, and
        # leave `release_conn` constant throughout the function. That way, if
        # the function recurses, the original value of `release_conn` will be
        # passed down into the recursive call, and its value will be respected.
        #
        # See issue #651 [1] for details.
        #
        # [1] <https://github.com/urllib3/urllib3/issues/651>
        release_this_conn = release_conn
    
        http_tunnel_required = connection_requires_http_tunnel(
            self.proxy, self.proxy_config, destination_scheme
        )
    
        # Merge the proxy headers. Only done when not using HTTP CONNECT. We
        # have to copy the headers dict so we can safely change it without those
        # changes being reflected in anyone else's copy.
        if not http_tunnel_required:
            headers = headers.copy()
            headers.update(self.proxy_headers)
    
        # Must keep the exception bound to a separate variable or else Python 3
        # complains about UnboundLocalError.
        err = None
    
        # Keep track of whether we cleanly exited the except block. This
        # ensures we do proper cleanup in finally.
        clean_exit = False
    
        # Rewind body position, if needed. Record current position
        # for future rewinds in the event of a redirect/retry.
        body_pos = set_file_position(body, body_pos)
    
        try:
            # Request a connection from the queue.
            timeout_obj = self._get_timeout(timeout)
            conn = self._get_conn(timeout=pool_timeout)
    
            conn.timeout = timeout_obj.connect_timeout
    
            is_new_proxy_conn = self.proxy is not None and not getattr(
                conn, "sock", None
            )
            if is_new_proxy_conn and http_tunnel_required:
                self._prepare_proxy(conn)
    
            # Make the request on the httplib connection object.
            httplib_response = self._make_request(
                conn,
                method,
                url,
                timeout=timeout_obj,
                body=body,
                headers=headers,
                chunked=chunked,
            )
    
            # If we're going to release the connection in ``finally:``, then
            # the response doesn't need to know about the connection. Otherwise
            # it will also try to release it and we'll have a double-release
            # mess.
            response_conn = conn if not release_conn else None
    
            # Pass method to Response for length checking
            response_kw["request_method"] = method
    
            # Import httplib's response into our own wrapper object
            response = self.ResponseCls.from_httplib(
                httplib_response,
                pool=self,
                connection=response_conn,
                retries=retries,
                **response_kw
            )
    
            # Everything went great!
            clean_exit = True
    
        except EmptyPoolError:
            # Didn't get a connection from the pool, no need to clean up
            clean_exit = True
            release_this_conn = False
            raise
    
        except (
            TimeoutError,
            HTTPException,
            SocketError,
            ProtocolError,
            BaseSSLError,
            SSLError,
            CertificateError,
        ) as e:
            # Discard the connection for these exceptions. It will be
            # replaced during the next _get_conn() call.
            clean_exit = False
    
            def _is_ssl_error_message_from_http_proxy(ssl_error):
                # We're trying to detect the message 'WRONG_VERSION_NUMBER' but
                # SSLErrors are kinda all over the place when it comes to the message,
                # so we try to cover our bases here!
                message = " ".join(re.split("[^a-z]", str(ssl_error).lower()))
                return (
                    "wrong version number" in message or "unknown protocol" in message
                )
    
            # Try to detect a common user error with proxies which is to
            # set an HTTP proxy to be HTTPS when it should be 'http://'
            # (ie {'http': 'http://proxy', 'https': 'https://proxy'})
            # Instead we add a nice error message and point to a URL.
            if (
                isinstance(e, BaseSSLError)
                and self.proxy
                and _is_ssl_error_message_from_http_proxy(e)
            ):
                e = ProxyError(
                    "Your proxy appears to only use HTTP and not HTTPS, "
                    "try changing your proxy URL to be HTTP. See: "
                    "https://urllib3.readthedocs.io/en/1.26.x/advanced-usage.html"
                    "#https-proxy-error-http-proxy",
                    SSLError(e),
                )
            elif isinstance(e, (BaseSSLError, CertificateError)):
                e = SSLError(e)
            elif isinstance(e, (SocketError, NewConnectionError)) and self.proxy:
                e = ProxyError("Cannot connect to proxy.", e)
            elif isinstance(e, (SocketError, HTTPException)):
                e = ProtocolError("Connection aborted.", e)
    
>           retries = retries.increment(
                method, url, error=e, _pool=self, _stacktrace=sys.exc_info()[2]
            )

..\AppData\Local\Programs\Python\Python310\lib\site-packages\urllib3\connectionpool.py:785: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

self = Retry(total=0, connect=None, read=False, redirect=None, status=None)
method = 'GET', url = '/visos-naujienos?pageno=0', response = None
error = SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:997)'))
_pool = <urllib3.connectionpool.HTTPSConnectionPool object at 0x0000028D06D11EA0>
_stacktrace = <traceback object at 0x0000028D06DCB6C0>

    def increment(
        self,
        method=None,
        url=None,
        response=None,
        error=None,
        _pool=None,
        _stacktrace=None,
    ):
        """Return a new Retry object with incremented retry counters.
    
        :param response: A response object, or None, if the server did not
            return a response.
        :type response: :class:`~urllib3.response.HTTPResponse`
        :param Exception error: An error encountered during the request, or
            None if the response was received successfully.
    
        :return: A new ``Retry`` object.
        """
        if self.total is False and error:
            # Disabled, indicate to re-raise the error.
            raise six.reraise(type(error), error, _stacktrace)
    
        total = self.total
        if total is not None:
            total -= 1
    
        connect = self.connect
        read = self.read
        redirect = self.redirect
        status_count = self.status
        other = self.other
        cause = "unknown"
        status = None
        redirect_location = None
    
        if error and self._is_connection_error(error):
            # Connect retry?
            if connect is False:
                raise six.reraise(type(error), error, _stacktrace)
            elif connect is not None:
                connect -= 1
    
        elif error and self._is_read_error(error):
            # Read retry?
            if read is False or not self._is_method_retryable(method):
                raise six.reraise(type(error), error, _stacktrace)
            elif read is not None:
                read -= 1
    
        elif error:
            # Other retry?
            if other is not None:
                other -= 1
    
        elif response and response.get_redirect_location():
            # Redirect retry?
            if redirect is not None:
                redirect -= 1
            cause = "too many redirects"
            redirect_location = response.get_redirect_location()
            status = response.status
    
        else:
            # Incrementing because of a server error like a 500 in
            # status_forcelist and the given method is in the allowed_methods
            cause = ResponseError.GENERIC_ERROR
            if response and response.status:
                if status_count is not None:
                    status_count -= 1
                cause = ResponseError.SPECIFIC_ERROR.format(status_code=response.status)
                status = response.status
    
        history = self.history + (
            RequestHistory(method, url, error, status, redirect_location),
        )
    
        new_retry = self.new(
            total=total,
            connect=connect,
            read=read,
            redirect=redirect,
            status=status_count,
            other=other,
            history=history,
        )
    
        if new_retry.is_exhausted():
>           raise MaxRetryError(_pool, url, error or ResponseError(cause))
E           urllib3.exceptions.MaxRetryError: HTTPSConnectionPool(host='www.vz.lt', port=443): Max retries exceeded with url: /visos-naujienos?pageno=0 (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:997)')))

..\AppData\Local\Programs\Python\Python310\lib\site-packages\urllib3\util\retry.py:592: MaxRetryError

During handling of the above exception, another exception occurred:

    def test_get_news_articles_json():
        scraper = NewsScraper()
>       scraper.get_news_articles_json(path='./results.json', page='vz', number=1)

test_main.py:42: 
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _
main.py:81: in get_news_articles_json
    self._get_one_page_data(page=page, number=number)
main.py:75: in _get_one_page_data
    r = self._get_response(page=page)
main.py:35: in _get_response
    r = requests.get(url=self.URL[page])
..\AppData\Local\Programs\Python\Python310\lib\site-packages\requests\api.py:75: in get
    return request('get', url, params=params, **kwargs)
..\AppData\Local\Programs\Python\Python310\lib\site-packages\requests\api.py:61: in request
    return session.request(method=method, url=url, **kwargs)
..\AppData\Local\Programs\Python\Python310\lib\site-packages\requests\sessions.py:529: in request
    resp = self.send(prep, **send_kwargs)
..\AppData\Local\Programs\Python\Python310\lib\site-packages\requests\sessions.py:645: in send
    r = adapter.send(request, **kwargs)
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _

self = <requests.adapters.HTTPAdapter object at 0x0000028D06D11C60>
request = <PreparedRequest [GET]>, stream = False
timeout = Timeout(connect=None, read=None, total=None), verify = True
cert = None, proxies = OrderedDict()

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        """Sends PreparedRequest object. Returns Response object.
    
        :param request: The :class:`PreparedRequest <PreparedRequest>` being sent.
        :param stream: (optional) Whether to stream the request content.
        :param timeout: (optional) How long to wait for the server to send
            data before giving up, as a float, or a :ref:`(connect timeout,
            read timeout) <timeouts>` tuple.
        :type timeout: float or tuple or urllib3 Timeout object
        :param verify: (optional) Either a boolean, in which case it controls whether
            we verify the server's TLS certificate, or a string, in which case it
            must be a path to a CA bundle to use
        :param cert: (optional) Any user-provided SSL certificate to be trusted.
        :param proxies: (optional) The proxies dictionary to apply to the request.
        :rtype: requests.Response
        """
    
        try:
            conn = self.get_connection(request.url, proxies)
        except LocationValueError as e:
            raise InvalidURL(e, request=request)
    
        self.cert_verify(conn, request.url, verify, cert)
        url = self.request_url(request, proxies)
        self.add_headers(request, stream=stream, timeout=timeout, verify=verify, cert=cert, proxies=proxies)
    
        chunked = not (request.body is None or 'Content-Length' in request.headers)
    
        if isinstance(timeout, tuple):
            try:
                connect, read = timeout
                timeout = TimeoutSauce(connect=connect, read=read)
            except ValueError as e:
                # this may raise a string formatting error.
                err = ("Invalid timeout {}. Pass a (connect, read) "
                       "timeout tuple, or a single float to set "
                       "both timeouts to the same value".format(timeout))
                raise ValueError(err)
        elif isinstance(timeout, TimeoutSauce):
            pass
        else:
            timeout = TimeoutSauce(connect=timeout, read=timeout)
    
        try:
            if not chunked:
                resp = conn.urlopen(
                    method=request.method,
                    url=url,
                    body=request.body,
                    headers=request.headers,
                    redirect=False,
                    assert_same_host=False,
                    preload_content=False,
                    decode_content=False,
                    retries=self.max_retries,
                    timeout=timeout
                )
    
            # Send the request.
            else:
                if hasattr(conn, 'proxy_pool'):
                    conn = conn.proxy_pool
    
                low_conn = conn._get_conn(timeout=DEFAULT_POOL_TIMEOUT)
    
                try:
                    skip_host = 'Host' in request.headers
                    low_conn.putrequest(request.method,
                                        url,
                                        skip_accept_encoding=True,
                                        skip_host=skip_host)
    
                    for header, value in request.headers.items():
                        low_conn.putheader(header, value)
    
                    low_conn.endheaders()
    
                    for i in request.body:
                        low_conn.send(hex(len(i))[2:].encode('utf-8'))
                        low_conn.send(b'\r\n')
                        low_conn.send(i)
                        low_conn.send(b'\r\n')
                    low_conn.send(b'0\r\n\r\n')
    
                    # Receive the response from the server
                    try:
                        # For Python 2.7, use buffering of HTTP responses
                        r = low_conn.getresponse(buffering=True)
                    except TypeError:
                        # For compatibility with Python 3.3+
                        r = low_conn.getresponse()
    
                    resp = HTTPResponse.from_httplib(
                        r,
                        pool=conn,
                        connection=low_conn,
                        preload_content=False,
                        decode_content=False
                    )
                except:
                    # If we hit any problems here, clean up the connection.
                    # Then, reraise so that we can handle the actual exception.
                    low_conn.close()
                    raise
    
        except (ProtocolError, socket.error) as err:
            raise ConnectionError(err, request=request)
    
        except MaxRetryError as e:
            if isinstance(e.reason, ConnectTimeoutError):
                # TODO: Remove this in 3.0.0: see #2811
                if not isinstance(e.reason, NewConnectionError):
                    raise ConnectTimeout(e, request=request)
    
            if isinstance(e.reason, ResponseError):
                raise RetryError(e, request=request)
    
            if isinstance(e.reason, _ProxyError):
                raise ProxyError(e, request=request)
    
            if isinstance(e.reason, _SSLError):
                # This branch is for urllib3 v1.22 and later.
>               raise SSLError(e, request=request)
E               requests.exceptions.SSLError: HTTPSConnectionPool(host='www.vz.lt', port=443): Max retries exceeded with url: /visos-naujienos?pageno=0 (Caused by SSLError(SSLCertVerificationError(1, '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:997)')))

..\AppData\Local\Programs\Python\Python310\lib\site-packages\requests\adapters.py:517: SSLError
=========================== short test summary info ===========================
FAILED test_main.py::test_et_response - requests.exceptions.SSLError: HTTPSCo...
FAILED test_main.py::test_get_articles_in_page - requests.exceptions.SSLError...
FAILED test_main.py::test_get_article_details - requests.exceptions.SSLError:...
FAILED test_main.py::test_get_news_articles_json - requests.exceptions.SSLErr...
========================= 4 failed, 2 passed in 1.67s =========================


