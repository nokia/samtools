#!/usr/bin/python

##############################################################################
#                                                                            #
#  samifmod.py                                                               #
#                                                                            #
#  History Change Log:                                                       #
#                                                                            #
#    0.1  [SW]  2008/05/13                                                   #
#                 first release                                              #
#                                                                            #
#    0.2  [SW]  2008/07/18                                                   #
#                 logging introduced                                         #
#                 exception handling introduced                              #
#                 method ping() added                                        #
#                                                                            #
#    1.0  [SW]  2011/06/17                                                   #
#                 SSL/TLS security added                                     #
#                 compatibility for Python 2.4 and 2.6 (hashlib vs md5lib)   #
#                 selectServer added to support redundant SAM installation   #
#                                                                            #
#    1.1  [SW]  2011/08/09                                                   #
#                 timeout only used for server redundancy                    #
#                                                                            #
#    1.2  [SW]  2012/09/27                                                   #
#                 possibility to provide password hashed or cleartext        #
#                                                                            #
#    1.3  [SW]  2015/05/08                                                   #
#                 Workaround for Python SSL bug with Diffie-Hellman ciphers  #
#                 Retry mechanism is used for SSL errors                     #
#                 More info:                                                 #
#                   http://stackoverflow.com/questions/14167508/intermittent-sslv3-alert-handshake-failure-under-python #
#                                                                            #
#    2.0  [SW]  2016/03/01                                                   #
#                 Code optimization and Python3 support                      #
#                 SSL uncertified to prevent SSL: CERTIFICATE_VERIFY_FAILED  #
#    2.1  [SW]  2016/05/12                                                   #
#                  more flexible usage for data column                       #
#                                                                            #
#  Objective:                                                                #
#    The "SAM Interface Module for Python" (samifmod) enables you to write   #
#    application using the Nokia NSP SAM-O interface in Python.              #
#                                                                            #
#  License:                                                                  #
#    Licensed under the BSD license                                          #
#    See LICENSE.md delivered with this project for more information.        #
#                                                                            #
#  Author:                                                                   #
#    Sven Wisotzky                                                           #
#    mail:  sven.wisotzky(at)nokia.com                                       #
##############################################################################

"""
SAM-O Interface Module for Python Version 2.0
Copyright (C) 2008-2018 Nokia. All Rights Reserved.
"""

__title__ = "samifmod"
__version__ = "2.0"
__status__ = "released"
__author__ = "Sven Wisotzky"
__date__ = "2016 May 12th"

##############################################################################

import sys
import socket
import logging
import traceback
import argparse

import xml
import xml.dom.minidom

if sys.version_info < (3, 0):
    import hashlib
    import httplib
    from urlparse import urlparse
else:
    import hashlib
    import http.client
    from urllib.parse import urlparse

import ssl

if sys.version_info >= (3, 0):
	ssl._create_default_https_context = ssl._create_unverified_context

##############################################################################


class HTTPError(Exception):
    def __init__(self, code, msg, body):
        self.code = code
        self.msg = msg
        self.body = body

    def __str__(self):
        return 'HTTPError code:%d msg:%s\n%s' % (self.code, self.msg, self.body)

    def xml(self):
        return '<HTTPError code="%d" message="%s" />' % (self.code, self.msg)


class SOAPError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return "SOAPError: %s" % self.msg

    def xml(self):
        return "<SOAPError message=\"%s\" />" % self.msg


##############################################################################


class SamConnection:
    """
    5620SAM Server object to handle SAM-O interface (SOAP/XML based)
    """

    def __init__(self, server, port, user, password, use_ssl=False, hashing=True):
        self.server = server
        self.port = port
        self.user = user
        self.secure = use_ssl
        self.requestId = 0
        self.log = logging.getLogger("samifmod")

        if hashing:
            hcalc = hashlib.md5()
            hcalc.update(password.encode('utf-8'))
            self.passhash = hcalc.hexdigest()
        else:
            self.passhash = password

    @staticmethod
    def fromURL(samserver="http://SamOClient:5620Sam!@172.23.81.20"):
        if samserver.find('://') == -1:
            url = urlparse("http://" + samserver)
        else:
            url = urlparse(samserver)

        if url.scheme == 'http':
            if url.port:
                return SamConnection(url.hostname, url.port, url.username, url.password)
            else:
                return SamConnection(url.hostname, 8080, url.username, url.password)
        elif url.scheme == 'https':
            if url.port:
                return SamConnection(url.hostname, url.port, url.username, url.password, True)
            else:
                return SamConnection(url.hostname, 8443, url.username, url.password, True)
        else:
            raise SOAPError("Unsupported protocol %s" % url.scheme)

    @staticmethod
    def soap(xmlapi, requestId, user, passhash):
        request = '<SOAP:Envelope xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/">' + \
                  '<SOAP:Header><header xmlns="xmlapi_1.0"><security><user>' + \
                  user + '</user><password>' + passhash + '</password>' + \
                  '</security><requestID>PythonClient:' + str(requestId) + \
                  '</requestID></header></SOAP:Header><SOAP:Body>' + \
                  xmlapi + '</SOAP:Body></SOAP:Envelope>'
        return xml.dom.minidom.parseString(request).toprettyxml()

    @staticmethod
    def isActive(samserver="http://SamOClient:5620Sam!@172.23.81.20"):
        if samserver.find('://') == -1:
            url = urlparse("http://" + samserver)
        else:
            url = urlparse(samserver)

        if url.scheme == 'http':
            if url.port:
                return SamConnection.isActive(url.hostname, url.port, url.username, url.password)
            else:
                return SamConnection.isActive(url.hostname, 8080, url.username, url.password)
        elif url.scheme == 'https':
            if url.port:
                return SamConnection.isActive(url.hostname, url.port, url.username, url.password, True)
            else:
                return SamConnection.isActive(url.hostname, 8443, url.username, url.password, True)
        else:
            raise SOAPError("Unsupported protocol %s" % url.scheme)

    @staticmethod
    def isActive(server, port, user, password, use_ssl=False, hashing=True):
        socket.setdefaulttimeout(3)

        if hashing:
            hcalc = hashlib.md5()
            hcalc.update(password.encode('utf-8'))
            body = SamConnection.soap('<ping xmlns="xmlapi_1.0"/>', 'activityCheck', user, hcalc.hexdigest())
        else:
            body = SamConnection.soap('<ping xmlns="xmlapi_1.0"/>', 'activityCheck', user, password)

        blen = len(body)
        try:
            if use_ssl:
                if sys.version_info < (3, 0):
                    requestor = httplib.HTTPS(server, port)
                else:
                    requestor = http.client.HTTPSConnection(server, port)
            else:
                if sys.version_info < (3, 0):
                    requestor = httplib.HTTP(server, port)
                else:
                    requestor = http.client.HTTPConnection(server, port)

            requestor.set_debuglevel(0)
            requestor.putrequest('POST', '/xmlapi/invoke')
            requestor.putheader('Content-Type', 'text/xml; charset=ISO-8859-1')
            requestor.putheader('Content-Length', str(blen))
            requestor.putheader('Host', socket.gethostname())
            requestor.putheader('Accept', 'text/xml')
            requestor.putheader('Accept', 'text/plain')
            requestor.endheaders()

            requestor.send(body.encode('utf-8'))

            if sys.version_info < (3, 0):
                s_code, s_msg, reply_headers = requestor.getreply()
                # encoding = reply_headers['content-type'].split('charset=')[-1]
                # reply_body = requestor.getfile().read().decode(encoding).encode('utf-8')
            else:
                response = requestor.getresponse()
                s_code = response.status
                # s_msg = response.reason
                # encoding = response.getheader('content-type').split('charset=')[-1]
                # reply_body = response.read().decode(encoding).encode('utf-8')

        except socket.gaierror:
            # DNS lookup for SAM Server failed
            raise

        except socket.error:
            # SAM Server connection failure (e.g. operation timeout or connection refused)
            raise

        except:
            # Any other error
            raise

        if s_code in (200, 500):
            # This must be the active server
            return True

        elif s_code == 404:
            # This must be the standby server
            return False

        # unknown s_code
        return False

    def request(self, xmlapi, reqId=-1, timeout=-1, retries=5):
        self.log.info("SamConnection.request(reqId=%d)" % reqId)

        if timeout == -1:
            socket.setdefaulttimeout(None)
        else:
            socket.setdefaulttimeout(timeout)

        if reqId == -1:
            body = SamConnection.soap(xmlapi, reqId, self.user, self.passhash)
        else:
            self.requestId += 1
            body = SamConnection.soap(xmlapi, self.requestId, self.user, self.passhash)

        blen = len(body)
        self.log.debug("SOAP request body\n%s", body)

        run = 1
        while run <= retries:
            try:
                self.log.info("connect to %s:%d" % (self.server, self.port))
                if self.secure:
                    if sys.version_info < (3, 0):
                        requestor = httplib.HTTPS(self.server, self.port)
                    else:
                        requestor = http.client.HTTPSConnection(self.server, self.port)
                else:
                    if sys.version_info < (3, 0):
                        requestor = httplib.HTTP(self.server, self.port)
                    else:
                        requestor = http.client.HTTPConnection(self.server, self.port)

                requestor.set_debuglevel(0)
                requestor.putrequest('POST', '/xmlapi/invoke')
                requestor.putheader('Content-Type', 'text/xml; charset=ISO-8859-1')
                requestor.putheader('Content-Length', str(blen))
                requestor.putheader('Host', socket.gethostname())
                requestor.putheader('Accept', 'text/xml')
                requestor.putheader('Accept', 'text/plain')
                requestor.endheaders()

                requestor.send(body.encode('utf-8'))

                if sys.version_info < (3, 0):
                    s_code, s_msg, reply_headers = requestor.getreply()
                    encoding = reply_headers['content-type'].split('charset=')[-1]
                    reply_body = requestor.getfile().read().decode(encoding).encode('utf-8')
                else:
                    response = requestor.getresponse()
                    s_code = response.status
                    s_msg = response.reason
                    encoding = response.getheader('content-type').split('charset=')[-1]
                    reply_body = response.read().decode(encoding).encode('utf-8')
                break

            except (KeyboardInterrupt, SystemExit):
                self.log.debug('KeyboardInterupt/SystemExit catched')
                raise

            except socket.timeout:
                self.log.debug('socket.timeout catched')
                raise

            except:
                self.log.debug(sys.exc_info()[0])
                pass

            run += 1
        # end of while run <= retries

        if run > retries:
            self.log.debug(''.join(traceback.format_exception(*sys.exc_info())))
            raise

        if s_code not in (200, 500):
            if s_code == 404:
                self.log.error("%s is standby server", self.server)
            else:
                self.log.error("5620SAM Connection Failure Server %s", self.server)
            self.log.debug("status code:    %s", s_code)
            self.log.debug("status message: %s", s_msg)
            self.log.debug("http reply received\n%s", reply_body)
            raise HTTPError(s_code, s_msg, reply_body)

        self.log.info(
            "http reply received from %s\n%s\n", self.server, xml.dom.minidom.parseString(reply_body).toprettyxml())

        try:
            reply_xml = xml.dom.minidom.parseString(reply_body)
        except:
            self.log.error(sys.exc_info()[0])
            raise SOAPError("Malformed response received")

        soapHeader = reply_xml.getElementsByTagName("SOAP:Header")
        soapBody = reply_xml.getElementsByTagName("SOAP:Body")
        soapFault = reply_xml.getElementsByTagName("SOAP:Fault")

        if not(soapHeader and (soapBody or soapFault)):
            self.log.error("Malformed response received")
            raise SOAPError("Malformed response received")

        if soapFault:
            response = soapFault[0].getElementsByTagName("faultstring")[0].firstChild.data
            self.log.warning("bad response:\t%s", response)
            raise SOAPError("%s" % response)

        rvalue = []
        for ichild in soapBody[0].childNodes:
            rvalue.append(ichild.toxml())

        return rvalue

    def ping(self, requestId=-1, timeout=-1):
        rvalue = False

        try:
            response = self.request('<ping xmlns="xmlapi_1.0"/>', requestId, timeout)
            this_xml = xml.dom.minidom.parseString(response[0])
            if this_xml.firstChild.tagName == "pingResponse":
                rvalue = True
            else:
                # SOAP response received, but it is no ping response
                self.log.error("no ping reply: %s", this_xml.firstChild.tagName)

        except SOAPError as e:
            # all SOAP related failures
            self.log.error("Exception SOAPError: %s" % e)
        except HTTPError as e:
            # all HTTP / HTTPS related failures
            self.log.error(e)
        except socket.gaierror as e:
            # DNS lookup for SAM Server failed
            self.log.error("Exception GetAddressInfoError: %s" % e)
        except socket.timeout:
            self.log.error('Request timeout')
        except socket.error as e:
            # SAM Server connection failure (e.g. operation timeout or
            # connection refused)
            self.log.error("Exception Socket Error: %s" % e)
        except (KeyboardInterrupt, SystemExit):
            self.log.error('KeyboardInterupt/SystemExit catched')
        except:
            # other failures???
            self.log.error("Unknown Exception: %s" % sys.exc_info()[0])

        return rvalue

    def version(self, requestId=-1, timeout=-1):
        response = self.request('<version xmlns="xmlapi_1.0"/>', requestId, timeout)
        this_xml = xml.dom.minidom.parseString(response[0])
        if this_xml.firstChild.tagName == "versionResponse":
            major = this_xml.getElementsByTagName("baseVersion")[0].firstChild.data
            minor = this_xml.getElementsByTagName("build")[0].firstChild.data
            patch = this_xml.getElementsByTagName("patch")[0].firstChild.data
            return major + "." + minor + "-" + patch


##############################################################################

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--version', action='version', version='samifmod ' + __version__)

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-q', '--quiet',   action='store_true', help='disable logging')
    group.add_argument('-v', '--verbose', action='store_true', help='enhanced logging')
    group.add_argument('-d', '--debug',   action='store_true', help='enable debugging')

    group = parser.add_argument_group()
    group.add_argument('--logfile', metavar='<filename>', type=argparse.FileType('wb', 0), default='-', help='Specify the logfile (default: <stdout>)')
    group.add_argument('--output',  metavar='<filename>', type=argparse.FileType('wb', 0), default='-', help='Specify the output (default: <stdout>)')

    group = parser.add_argument_group()
    group.add_argument('server', metavar='http://<username>:<password>@<hostname>[:port]', help='5620SAM server (use http/https URL)')

    options = parser.parse_args()

    if options.quiet:
        loghandler = logging.NullHandler()
        loglevel = logging.NOTSET
    else:
        logformat = '%(asctime)s,%(msecs)-3d %(levelname)-8s %(threadName)s %(message)s'
        timeformat = '%y/%m/%d %H:%M:%S'
        loghandler = logging.StreamHandler(options.logfile)
        loghandler.setFormatter(logging.Formatter(logformat, timeformat))

        if options.debug:
            loglevel = logging.DEBUG
        elif options.verbose:
            loglevel = logging.INFO
        else:
            loglevel = logging.WARNING

        log = logging.getLogger('samifmod')
        log.setLevel(loglevel)
        log.addHandler(loghandler)

    # actual SamConnection example:

    mysam = SamConnection.fromURL(options.server)

    # Some more usage examples:
    # mysam = SamConnection.fromURL('http://SamOClient:5620Sam!@172.23.81.20')
    # mysam = SamConnection("172.22.108.240", 8443, "SamOClient", "5620Sam!", True)
    # mysam = SamConnection("172.22.108.240", 8080, "SamOClient", "5620Sam!")

    if mysam.ping(timeout=5):
        print("5620SAM Server is reachable")
        print(mysam.version())
    else:
        print("5620SAM Server is NOT reachable")

# EOF
