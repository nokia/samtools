#!/usr/bin/python

##############################################################################
#                                                                            #
#  samifmod.py                                                               #
#                                                                            #
#  History Change Log:                                                       #
#                                                                            #
#    1.0  [SW]  2008/05/20    first version                                  #
#    2.0  [SW]  2011/06/17    supports: security, multiple servers           #
#    2.1  [SW]  2011/08/09    time support improved                          #
#    2.2  [SW]  2010/09/27    cleartext and md5 password support added       #
#                             list of xml files can be executed at once      #
#                                                                            #
#  Objective:                                                                #
#    Tool to send XML files containing SAM-O requests to the SAM/NSP server  #
#    using SOAP over HTTP/s. Result is captured for further processing.      #
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
Post SAM-O Requests in Python
Copyright (C) 2008-2018 Nokia. All Rights Reserved.
"""

__title__ = "sendXML"
__version__ = "2.2"
__status__ = "released"
__author__ = "Sven Wisotzky"
__date__ = "2012 September 27th"

##############################################################################

import logging
import samifmod
import xml.dom.minidom
import os, sys, time, string, re

from time import time
from datetime import datetime
from optparse import OptionParser, OptionGroup

##############################################################################

def getContent(line):
	idx  = 0
	pos4 = len(line)-1

	while pos4>0 and line[pos4] in (' ','\n','\r','\t'): pos4-=1
	if (pos4==0): return ("","")

	while idx<pos4 and line[idx] in (' ','\n','\r','\t'): idx+=1
	pos1 = idx
	while idx<pos4 and line[idx] not in (' ','\n','\r','\t'): idx+=1
	pos2 = idx
	while idx<pos4 and line[idx] in (' ','\n','\r','\t'): idx+=1
	pos3 = idx
	
	if pos2==pos4:
		return ("", "")
	else:
		return (line[pos1:pos2], line[pos3:pos4+1])

##############################################################################
# evaluate command line paramters
##############################################################################

prolog = ''''''

epilog = '''The script expects a list of XML files containing 5620SAM XMLAPI
requests to execute. The list may contain one or multiple files.'''

parser = OptionParser(usage="USAGE: %prog [OPTIONS] FILENAME [FILENAME]", version="%prog version "+__version__, description=prolog, epilog=epilog)

group = OptionGroup(parser, "5620SAM Server Connectivity")
group.add_option("-s", dest="server",   help="5620SAM server",            default="10.15.120.110,10.15.120.111"),
group.add_option("-u", dest="user",     help="5620SAM oss user name",     default="SamOClient")
group.add_option("-p", dest="password", help="5620SAM oss user password", default="5620Sam!")
group.add_option("--md5",    dest="md5",    action="store_true", default=False, help="password is md5 hashed")
group.add_option("--secure", dest="secure", action="store_true", default=False, help="use HTTPS instead of HTTP")
group.add_option("-t", dest="timeout",  help="5620SAM request timeout",   default=-1)
parser.add_option_group(group)

group = OptionGroup(parser, "Debug Options")
group.add_option("--quiet",    dest="quiet",   action="store_true", default=False, help="suppress information")
group.add_option("--verbose",  dest="verbose", action="store_true", default=False, help="enable debug mode")
group.add_option("--debug",    dest="debug",   action="store_true", default=False, help="enhanced debug info")
parser.add_option_group(group)

(options, filenames) = parser.parse_args()

if not options.server:
	parser.error("option -s is mandatory")

if not options.user:
	parser.error("option -u is mandatory")

if not options.password:
	parser.error("option -p is mandatory")

if len(filenames) < 1:
	parser.error("list of filenames is mandatory")

##############################################################################
# setup 5620SAM communication object
##############################################################################

if options.secure:
	mysam = samifmod.SamConnection(options.server, 8443, options.user, options.password, True,  not options.md5)
else:
	mysam = samifmod.SamConnection(options.server, 8080, options.user, options.password, False, not options.md5)

if options.quiet:
	mysam.quiet()

if options.verbose:
	mysam.verbose()

if options.debug:
	mysam.debug()

if ',' in options.server:
	if not mysam.selectServer(options.server):
		print '''<ERROR: SAM servers not reachable/>\n'''
		quit()

##############################################################################

now = int(round(time()/60))
plist_init = {}
plist_init["now"]         = str(60000* now)
plist_init["before15min"] = str(60000*(now-15))
plist_init["before60min"] = str(60000*(now-60))
plist_init["before2h"]    = str(60000*(now-120))
plist_init["before4h"]    = str(60000*(now-240))
plist_init["before6h"]    = str(60000*(now-360))
plist_init["before12h"]   = str(60000*(now-720))
plist_init["before24h"]   = str(60000*(now-1440))
plist_init["date"]        = datetime.today().strftime("%Y%m%d")
plist_init["time"]        = datetime.today().strftime("%H%M%S")

results = []

try:
	for filename in filenames:
		request  = open(filename).read()
		param = "none"
		plist = plist_init

		for line in request.split('\n'):
			(tag,value) = getContent(line)
			if (tag=="@param"):     param=value
			if (tag=="example:"):	plist[param]=value

		rmXmlCom = re.compile('<!--.*?-->', re.DOTALL);
		x1=rmXmlCom.sub('', request)
		x2 = re.sub('^[\s\n\r]*<', '<', x1)
		request = re.sub('>[\s\n\r]*$', '>', x2)

		response = mysam.request(request%plist, timeout=float(options.timeout))
		for result in response:
			results.append(result.encode('utf-8'))
			# object   = xml.dom.minidom.parseString(response[0])
			# print object.toprettyxml()
	
except samifmod.SOAPError, e:
	print e.xml()
	
except samifmod.HTTPError, e:
	print e.xml()

except:
	obj = str(sys.exc_info()[0])
	if (obj.find("'")>0): obj = obj.split("'")[1]

	msg = str(sys.exc_info()[1])
	if (msg.find("'")>0): msg = msg.split("'")[1]

	print "<%s message=\"%s\" />" % (obj, msg)

if len(results)==1:
	print results[0]
elif len(results)==0:
	print "<No Results/>"
else:
	print "<MultiResponseSendXML>"
	for result in results: print result
	print "</MultiResponseSendXML>"
	
# EOF