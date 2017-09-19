#!/usr/bin/python

##############################################################################
#                                                                            #
#  csvtool.py                                                                #
#                                                                            #
#  History Change Log:                                                       #
#                                                                            #
#    1.0  [SW]  2010/05/18    first version                                  #
#    1.2  [SW]  2011/06/17    adaptation to new samifmod version             #
#    2.0  [SW]  2012/09/18    combination of bluk reader and provision       #
#    2.1  [SW]  2012/09/26    improved online help                           #
#    2.2  [SW]  2012/09/27    adding 'objectClass' reference                 #
#                             adding 'callingObject' reference               #
#                             result level to filter output                  #
#                             search filter criteria to filter input         #
#    2.3  [SW]  2012/10/10    search xml-filter to filter input              #
#                             bulksize added to improve performance          #
#    2.4  [SW]  2012/10/22    store failed objects for later analysis/retry  #
#    2.5  [SW]  2012/10/29    logging improvements                           #
#    2.6  [SW]  2014/09/08    filename / line #                              #
#    2.7  [SW]  2014/11/04    make separation character configurable         #
#    2.8  [SW]  2015/03/16    interactive password input                     #
#    3.0  [SW]  2016/03/01    code optimization, python3 support, callouts   #
#    3.1  [SW]  2016/05/03    more flexible usage for data column            #
#    3.2  [SW]  2017/04/12    fix for FAILED object list (python3 migration) #
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
SAM-O CSV Tool in Python Version 3.2
Copyright (C) 2010-2017 Nokia. All Rights Reserved.
"""

__title__ = "csvtool"
__version__ = "3.2"
__status__ = "released"
__author__ = "Sven Wisotzky"
__date__ = "2017 April 12th"

##############################################################################

import os
import argparse
import csv
import sys
import re
import samifmod
import xml.dom.minidom
import time
import logging
import traceback
import getpass
import datetime

##############################################################################

class ProcessingError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return "ProcessingError: %s" % self.msg

    def xml(self):
        return "<ProcessingError message=\"%s\" />" % self.msg

##############################################################################
# Little Helper Functions
##############################################################################

def getText(nodelist):
    rc = ""
    for node in nodelist:
        rc += node.toxml()

    rc = rc.replace('"', '\'')

    if options.eol:
        rc = rc.replace('\n', '')
        rc = rc.replace('\r', '')
        rc = re.sub('\s+', " ", rc)
    elif options.quote:
        rc = rc.replace('\\',   r"\\")
        rc = rc.replace('\r\n', r"\n")
        rc = rc.replace('\n',   r"\n")
        rc = rc.replace('\r',   r"\n")
        rc = re.sub('\s+', " ", rc)

    if 1 in [char in rc for char in ",;\n\r\t"]:
        rc = '"' + rc + '"'

    return rc


def getObjects(types, values, parent, calling_item, nodelist):
    for node in nodelist:
        classname = node.nodeName
        fqdn = "N/A"
        tlist = []
        vlist = []

        for param in node.childNodes:
            if param.nodeName == "children-Set":
                if options.child:
                    getObjects(
                        types, values, fqdn, calling_item, param.childNodes)
                continue

            if param.nodeName == "objectFullName":
                fqdn = getText(param.childNodes)

            tlist.append(param.nodeName)
            vlist.append(getText(param.childNodes))

        if parent == "N/A":
            tlist.insert(0, 'parentFullName')
            vlist.insert(0, ':'.join(fqdn.split(':')[0:-1]))
        else:
            tlist.insert(0, 'parentFullName')
            vlist.insert(0, parent)

        tlist.insert(0, 'objectClass')
        vlist.insert(0, classname)

        if len(calling_item) > 0:
            tlist.insert(0, 'callingObject')
            vlist.insert(0, calling_item['objectFullName'])

        if classname not in types:
            types[classname] = tlist
            values[classname] = []

        values[classname].append(vlist)


def getExceptInfo(node):
    text = node.getElementsByTagName('description')[0].firstChild.toxml()
    text = text.replace('\n', '')
    text = text.replace('\r', '')
    return text


def findRequest(classname, criteria, children):
    """XML find request"""
    filter = ""
    rfilter = ""

    if criteria:
        if '<filter>' in criteria:
            filter = criteria
        elif '==' in criteria:
            (p, v) = criteria.split('==', 2)
            filter = "<filter><equal name='%s' value='%s'/></filter>" % (p, v)
        elif '!=' in criteria:
            (p, v) = criteria.split('!=', 2)
            filter = "<filter><notEqual name='%s' value='%s'/></filter>" % (
                p, v)
        elif '<=' in criteria:
            (p, v) = criteria.split('<=', 2)
            filter = "<filter><lessOrEqual name='%s' value='%s'/></filter>" % (
                p, v)
        elif '>=' in criteria:
            (p, v) = criteria.split('>=', 2)
            filter = "<filter><greaterOrEqual name='%s' value='%s'/></filter>" % (
                p, v)
        elif '<' in criteria:
            (p, v) = criteria.split('<', 2)
            filter = "<filter><less name='%s' value='%s'/></filter>" % (p, v)
        elif '>' in criteria:
            (p, v) = criteria.split('>', 2)
            filter = "<filter><greater name='%s' value='%s'/></filter>" % (
                p, v)
        elif '=~' in criteria:
            (p, v) = criteria.split('=~', 2)
            filter = "<filter><wildcard name='%s' value='%s'/></filter>" % (
                p, v)
        elif '!~' in criteria:
            (p, v) = criteria.split('!~', 2)
            filter = "<filter><not><wildcard name='%s' value='%s'/></not></filter>" % (
                p, v)

    log.debug("search filter: %s", filter)

    if not children:
        rfilter = "<resultFilter><children/></resultFilter>"

    return '<find xmlns="xmlapi_1.0"><fullClassName>' + classname + '</fullClassName>' + filter + rfilter + '</find>'


def getBatchesFromClass(nodelist):
    """Get calling objects (batch mode)"""
    batches = []

    responses = mysam.request(findRequest(options.classname, options.criteria, False))
    for result in xml.dom.minidom.parseString(responses[0]).getElementsByTagName('result'):
        for node in result.childNodes:
            tlist = []
            vlist = []
            tlist.append('objectClass')
            vlist.append(node.nodeName)
            for param in node.childNodes:
                if param.nodeName == "objectFullName":
                    tlist.append('parentFullName')
                    vlist.append(
                        ':'.join(getText(param.childNodes).split(':')[0:-1]))
                tlist.append(param.nodeName)
                vlist.append(getText(param.childNodes))
            batches.append(dict(list(zip(tlist, vlist))))

    return batches


def getBatchesFromCSV(csvfile, sChar):
    """Get calling objects from CSV file (batch mode)"""

    csvReader = csv.reader(csvfile, delimiter=sChar, quotechar='"')

    idx = 2
    plist = []
    batches = []

    for row in csvReader:
        if len(row) == 0:
            continue

        if len(plist) == 0:
            plist = row
            continue

        object = dict(list(zip(plist, row)))
        
        if (chk_date != None) and '**date' in object:
            dateX = object["**date"]
            if ('.' in dateX):
                xx = dateX.split(".")
                dateX = datetime.date(int(xx[2]), int(xx[1]), int(xx[0]))
            elif ('-' in dateX):
                xx = dateX.split("-")
                dateX = datetime.date(int(xx[0]), int(xx[1]), int(xx[2]))

            if (chk_date != dateX):
                continue

        object["FILE"] = os.path.basename(csvfile.name) + ":" + str(idx)
        idx = idx + 1

        batches.append(object)

    return batches

##############################################################################
    
def findObject(className, attributeName, attributeValue):
    # example:
    #   [[!findObject('script.AbstractScript', 'scriptName', 'test 123')]]
    
    sfilter = "<filter><equal name='%s' value='%s'/></filter>" % (attributeName, attributeValue)
    rfilter = "<resultFilter><attribute>objectFullName</attribute><children /></resultFilter>"
    reqxml  = "<find xmlns='xmlapi_1.0'><fullClassName>%s</fullClassName>%s%s</find>" % (className, sfilter, rfilter)
    responses = mysam.request(reqxml)

    for result in xml.dom.minidom.parseString(responses[0]).getElementsByTagName('result'):
        for node in result.childNodes:
            for param in node.childNodes:
                if param.nodeName == "objectFullName":
                    # found ObjectFullName 
                    return getText(param.childNodes)
    
    raise ProcessingError("%s object not found with criteria %s=='%s'" % (className, attributeName, attributeValue))
    return "none"

def callout(xmlTemplate):
    while (xmlTemplate.find('[[!')!=-1):
        pos1=xmlTemplate.find('[[!')
        pos2=xmlTemplate.find(']]', pos1)
        xmlTemplate = xmlTemplate[:pos1] + str(eval(xmlTemplate[pos1+3:pos2])) + xmlTemplate[pos2+2:]
    return xmlTemplate
    
##############################################################################

if __name__ == '__main__':
    prog = os.path.splitext(os.path.basename(sys.argv[0]))[0]
    dlog = prog + '.log'

    parser = argparse.ArgumentParser()
    parser.add_argument('--version', action='version', version=prog+' '+__version__)

    group = parser.add_mutually_exclusive_group()
    group.add_argument('--quiet',   action='store_true', help='disable logging')
    group.add_argument('--verbose', action='store_true', help='enhanced logging')
    group.add_argument('--debug',   action='store_true', help='enable debugging (incl ssh-lib)')

    group = parser.add_argument_group()
    group.add_argument('--logfile', metavar='<filename>', type=argparse.FileType('wt'), default=dlog, help='Specify the logfile (default: %s)' % dlog)

    # 5620SAM Server Connectivity
    group = parser.add_argument_group()
    group.add_argument('-s',            dest='server',   help='5620SAM server', default='10.15.120.110,10.15.120.111'),
    group.add_argument('-u',            dest='user',     help='5620SAM oss user name',     default='SamOClient')
    group.add_argument('-p',            dest='password', help='5620SAM oss user password', default='5620Sam!')
    group.add_argument('--md5',         dest='md5',         action='store_true', default=False, help='password is md5 hashed')
    group.add_argument('--secure',      dest='secure',      action='store_true', default=False, help='use HTTPS instead of HTTP')
    group.add_argument('--interactive', dest='interactive', action='store_true', default=False, help='prompt for OSS username/password')

    # Execution Parameters (Input)
    group = parser.add_argument_group()
    group.add_argument('--class',    dest='classname', help='CLASS name based request')
    group.add_argument('--batch',    dest='csvfile', metavar='<csv-file>', type=argparse.FileType('rU'), help='CSV file - contains batch object list')
    group.add_argument('--bulksize', dest='bulksize', default=1, help='Improve Performance by grouping bulk requests')
    group.add_argument('--xml',      dest='xmlfile', help='XML file - contains batch XMLAPI request')
    group.add_argument('--date',     dest='date', metavar='<dd-mm-yyyy|interactive|today|tomorrow>', help='Filter <csv-file> by column [**date]')

    # Execution Parameters (Output)
    group = parser.add_argument_group()
    group.add_argument('--csv',   dest='filename', default='default', help='CSV file for results <stdout|stderr|multi|filname|none>')
    group.add_argument('--eol',   dest='eol',   action='store_true', default=False, help='EoL character suppression')
    group.add_argument('--quote', dest='quote', action='store_true', default=False, help='EoL character quotation (\\n and \\r)')
    group.add_argument('--separator', dest='separator', default='comma', help='CSV separator <tab|comma|colon|semicolon>')

    # Execution Parameters (Processing)
    group = parser.add_argument_group()
    group.add_argument('--delay',    dest='seconds', help='provisioning delay', default=0),
    group.add_argument('--store',   dest='store', action='store_true', default=False, help='store failed objects')
    group.add_argument('--result',   dest='level', default='default', help='xml result level wrapper')
    group.add_argument('--filter',   dest='criteria', default='', help='filter criteria for class name based request')
    group.add_argument('--children', dest='child',  action='store_true', default=False,    help='search children too')

    options = parser.parse_args()

    # --- setup logging ------------------------------------------------------

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

    log = logging.getLogger(prog)
    log.setLevel(loglevel)
    log.addHandler(loghandler)

    if options.debug:
        logging.getLogger('samifmod').setLevel(logging.DEBUG)
        logging.getLogger('samifmod').addHandler(loghandler)
    else:
        logging.getLogger('samifmod').setLevel(logging.NOTSET)
        logging.getLogger('samifmod').addHandler(logging.NullHandler())

    # --- check parameters received ------------------------------------------

    if not options.xmlfile and not options.classname:
        parser.error("Options --xml or --class is needed")

    if options.csvfile and options.classname:
        parser.error("Options --batch and --class to be used exclusively")

    if options.csvfile and not options.xmlfile:
        parser.error("Option --batch requires option --xml")

    if options.criteria and not options.classname:
        parser.error("Option --filter requires option --class")

    if options.filename == 'default':
        if options.xmlfile and options.classname:
            options.filename = 'none'
        elif options.xmlfile and options.csvfile:
            options.filename = 'none'
        else:
            options.filename = 'multi'

    if options.separator == "tab":
        sChar = '\t'
    elif options.separator == "comma":
        sChar = ','
    elif options.separator == "colon":
        sChar = ':'
    else:
        sChar = ';'

    # --- get username/password via stdin ------------------------------------

    if options.interactive:
        sys.stdout.write("Username: ")
        sys.stdout.flush()
        options.user = sys.stdin.readline().rstrip()
        options.password = getpass.getpass()

    # --- calculate date check -----------------------------------------------

    if options.date=='interactive':
        sys.stdout.write("Date: ")
        sys.stdout.flush()
        options.date = sys.stdin.readline().rstrip()
    
    if (options.date):
        if (options.date=='today'):
            chk_date = datetime.date.today()
        elif (options.date=='tomorrow'):
            chk_date = datetime.date.today() + datetime.timedelta(days=1)
        elif (options.date=='yesterday'):
            chk_date = datetime.date.today() - datetime.timedelta(days=1)
        elif (options.date[0]=='+'):
            delta = int(options.date[1:])
            chk_date = datetime.date.today() + datetime.timedelta(days=delta)
        elif (options.date[0]=='-'):
            delta = int(options.date[1:])
            chk_date = datetime.date.today() - datetime.timedelta(days=delta)
        elif ('.' in options.date):
            xx = options.date.split(".")
            chk_date = datetime.date(int(xx[2]), int(xx[1]), int(xx[0]))
        elif ('-' in options.date):
            xx = options.date.split("-")
            chk_date = datetime.date(int(xx[0]), int(xx[1]), int(xx[2]))
        else:
            parser.error("Unsupported value for option --date")
    else:
        chk_date = None
            
    # --- setup 5620SAM communication object ---------------------------------

    mysam = None
    for server in options.server.split(","):
        try:
            if options.secure:
                if samifmod.SamConnection.isActive(server, 8443, options.user, options.password, True, not options.md5):
                    mysam = samifmod.SamConnection(server, 8443, options.user, options.password, True, not options.md5)
                    break
            else:
                if samifmod.SamConnection.isActive(server, 8080, options.user, options.password, False, not options.md5):
                    mysam = samifmod.SamConnection(server, 8080, options.user, options.password, False, not options.md5)
                    break
        except Exception as e:
            log.warning("SAM server activity check failed: %s (%s)", server, str(e))

    if mysam == None:
        log.critical("SAM server(s) not reachable")
        quit()

    # --- initialize variables -----------------------------------------------

    headers = {}
    objects = {}
    itemlist = []

    if options.xmlfile:
        try:
            if sys.version_info < (3, 0):
                xmlTemplate = open(options.xmlfile).read()
            else:
                xmlTemplate = open(options.xmlfile, encoding="latin-1").read()
        except:
            log.error("%s %s" % (sys.exc_info()[0], sys.exc_info()[1]))
            log.error("Can not read xml file: %s", options.xmlfile)
            exit()
            
        try:
            xmlTemplate = callout(xmlTemplate)

        except ProcessingError as e:
            log.error("%s", e.xml())
            quit()

        except samifmod.SOAPError as e:
            log.error("%s", e.xml())
            quit()

        except samifmod.HTTPError as e:
            log.error("%s", e.xml())
            quit()

        except KeyboardInterrupt:
            log.error("^C break received")
            quit()

        except:
            log.error("Failure during template callout processing")
            quit()

    if options.level == "default":
        if options.xmlfile:
            options.level = "1"
            # running in batch mode (csvfile or classname), default level is 1
        else:
            options.level = "2"
            # running in query mode, default level is 2

    # --- get batch items ----------------------------------------------------

    if options.csvfile:
        try:
            itemlist = getBatchesFromCSV(options.csvfile, sChar)
        except:
            log.error("Can not read CSV file: %s", options.csvfile)
            exit()

    elif options.xmlfile and options.classname:
        itemlist = getBatchesFromClass(options.classname)
    else:
        itemlist.append({})

    # --- execute SAM-O request ----------------------------------------------

    if len(itemlist) == 0:
        log.error("Nothing to be done (itemlist empty)")
        exit()

    if options.xmlfile and 'objectClass' in itemlist[0]:
        print(("CLASS %s execute %s objects" %
              (itemlist[0]['objectClass'], len(itemlist))))

    # Remarks:
    #   Variables index, total and blksz are used for bulkmode. This is to enhance
    #   XMLAPI execution performance, especially when latency plays a role. We first
    #   concat all pending request in reqxml. Exceptions are stored in the ecache for
    #   later output.

    index = 0
    total = len(itemlist)
    blksz = int(options.bulksize)

    reqxml = ""
    ecache = ""

    # Remarks:
    #   We don't know how many XML requests are in the xml file. To determine the
    #   number of XMLAPI request per object, we simple count the number of responses
    #   and divide by the number of objects.
    #   The set 'failed' is used, to check - which objects have returned an exception
    #   for whatever reason. This is to store the failed objects later.

    failed = set()
    subidx = 0
    factor = 0

    for item in itemlist:
        if options.xmlfile:
            reqxml += xmlTemplate % item
        else:
            reqxml += findRequest(options.classname, options.criteria, options.child)

        index = index + 1
        if index % blksz > 0 and index < total:
            continue

        try:
            responses = mysam.request(reqxml)
            reqxml = ""

            if factor < 1:
                factor = len(responses) / index

            for response in responses:
                this_xml = xml.dom.minidom.parseString(response)
                if "Exception" in this_xml.firstChild.tagName:
                    ecache += getExceptInfo(this_xml.firstChild) + "\n"
                    sys.stdout.write('E')
                    failed.add(int(subidx / factor))
                    subidx += 1
                elif len(this_xml.getElementsByTagName('Exception')) > 0:
                    # should only occur when
                    # <continueOnFailure>true</continueOnFailure> is set
                    ecache += getExceptInfo(
                        this_xml.getElementsByTagName('Exception')[0]) + "\n"
                    sys.stdout.write('E')
                    failed.add(int(subidx / factor))
                    subidx += 1
                else:
                    if options.level == "0":
                        getObjects(
                            headers, objects, "N/A", item, this_xml.childNodes)
                    elif options.level == "1":
                        getObjects(
                            headers, objects, "N/A", item, this_xml.firstChild.childNodes)
                    elif options.level == "2":
                        getObjects(
                            headers, objects, "N/A", item, this_xml.firstChild.firstChild.childNodes)
                    elif options.level == "3":
                        getObjects(
                            headers, objects, "N/A", item, this_xml.firstChild.firstChild.firstChild.childNodes)
                    # if option.level not in [0..3] there is nothing to do

                    sys.stdout.write('.')
                    subidx += 1
            sys.stdout.flush()

        except samifmod.SOAPError as e:
            log.error("%s", e.xml())
            quit()

        except samifmod.HTTPError as e:
            log.error("%s", e.xml())
            quit()

        except KeyboardInterrupt:
            log.error("^C break received")
            quit()

        except:
            obj = str(sys.exc_info()[0])
            if (obj.find("'") > 0):
                obj = obj.split("'")[1]
            msg = str(sys.exc_info()[1])
            if (msg.find("'") > 0):
                msg = msg.split("'")[1]
            log.error("%s (%s)", obj, msg)

        if options.seconds > 0:
            time.sleep(int(options.seconds))

    print(" done\n")
    sys.stdout.flush()

    if len(itemlist) > 1 and len(failed) > 0 and options.store:
        if 'objectClass' in itemlist[0]:
            csvfile = open('FAILED_' + itemlist[0]['objectClass'] + '.csv', 'wb')
        else:
            csvfile = open('FAILED_OBJECTS.csv', 'wb')
      
        csvfile.write(bytes(sChar.join(list(itemlist[0].keys()))+'\n', 'utf-8'))
      
        for idx in failed:
            csvfile.write(bytes(sChar.join(list(itemlist[idx].values()))+'\n', 'utf-8'))

    if len(ecache) > 0 and ((loglevel != logging.NOTSET) or len(itemlist) == 1):
        log.error("RECEIVED ERRORS (%s objects):\n%s", len(failed), ecache)

    # --- store results ------------------------------------------------------

    for classname in list(headers.keys()):
        print(("CLASS [%s] - %s objects" % (classname, len(objects[classname]))))

        if options.filename == "none":
            continue

        if len(headers) > 1 or options.filename == "multi":
            csvfile = open(classname + '.csv', 'wb')
        elif options.filename == "stdout":
            csvfile = sys.stdout
        elif options.filename == "stderr":
            csvfile = sys.stderr
        else:
            csvfile = open(options.filename, 'wb')

        if sys.version_info < (3, 0):
            csvfile.write(sChar.join(headers[classname])+'\n')
        else:
            csvfile.write(bytes(sChar.join(headers[classname])+'\n', 'utf-8'))

        for object in objects[classname]:
            if sys.version_info < (3, 0):
                csvfile.write(sChar.join(object)+'\n')
            else:
                csvfile.write(bytes(sChar.join(object)+'\n', 'utf-8'))

    if len(headers) == 0 and options.filename != "none":
        print("No objects returned by 5620SAM")

# EOF
