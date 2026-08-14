#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   WMI multitool for registry, service, process, and enumeration
#   operations via DCOM. No processes are spawned on the target.
#
#   Subcommands:
#     reg      - Registry operations via StdRegProv (root/default)
#     service  - Service management via Win32_Service
#     process  - Process listing and termination via Win32_Process
#     enum     - System enumeration (sysinfo, users, groups, shares,
#                disks, network adapters)
#
# Author:
#   Black Lantern Security
#
# Reference for:
#   DCOM/WMI
#

from __future__ import division
from __future__ import print_function
import sys
import argparse
import logging

from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket import version
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcom.wmi import WBEMSTATUS
from impacket.dcerpc.v5.dcomrt import DCOMConnection, COMVERSION
from impacket.dcerpc.v5.dtypes import NULL
from impacket.krb5.keytab import Keytab

HIVE_MAP = {
    'HKLM': 0x80000002, 'HKEY_LOCAL_MACHINE': 0x80000002,
    'HKCU': 0x80000001, 'HKEY_CURRENT_USER': 0x80000001,
    'HKU':  0x80000003, 'HKEY_USERS': 0x80000003,
    'HKCR': 0x80000000, 'HKEY_CLASSES_ROOT': 0x80000000,
    'HKCC': 0x80000005, 'HKEY_CURRENT_CONFIG': 0x80000005,
}

TYPE_MAP = {
    1: 'REG_SZ', 2: 'REG_EXPAND_SZ', 3: 'REG_BINARY',
    4: 'REG_DWORD', 7: 'REG_MULTI_SZ', 11: 'REG_QWORD',
}


class WMIConnection:
    def __init__(self, host, username, password, domain,
                 lmhash='', nthash='', aesKey=None,
                 doKerberos=False, kdcHost=None):
        self.__host = host
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = lmhash
        self.__nthash = nthash
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost

    def connect(self, namespace='//./root/cimv2'):
        dcom = DCOMConnection(self.__host, self.__username, self.__password,
                              self.__domain, self.__lmhash, self.__nthash,
                              self.__aesKey, oxidResolver=False,
                              doKerberos=self.__doKerberos,
                              kdcHost=self.__kdcHost)
        iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,
                                             wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        iWbemServices = iWbemLevel1Login.NTLMLogin(namespace, NULL, NULL)
        iWbemLevel1Login.RemRelease()
        return dcom, iWbemServices

    @staticmethod
    def check_error(banner, resp):
        call_status = resp.GetCallStatus(0) & 0xffffffff
        if call_status != 0:
            try:
                error_name = WBEMSTATUS.enumItems(call_status).name
            except ValueError:
                error_name = 'Unknown'
            logging.error('%s - ERROR: %s (0x%08x)' % (banner, error_name, call_status))
            return False
        logging.info('%s - OK' % banner)
        return True


def _iter_query(iWbemServices, query):
    iEnum = iWbemServices.ExecQuery(query)
    try:
        while True:
            try:
                item = iEnum.Next(0xffffffff, 1)[0]
                yield item.getProperties()
            except Exception as e:
                if str(e).find('S_FALSE') < 0:
                    raise
                break
    finally:
        iEnum.RemRelease()


class RegOps:
    def __init__(self, iWbemServices):
        self.reg, _ = iWbemServices.GetObject('StdRegProv')

    @staticmethod
    def parse_keyname(keyname):
        parts = keyname.split('\\', 1)
        hive_str = parts[0].upper()
        subkey = parts[1] if len(parts) > 1 else ''
        hive = HIVE_MAP.get(hive_str)
        if hive is None:
            raise ValueError("Unknown hive: %s" % hive_str)
        return hive, subkey

    def query(self, hive, subkey, valuename=None):
        if valuename:
            return self._query_value(hive, subkey, valuename)

        try:
            ret = self.reg.EnumKey(hive, subkey)
            if ret.ReturnValue == 0 and ret.sNames:
                print('[+] Subkeys of %s:' % subkey)
                for n in ret.sNames:
                    print('    %s' % n)
        except Exception as e:
            print('[-] EnumKey failed: %s' % e)

        try:
            ret = self.reg.EnumValues(hive, subkey)
            if ret.ReturnValue == 0 and ret.sNames:
                print('[+] Values:')
                for name in ret.sNames:
                    self._query_value(hive, subkey, name)
        except Exception as e:
            print('[-] EnumValues failed: %s' % e)

    def _query_value(self, hive, subkey, valuename):
        for method, vtype, attr in [
            ('GetStringValue',         'REG_SZ',        'sValue'),
            ('GetExpandedStringValue', 'REG_EXPAND_SZ', 'sValue'),
            ('GetDWORDValue',          'REG_DWORD',     'uValue'),
            ('GetMultiStringValue',    'REG_MULTI_SZ',  'sValue'),
            ('GetBinaryValue',         'REG_BINARY',    'uValue'),
            ('GetQWORDValue',          'REG_QWORD',     'uValue'),
        ]:
            try:
                ret = getattr(self.reg, method)(hive, subkey, valuename)
                if ret.ReturnValue == 0:
                    val = getattr(ret, attr, None)
                    if vtype == 'REG_BINARY' and val is not None:
                        val = bytes(val).hex()
                    elif vtype == 'REG_DWORD' and val is not None:
                        val = '%d (0x%x)' % (val, val)
                    elif vtype == 'REG_MULTI_SZ' and val is not None:
                        val = ' | '.join(val) if val else '(empty)'
                    print('    %s    %s    %s' % (valuename, vtype, val))
                    return True
            except Exception:
                continue
        print('[-] Value \'%s\' not found or access denied' % valuename)
        return False

    def add(self, hive, subkey, valuename, valuetype, valuedata):
        vt = valuetype.upper()

        try:
            self.reg.CreateKey(hive, subkey)
        except Exception:
            pass

        try:
            if vt == 'REG_SZ':
                ret = self.reg.SetStringValue(hive, subkey, valuename, valuedata[0])
            elif vt == 'REG_EXPAND_SZ':
                ret = self.reg.SetExpandedStringValue(hive, subkey, valuename, valuedata[0])
            elif vt == 'REG_DWORD':
                ret = self.reg.SetDWORDValue(hive, subkey, valuename, int(valuedata[0], 0))
            elif vt == 'REG_QWORD':
                ret = self.reg.SetQWORDValue(hive, subkey, valuename, int(valuedata[0], 0))
            elif vt == 'REG_MULTI_SZ':
                ret = self.reg.SetMultiStringValue(hive, subkey, valuename, valuedata)
            elif vt == 'REG_BINARY':
                ret = self.reg.SetBinaryValue(hive, subkey, valuename, list(bytes.fromhex(valuedata[0])))
            else:
                print('[-] Unsupported type: %s' % vt)
                return False

            if ret.ReturnValue == 0:
                print('[+] Set %s = %s (%s)' % (valuename, valuedata, vt))
                return True
            else:
                print('[-] Set failed, return value: %d' % ret.ReturnValue)
                return False
        except Exception as e:
            print('[-] Set failed: %s' % e)
            return False

    def delete(self, hive, subkey, valuename=None):
        try:
            if valuename:
                ret = self.reg.DeleteValue(hive, subkey, valuename)
                if ret.ReturnValue == 0:
                    print('[+] Deleted value: %s' % valuename)
                else:
                    print('[-] DeleteValue returned: %d' % ret.ReturnValue)
            else:
                ret = self.reg.DeleteKey(hive, subkey)
                if ret.ReturnValue == 0:
                    print('[+] Deleted key: %s' % subkey)
                else:
                    print('[-] DeleteKey returned: %d' % ret.ReturnValue)
            return ret.ReturnValue == 0
        except Exception as e:
            print('[-] Delete failed: %s' % e)
            return False

    def createkey(self, hive, subkey):
        try:
            ret = self.reg.CreateKey(hive, subkey)
            if ret.ReturnValue == 0:
                print('[+] Created key: %s' % subkey)
            else:
                print('[-] CreateKey returned: %d' % ret.ReturnValue)
            return ret.ReturnValue == 0
        except Exception as e:
            print('[-] CreateKey failed: %s' % e)
            return False


class ServiceOps:
    def __init__(self, iWbemServices):
        self.__iWbemServices = iWbemServices

    def list(self, name_filter=None):
        query = 'SELECT Name, State, StartMode, PathName FROM Win32_Service'
        if name_filter:
            query += " WHERE Name LIKE '%%%s%%'" % name_filter

        print('%-40s %-12s %-12s %s' % ('Name', 'State', 'StartMode', 'PathName'))
        print('%-40s %-12s %-12s %s' % ('----', '-----', '---------', '--------'))
        for props in _iter_query(self.__iWbemServices, query):
            print('%-40s %-12s %-12s %s' % (
                props['Name']['value'] or '',
                props['State']['value'] or '',
                props['StartMode']['value'] or '',
                props['PathName']['value'] or '',
            ))

    def start(self, name):
        query = "SELECT * FROM Win32_Service WHERE Name='%s'" % name
        for props in _iter_query(self.__iWbemServices, query):
            svc_path = "Win32_Service.Name='%s'" % name
            svc_obj, _ = self.__iWbemServices.GetObject(svc_path)
            result = svc_obj.StartService()
            ret = result.ReturnValue
            if ret == 0:
                print('[+] Service \'%s\' started' % name)
            else:
                print('[-] StartService returned: %d' % ret)
            return
        print('[-] Service \'%s\' not found' % name)

    def stop(self, name):
        query = "SELECT * FROM Win32_Service WHERE Name='%s'" % name
        for props in _iter_query(self.__iWbemServices, query):
            svc_path = "Win32_Service.Name='%s'" % name
            svc_obj, _ = self.__iWbemServices.GetObject(svc_path)
            result = svc_obj.StopService()
            ret = result.ReturnValue
            if ret == 0:
                print('[+] Service \'%s\' stopped' % name)
            else:
                print('[-] StopService returned: %d' % ret)
            return
        print('[-] Service \'%s\' not found' % name)

    def status(self, name):
        query = "SELECT * FROM Win32_Service WHERE Name='%s'" % name
        for props in _iter_query(self.__iWbemServices, query):
            print('[*] Service: %s' % name)
            for key in sorted(props.keys()):
                val = props[key]['value']
                if isinstance(val, list):
                    val = ', '.join(str(v) for v in val)
                print('  %-30s %s' % (key + ':', val))
            return
        print('[-] Service \'%s\' not found' % name)


class ProcessOps:
    def __init__(self, iWbemServices):
        self.__iWbemServices = iWbemServices

    def list(self, name_filter=None):
        query = 'SELECT ProcessId, Name, SessionId, CommandLine FROM Win32_Process'
        if name_filter:
            query += " WHERE Name LIKE '%%%s%%'" % name_filter

        print('%-8s %-30s %-10s %s' % ('PID', 'Name', 'SessionId', 'CommandLine'))
        print('%-8s %-30s %-10s %s' % ('---', '----', '---------', '-----------'))
        for props in _iter_query(self.__iWbemServices, query):
            print('%-8s %-30s %-10s %s' % (
                props['ProcessId']['value'],
                props['Name']['value'] or '',
                props['SessionId']['value'],
                props['CommandLine']['value'] or '',
            ))

    def kill(self, pid):
        query = 'SELECT * FROM Win32_Process WHERE ProcessId=%d' % pid
        for props in _iter_query(self.__iWbemServices, query):
            proc_path = 'Win32_Process.Handle="%d"' % pid
            proc_obj, _ = self.__iWbemServices.GetObject(proc_path)
            result = proc_obj.Terminate(0)
            ret = result.ReturnValue
            if ret == 0:
                print('[+] Process %d terminated' % pid)
            else:
                print('[-] Terminate returned: %d' % ret)
            return
        print('[-] Process with PID %d not found' % pid)


class EnumOps:
    def __init__(self, iWbemServices):
        self.__iWbemServices = iWbemServices

    def _print_query(self, title, query, fields=None):
        print('[*] %s' % title)
        count = 0
        for props in _iter_query(self.__iWbemServices, query):
            if count > 0:
                print('')
            keys = fields if fields else sorted(props.keys())
            for key in keys:
                if key in props:
                    val = props[key]['value']
                    if isinstance(val, list):
                        val = ', '.join(str(v) for v in val) if val else ''
                    print('  %-30s %s' % (key + ':', val))
            count += 1
        if count == 0:
            print('  (no results)')
        print('')

    def sysinfo(self):
        self._print_query(
            'Operating System',
            'SELECT Caption, Version, BuildNumber, OSArchitecture, '
            'CSName, RegisteredUser, LastBootUpTime, InstallDate, '
            'TotalVisibleMemorySize, FreePhysicalMemory '
            'FROM Win32_OperatingSystem',
            ['Caption', 'Version', 'BuildNumber', 'OSArchitecture',
             'CSName', 'RegisteredUser', 'LastBootUpTime', 'InstallDate',
             'TotalVisibleMemorySize', 'FreePhysicalMemory'])
        self._print_query(
            'Computer System',
            'SELECT Name, Domain, DomainRole, Manufacturer, Model, '
            'NumberOfProcessors, TotalPhysicalMemory, UserName '
            'FROM Win32_ComputerSystem',
            ['Name', 'Domain', 'DomainRole', 'Manufacturer', 'Model',
             'NumberOfProcessors', 'TotalPhysicalMemory', 'UserName'])

    def users(self):
        self._print_query(
            'Local User Accounts',
            'SELECT Name, FullName, Description, Disabled, Lockout, '
            'PasswordRequired, SID FROM Win32_UserAccount',
            ['Name', 'FullName', 'Description', 'Disabled', 'Lockout',
             'PasswordRequired', 'SID'])

    def groups(self):
        self._print_query(
            'Local Groups',
            'SELECT Name, Description, SID FROM Win32_Group',
            ['Name', 'Description', 'SID'])

    def shares(self):
        self._print_query(
            'Network Shares',
            'SELECT Name, Path, Description, Type FROM Win32_Share',
            ['Name', 'Path', 'Description', 'Type'])

    def disks(self):
        self._print_query(
            'Logical Disks',
            'SELECT DeviceID, VolumeName, FileSystem, Size, FreeSpace, '
            'DriveType FROM Win32_LogicalDisk',
            ['DeviceID', 'VolumeName', 'FileSystem', 'Size', 'FreeSpace',
             'DriveType'])

    def network(self):
        self._print_query(
            'Network Adapters (IP Enabled)',
            'SELECT Description, IPAddress, IPSubnet, DefaultIPGateway, '
            'DNSServerSearchOrder, MACAddress, DHCPEnabled '
            'FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True',
            ['Description', 'MACAddress', 'IPAddress', 'IPSubnet',
             'DefaultIPGateway', 'DNSServerSearchOrder', 'DHCPEnabled'])


class WMIMultiTool:
    def __init__(self, username, password, domain, options):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__options = options
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = options.aesKey
        self.__doKerberos = options.k
        self.__kdcHost = options.dc_ip
        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')

    def run(self, remoteName, remoteHost):
        if self.__options.action == 'reg':
            namespace = '//./root/default'
        else:
            namespace = '//./root/cimv2'

        conn = WMIConnection(remoteHost, self.__username, self.__password,
                             self.__domain, self.__lmhash, self.__nthash,
                             self.__aesKey, self.__doKerberos, self.__kdcHost)
        dcom, iWbemServices = conn.connect(namespace)
        try:
            if self.__options.action == 'reg':
                self._dispatch_reg(iWbemServices)
            elif self.__options.action == 'service':
                self._dispatch_service(iWbemServices)
            elif self.__options.action == 'process':
                self._dispatch_process(iWbemServices)
            elif self.__options.action == 'enum':
                self._dispatch_enum(iWbemServices)
        finally:
            iWbemServices.RemRelease()
            dcom.disconnect()

    def _dispatch_reg(self, iWbemServices):
        opts = self.__options
        if not opts.reg_action:
            logging.error('No registry action specified. Use -h for help.')
            return

        ops = RegOps(iWbemServices)
        hive, subkey = RegOps.parse_keyname(opts.keyName)

        if opts.reg_action == 'query':
            ops.query(hive, subkey, opts.valuename)
        elif opts.reg_action == 'add':
            ops.add(hive, subkey, opts.valuename, opts.valuetype, opts.valuedata)
        elif opts.reg_action == 'delete':
            ops.delete(hive, subkey, opts.valuename)
        elif opts.reg_action == 'createkey':
            ops.createkey(hive, subkey)

    def _dispatch_service(self, iWbemServices):
        opts = self.__options
        if not opts.service_action:
            logging.error('No service action specified. Use -h for help.')
            return

        ops = ServiceOps(iWbemServices)

        if opts.service_action == 'list':
            ops.list(getattr(opts, 'svc_filter', None))
        elif opts.service_action == 'start':
            ops.start(opts.name)
        elif opts.service_action == 'stop':
            ops.stop(opts.name)
        elif opts.service_action == 'status':
            ops.status(opts.name)

    def _dispatch_process(self, iWbemServices):
        opts = self.__options
        if not opts.process_action:
            logging.error('No process action specified. Use -h for help.')
            return

        ops = ProcessOps(iWbemServices)

        if opts.process_action == 'list':
            ops.list(getattr(opts, 'name', None))
        elif opts.process_action == 'kill':
            ops.kill(opts.pid)

    def _dispatch_enum(self, iWbemServices):
        opts = self.__options
        if not opts.enum_action:
            logging.error('No enum action specified. Use -h for help.')
            return

        ops = EnumOps(iWbemServices)

        if opts.enum_action == 'sysinfo':
            ops.sysinfo()
        elif opts.enum_action == 'users':
            ops.users()
        elif opts.enum_action == 'groups':
            ops.groups()
        elif opts.enum_action == 'shares':
            ops.shares()
        elif opts.enum_action == 'disks':
            ops.disks()
        elif opts.enum_action == 'network':
            ops.network()


if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser(
        add_help=True,
        description='WMI multitool for registry, service, process, and enumeration '
                    'operations via DCOM. No processes are spawned on the target.')

    parser.add_argument('target', action='store',
                        help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-ts', action='store_true',
                        help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true',
                        help='Turn DEBUG output ON')
    parser.add_argument('-com-version', action='store',
                        metavar='MAJOR_VERSION:MINOR_VERSION',
                        help='DCOM version, format is MAJOR_VERSION:MINOR_VERSION e.g. 5.7')

    subparsers = parser.add_subparsers(help='modules', dest='action')

    # --- reg module ---
    reg_parser = subparsers.add_parser('reg',
        help='Registry operations via WMI StdRegProv (no subprocess)')
    reg_subparsers = reg_parser.add_subparsers(help='registry actions', dest='reg_action')

    reg_query = reg_subparsers.add_parser('query',
        help='Query registry keys and values')
    reg_query.add_argument('-keyName', action='store', required=True,
        help='Registry key path (e.g. HKLM\\SOFTWARE\\Microsoft)')
    reg_query.add_argument('-v', dest='valuename', action='store',
        help='Value name to query. If omitted, enumerates all subkeys and values')

    reg_add = reg_subparsers.add_parser('add',
        help='Add or modify a registry value')
    reg_add.add_argument('-keyName', action='store', required=True,
        help='Registry key path')
    reg_add.add_argument('-v', dest='valuename', action='store', required=True,
        help='Value name to set')
    reg_add.add_argument('-vt', dest='valuetype', action='store', required=True,
        help='Value type (REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_QWORD, REG_MULTI_SZ, REG_BINARY)')
    reg_add.add_argument('-vd', dest='valuedata', action='append', required=True,
        help='Value data (repeat for REG_MULTI_SZ)')

    reg_delete = reg_subparsers.add_parser('delete',
        help='Delete a registry key or value')
    reg_delete.add_argument('-keyName', action='store', required=True,
        help='Registry key path')
    reg_delete.add_argument('-v', dest='valuename', action='store',
        help='Value name to delete. If omitted, deletes the key itself')

    reg_createkey = reg_subparsers.add_parser('createkey',
        help='Create a registry key')
    reg_createkey.add_argument('-keyName', action='store', required=True,
        help='Registry key path to create')

    # --- service module ---
    service_parser = subparsers.add_parser('service',
        help='Service operations via WMI Win32_Service')
    service_subparsers = service_parser.add_subparsers(help='service actions',
                                                        dest='service_action')

    svc_list = service_subparsers.add_parser('list',
        help='List all services')
    svc_list.add_argument('-filter', dest='svc_filter', action='store',
        help='Filter by service name (substring match)')

    svc_start = service_subparsers.add_parser('start',
        help='Start a service')
    svc_start.add_argument('-name', action='store', required=True,
        help='Service name')

    svc_stop = service_subparsers.add_parser('stop',
        help='Stop a service')
    svc_stop.add_argument('-name', action='store', required=True,
        help='Service name')

    svc_status = service_subparsers.add_parser('status',
        help='Show detailed service status')
    svc_status.add_argument('-name', action='store', required=True,
        help='Service name')

    # --- process module ---
    process_parser = subparsers.add_parser('process',
        help='Process operations via WMI Win32_Process')
    process_subparsers = process_parser.add_subparsers(help='process actions',
                                                        dest='process_action')

    proc_list = process_subparsers.add_parser('list',
        help='List running processes')
    proc_list.add_argument('-name', action='store',
        help='Filter by process name')

    proc_kill = process_subparsers.add_parser('kill',
        help='Terminate a process by PID')
    proc_kill.add_argument('-pid', action='store', type=int, required=True,
        help='Process ID to terminate')

    # --- enum module ---
    enum_parser = subparsers.add_parser('enum',
        help='System enumeration via WMI')
    enum_subparsers = enum_parser.add_subparsers(help='enumeration targets',
                                                  dest='enum_action')

    enum_subparsers.add_parser('sysinfo',
        help='OS and computer system information')
    enum_subparsers.add_parser('users',
        help='Local user accounts')
    enum_subparsers.add_parser('groups',
        help='Local groups')
    enum_subparsers.add_parser('shares',
        help='Network shares')
    enum_subparsers.add_parser('disks',
        help='Logical disks')
    enum_subparsers.add_parser('network',
        help='Network adapter configurations')

    # --- authentication ---
    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action='store', metavar='LMHASH:NTHASH',
                       help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action='store_true',
                       help='Don\'t ask for password (useful for -k)')
    group.add_argument('-k', action='store_true',
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on target parameters. If valid credentials '
                            'cannot be found, it will use the ones specified in the command line')
    group.add_argument('-aesKey', action='store', metavar='hex key',
                       help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    group.add_argument('-keytab', action='store',
                       help='Read keys for SPN from keytab file')

    # --- connection ---
    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store', metavar='ip address',
                       help='IP Address of the domain controller. If omitted it will use the '
                            'domain part (FQDN) specified in the target parameter')
    group.add_argument('-target-ip', action='store', metavar='ip address',
                       help='IP Address of the target machine. If omitted it will use whatever '
                            'was specified as target. This is useful when target is the NetBIOS '
                            'name and you cannot resolve it')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    logger.init(options.ts, options.debug)

    if options.com_version is not None:
        try:
            major_version, minor_version = options.com_version.split('.')
            COMVERSION.set_default_version(int(major_version), int(minor_version))
        except Exception:
            logging.error('Wrong COMVERSION format, use dot separated integers e.g. "5.7"')
            sys.exit(1)

    if options.action is None:
        parser.print_help()
        sys.exit(1)

    domain, username, password, address = parse_target(options.target)

    if options.target_ip is None:
        options.target_ip = address

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None \
            and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass('Password:')

    if options.aesKey is not None:
        options.k = True

    if options.keytab is not None:
        Keytab.loadKeysFromKeytab(options.keytab, username, domain, options)
        options.k = True

    try:
        tool = WMIMultiTool(username, password, domain, options)
        tool.run(address, options.target_ip)
    except KeyboardInterrupt:
        pass
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))
        sys.exit(1)

    sys.exit(0)
