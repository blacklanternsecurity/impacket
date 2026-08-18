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
#   WMI multitool for remote Windows operations via DCOM.
#   No processes are spawned on the target.
#
#   Modules:
#     reg       - Registry operations via StdRegProv
#     service   - Service management via Win32_Service
#     process   - Process listing/termination via Win32_Process
#     enum      - System enumeration (sysinfo, users, groups, shares,
#                 disks, network, startup, hotfix, sessions, env, bios)
#     defender  - Windows Defender management (exclusions, status)
#     av        - Security product detection (AV, firewall)
#     eventlog  - Event log listing, reading, and clearing
#     net       - Network connections and DNS cache (netstat equiv)
#     rdp       - Remote Desktop enable/disable/status
#     file      - File search, copy, delete via CIM_DataFile
#     share     - Network share creation and deletion
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
from impacket.dcerpc.v5.dtypes import NULL, OWNER_SECURITY_INFORMATION, DACL_SECURITY_INFORMATION
from impacket.dcerpc.v5 import transport, rrp
from impacket.smbconnection import SMBConnection
from impacket.krb5.keytab import Keytab
import struct

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

NAMESPACE_MAP = {
    'reg':      '//./root/default',
    'defender': '//./root/Microsoft/Windows/Defender',
    'av':       '//./root/SecurityCenter2',
    'net':      '//./root/StandardCimv2',
    'rdp':      '//./root/cimv2/TerminalServices',
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


def _print_query(iWbemServices, title, query, fields=None):
    print('[*] %s' % title)
    count = 0
    for props in _iter_query(iWbemServices, query):
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


# ---------------------------------------------------------------------------
# Registry operations (StdRegProv, root/default)
# ---------------------------------------------------------------------------
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

    @staticmethod
    def takeown(address, username, password, domain, lmhash, nthash,
                aesKey, doKerberos, kdcHost, keypath):
        admin_sid = b'\x01\x02\x00\x00\x00\x00\x00\x05\x20\x00\x00\x00\x20\x02\x00\x00'
        everyone_sid = b'\x01\x01\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00'
        system_sid = b'\x01\x01\x00\x00\x00\x00\x00\x05\x12\x00\x00\x00'

        smb = SMBConnection(address, address)
        if doKerberos:
            smb.kerberosLogin(username, password, domain, lmhash, nthash,
                              aesKey, kdcHost=kdcHost)
        else:
            smb.login(username, password, domain, lmhash, nthash)

        rpctransport = transport.SMBTransport(address, filename=r'\winreg',
                                              smb_connection=smb)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(rrp.MSRPC_UUID_RRP)

        ans = rrp.hOpenLocalMachine(dce)
        hklm = ans['phKey']

        try:
            print('[*] Opening key with WRITE_OWNER: %s' % keypath)
            ans = rrp.hBaseRegOpenKey(dce, hklm, keypath, samDesired=0x80000)
            hKey = ans['phkResult']

            print('[*] Taking ownership (setting owner to Administrators)...')
            owner_sd = struct.pack('<BBHIIII', 1, 0, 0x8000, 20, 0, 0, 0) + admin_sid
            request = rrp.BaseRegSetKeySecurity()
            request['hKey'] = hKey
            request['SecurityInformation'] = OWNER_SECURITY_INFORMATION
            request['pRpcSecurityDescriptor']['lpSecurityDescriptor'] = list(owner_sd)
            request['pRpcSecurityDescriptor']['cbInSecurityDescriptor'] = len(owner_sd)
            request['pRpcSecurityDescriptor']['cbOutSecurityDescriptor'] = len(owner_sd)
            dce.request(request)
            print('[+] Ownership taken')

            rrp.hBaseRegCloseKey(dce, hKey)
            print('[*] Reopening with WRITE_DAC...')
            ans = rrp.hBaseRegOpenKey(dce, hklm, keypath, samDesired=0x40000)
            hKey = ans['phkResult']

            print('[*] Setting DACL (Administrators + SYSTEM: full, Everyone: read)...')
            def _ace(mask, sid):
                body = struct.pack('<I', mask) + sid
                return struct.pack('<BBH', 0, 0x02, 4 + len(body)) + body

            aces = _ace(0xF003F, admin_sid) + _ace(0xF003F, system_sid) + _ace(0x20019, everyone_sid)
            acl = struct.pack('<BBHHH', 2, 0, 8 + len(aces), 3, 0) + aces
            dacl_sd = struct.pack('<BBHIIII', 1, 0, 0x8004, 0, 0, 0, 20) + acl

            request = rrp.BaseRegSetKeySecurity()
            request['hKey'] = hKey
            request['SecurityInformation'] = DACL_SECURITY_INFORMATION
            request['pRpcSecurityDescriptor']['lpSecurityDescriptor'] = list(dacl_sd)
            request['pRpcSecurityDescriptor']['cbInSecurityDescriptor'] = len(dacl_sd)
            request['pRpcSecurityDescriptor']['cbOutSecurityDescriptor'] = len(dacl_sd)
            dce.request(request)
            print('[+] DACL set — key is now writable')

            rrp.hBaseRegCloseKey(dce, hKey)
        finally:
            rrp.hBaseRegCloseKey(dce, hklm)
            dce.disconnect()
            smb.close()


# ---------------------------------------------------------------------------
# Service operations (Win32_Service, root/cimv2)
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Process operations (Win32_Process, root/cimv2)
# ---------------------------------------------------------------------------
class ProcessOps:
    def __init__(self, iWbemServices):
        self.__iWbemServices = iWbemServices

    def list(self, name_filter=None):
        query = 'SELECT Handle, ProcessId, Name, SessionId, CommandLine FROM Win32_Process'
        if name_filter:
            query += " WHERE Name LIKE '%%%s%%'" % name_filter

        print('%-8s %-25s %-22s %-10s %s' % ('PID', 'Name', 'Owner', 'SessionId', 'CommandLine'))
        print('%-8s %-25s %-22s %-10s %s' % ('---', '----', '-----', '---------', '-----------'))
        iEnum = self.__iWbemServices.ExecQuery(query)
        try:
            while True:
                try:
                    item = iEnum.Next(0xffffffff, 1)[0]
                    props = item.getProperties()
                    pid = props['ProcessId']['value']
                    owner = ''
                    try:
                        result = item.GetOwner()
                        user = getattr(result, 'User', None)
                        domain = getattr(result, 'Domain', None)
                        if user:
                            owner = '%s\\%s' % (domain, user) if domain else user
                    except Exception:
                        pass
                    print('%-8s %-25s %-22s %-10s %s' % (
                        pid,
                        props['Name']['value'] or '',
                        owner,
                        props['SessionId']['value'],
                        props['CommandLine']['value'] or '',
                    ))
                except Exception as e:
                    if str(e).find('S_FALSE') < 0:
                        raise
                    break
        finally:
            iEnum.RemRelease()

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


# ---------------------------------------------------------------------------
# Enumeration operations (various cimv2 classes)
# ---------------------------------------------------------------------------
class EnumOps:
    def __init__(self, iWbemServices):
        self.__iWbemServices = iWbemServices

    def sysinfo(self):
        _print_query(self.__iWbemServices,
            'Operating System',
            'SELECT Caption, Version, BuildNumber, OSArchitecture, '
            'CSName, RegisteredUser, LastBootUpTime, InstallDate, '
            'TotalVisibleMemorySize, FreePhysicalMemory '
            'FROM Win32_OperatingSystem',
            ['Caption', 'Version', 'BuildNumber', 'OSArchitecture',
             'CSName', 'RegisteredUser', 'LastBootUpTime', 'InstallDate',
             'TotalVisibleMemorySize', 'FreePhysicalMemory'])
        _print_query(self.__iWbemServices,
            'Computer System',
            'SELECT Name, Domain, DomainRole, Manufacturer, Model, '
            'NumberOfProcessors, TotalPhysicalMemory, UserName '
            'FROM Win32_ComputerSystem',
            ['Name', 'Domain', 'DomainRole', 'Manufacturer', 'Model',
             'NumberOfProcessors', 'TotalPhysicalMemory', 'UserName'])

    def users(self):
        _print_query(self.__iWbemServices,
            'Local User Accounts',
            'SELECT Name, FullName, Description, Disabled, Lockout, '
            'PasswordRequired, SID FROM Win32_UserAccount',
            ['Name', 'FullName', 'Description', 'Disabled', 'Lockout',
             'PasswordRequired', 'SID'])

    def groups(self):
        _print_query(self.__iWbemServices,
            'Local Groups',
            'SELECT Name, Description, SID FROM Win32_Group',
            ['Name', 'Description', 'SID'])

    def shares(self):
        _print_query(self.__iWbemServices,
            'Network Shares',
            'SELECT Name, Path, Description, Type FROM Win32_Share',
            ['Name', 'Path', 'Description', 'Type'])

    def disks(self):
        _print_query(self.__iWbemServices,
            'Logical Disks',
            'SELECT DeviceID, VolumeName, FileSystem, Size, FreeSpace, '
            'DriveType FROM Win32_LogicalDisk',
            ['DeviceID', 'VolumeName', 'FileSystem', 'Size', 'FreeSpace',
             'DriveType'])

    def network(self):
        _print_query(self.__iWbemServices,
            'Network Adapters (IP Enabled)',
            'SELECT Description, IPAddress, IPSubnet, DefaultIPGateway, '
            'DNSServerSearchOrder, MACAddress, DHCPEnabled '
            'FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=True',
            ['Description', 'MACAddress', 'IPAddress', 'IPSubnet',
             'DefaultIPGateway', 'DNSServerSearchOrder', 'DHCPEnabled'])

    def startup(self):
        _print_query(self.__iWbemServices,
            'Startup Commands',
            'SELECT Name, Command, User, Location FROM Win32_StartupCommand',
            ['Name', 'Command', 'User', 'Location'])

    def hotfix(self):
        _print_query(self.__iWbemServices,
            'Installed Hotfixes',
            'SELECT HotFixID, Description, InstalledOn, InstalledBy '
            'FROM Win32_QuickFixEngineering',
            ['HotFixID', 'Description', 'InstalledOn', 'InstalledBy'])

    def sessions(self):
        _print_query(self.__iWbemServices,
            'Logon Sessions',
            'SELECT LogonId, LogonType, StartTime, AuthenticationPackage, '
            'Status FROM Win32_LogonSession',
            ['LogonId', 'LogonType', 'StartTime', 'AuthenticationPackage',
             'Status'])

    def env(self):
        _print_query(self.__iWbemServices,
            'Environment Variables',
            'SELECT Name, VariableValue, UserName, SystemVariable '
            'FROM Win32_Environment',
            ['Name', 'VariableValue', 'UserName', 'SystemVariable'])

    def bios(self):
        _print_query(self.__iWbemServices,
            'BIOS Information',
            'SELECT Manufacturer, Name, SerialNumber, SMBIOSBIOSVersion, '
            'Version FROM Win32_BIOS',
            ['Manufacturer', 'Name', 'SerialNumber', 'SMBIOSBIOSVersion',
             'Version'])
        _print_query(self.__iWbemServices,
            'Computer System Product (VM Detection)',
            'SELECT Name, Vendor, Version, UUID, IdentifyingNumber '
            'FROM Win32_ComputerSystemProduct',
            ['Name', 'Vendor', 'Version', 'UUID', 'IdentifyingNumber'])


# ---------------------------------------------------------------------------
# Windows Defender operations (MSFT_Mp*, root/Microsoft/Windows/Defender)
# ---------------------------------------------------------------------------
class DefenderOps:
    def __init__(self, iWbemServices):
        self.__iWbemServices = iWbemServices

    def status(self):
        _print_query(self.__iWbemServices,
            'Windows Defender Status',
            'SELECT AMRunningMode, AMServiceEnabled, AntispywareEnabled, '
            'AntivirusEnabled, RealTimeProtectionEnabled, '
            'AntivirusSignatureLastUpdated, QuickScanEndTime, '
            'FullScanEndTime, ComputerState '
            'FROM MSFT_MpComputerStatus',
            ['AMRunningMode', 'AMServiceEnabled', 'AntispywareEnabled',
             'AntivirusEnabled', 'RealTimeProtectionEnabled',
             'AntivirusSignatureLastUpdated', 'QuickScanEndTime',
             'FullScanEndTime', 'ComputerState'])

    def exclusions(self):
        print('[*] Defender Exclusions')
        for props in _iter_query(self.__iWbemServices,
                                 'SELECT ExclusionPath, ExclusionProcess, '
                                 'ExclusionExtension FROM MSFT_MpPreference'):
            for field, label in [('ExclusionPath', 'Path'),
                                 ('ExclusionProcess', 'Process'),
                                 ('ExclusionExtension', 'Extension')]:
                val = props.get(field, {}).get('value')
                if val:
                    items = val if isinstance(val, list) else [val]
                    for item in items:
                        print('  %-12s %s' % (label + ':', item))
            return
        print('  (no exclusions or access denied)')

    def add_exclusion(self, exc_type, value):
        pref, _ = self.__iWbemServices.GetObject('MSFT_MpPreference')
        try:
            if exc_type == 'path':
                result = pref.Add(ExclusionPath=[value])
            elif exc_type == 'process':
                result = pref.Add(ExclusionProcess=[value])
            elif exc_type == 'extension':
                result = pref.Add(ExclusionExtension=[value])
            else:
                print('[-] Unknown exclusion type: %s' % exc_type)
                return False

            ret = result.ReturnValue
            if ret == 0:
                print('[+] Added %s exclusion: %s' % (exc_type, value))
                return True
            else:
                print('[-] Add exclusion returned: %d' % ret)
                return False
        except Exception as e:
            print('[-] Add exclusion failed: %s' % e)
            return False

    def remove_exclusion(self, exc_type, value):
        pref, _ = self.__iWbemServices.GetObject('MSFT_MpPreference')
        try:
            if exc_type == 'path':
                result = pref.Remove(ExclusionPath=[value])
            elif exc_type == 'process':
                result = pref.Remove(ExclusionProcess=[value])
            elif exc_type == 'extension':
                result = pref.Remove(ExclusionExtension=[value])
            else:
                print('[-] Unknown exclusion type: %s' % exc_type)
                return False

            ret = result.ReturnValue
            if ret == 0:
                print('[+] Removed %s exclusion: %s' % (exc_type, value))
                return True
            else:
                print('[-] Remove exclusion returned: %d' % ret)
                return False
        except Exception as e:
            print('[-] Remove exclusion failed: %s' % e)
            return False


# ---------------------------------------------------------------------------
# AV/Security product detection (SecurityCenter2)
# ---------------------------------------------------------------------------
class AvOps:
    def __init__(self, iWbemServices):
        self.__iWbemServices = iWbemServices

    @staticmethod
    def _decode_product_state(state):
        hex_state = '%06x' % state
        scanner_on = hex_state[2:4] == '10'
        defs_current = hex_state[4:6] == '00'
        return ('Enabled' if scanner_on else 'Disabled',
                'Up to date' if defs_current else 'Outdated')

    def list(self):
        for wmi_class, label in [('AntiVirusProduct', 'Antivirus'),
                                 ('AntiSpywareProduct', 'Antispyware'),
                                 ('FirewallProduct', 'Firewall')]:
            print('[*] %s Products' % label)
            count = 0
            try:
                for props in _iter_query(self.__iWbemServices,
                                         'SELECT displayName, productState '
                                         'FROM %s' % wmi_class):
                    name = props.get('displayName', {}).get('value', '(unknown)')
                    state = props.get('productState', {}).get('value', 0)
                    scanner, defs = self._decode_product_state(state)
                    print('  %-30s Scanner: %-10s Definitions: %s' % (
                        name, scanner, defs))
                    count += 1
            except Exception as e:
                print('  [-] Query failed: %s' % e)
            if count == 0:
                print('  (none found)')
            print('')


# ---------------------------------------------------------------------------
# Event log operations (Win32_NTEventLogFile/Win32_NTLogEvent, root/cimv2)
# ---------------------------------------------------------------------------
class EventLogOps:
    def __init__(self, iWbemServices):
        self.__iWbemServices = iWbemServices

    def list(self):
        print('%-25s %-12s %-12s %s' % ('LogFile', 'Records', 'Size (KB)', 'MaxSize (KB)'))
        print('%-25s %-12s %-12s %s' % ('-------', '-------', '---------', '------------'))
        for props in _iter_query(self.__iWbemServices,
                                 'SELECT LogfileName, NumberOfRecords, FileSize, '
                                 'MaxFileSize FROM Win32_NTEventLogFile'):
            size_kb = (props['FileSize']['value'] or 0) // 1024
            max_kb = (props['MaxFileSize']['value'] or 0) // 1024
            print('%-25s %-12s %-12s %s' % (
                props['LogfileName']['value'] or '',
                props['NumberOfRecords']['value'] or 0,
                size_kb,
                max_kb))

    def clear(self, logname):
        path = "Win32_NTEventLogFile.LogfileName='%s'" % logname
        try:
            log_obj, _ = self.__iWbemServices.GetObject(path)
            result = log_obj.ClearEventLog()
            ret = result.ReturnValue
            if ret == 0:
                print('[+] Cleared event log: %s' % logname)
            else:
                print('[-] ClearEventLog returned: %d' % ret)
        except Exception as e:
            print('[-] Clear failed: %s' % e)

    def read(self, logfile, event_id=None, count=50):
        query = "SELECT EventCode, Type, TimeGenerated, SourceName, Message " \
                "FROM Win32_NTLogEvent WHERE Logfile='%s'" % logfile
        if event_id is not None:
            query += ' AND EventCode=%d' % event_id

        print('%-8s %-12s %-25s %-25s %s' % ('EventID', 'Type', 'TimeGenerated', 'Source', 'Message'))
        print('%-8s %-12s %-25s %-25s %s' % ('-------', '----', '-------------', '------', '-------'))
        n = 0
        for props in _iter_query(self.__iWbemServices, query):
            if n >= count:
                print('[*] (showing first %d events, use -count for more)' % count)
                break
            msg = props.get('Message', {}).get('value', '') or ''
            msg = msg.replace('\r\n', ' ').replace('\n', ' ')[:120]
            print('%-8s %-12s %-25s %-25s %s' % (
                props.get('EventCode', {}).get('value', ''),
                props.get('Type', {}).get('value', ''),
                props.get('TimeGenerated', {}).get('value', ''),
                props.get('SourceName', {}).get('value', ''),
                msg))
            n += 1


# ---------------------------------------------------------------------------
# Network connections and DNS cache (StandardCimv2)
# ---------------------------------------------------------------------------
class NetOps:
    def __init__(self, iWbemServices):
        self.__iWbemServices = iWbemServices

    def tcp(self):
        TCP_STATES = {
            1: 'Closed', 2: 'Listen', 3: 'SynSent', 4: 'SynReceived',
            5: 'Established', 6: 'FinWait1', 7: 'FinWait2', 8: 'CloseWait',
            9: 'Closing', 10: 'LastAck', 11: 'TimeWait', 12: 'DeleteTCB',
        }
        print('%-6s %-25s %-25s %-15s %s' % ('PID', 'Local', 'Remote', 'State', 'Name'))
        print('%-6s %-25s %-25s %-15s %s' % ('---', '-----', '------', '-----', '----'))
        for props in _iter_query(self.__iWbemServices,
                                 'SELECT LocalAddress, LocalPort, RemoteAddress, '
                                 'RemotePort, State, OwningProcess '
                                 'FROM MSFT_NetTCPConnection'):
            local = '%s:%s' % (props['LocalAddress']['value'],
                               props['LocalPort']['value'])
            remote = '%s:%s' % (props['RemoteAddress']['value'],
                                props['RemotePort']['value'])
            state_num = props['State']['value']
            state = TCP_STATES.get(state_num, str(state_num))
            pid = props['OwningProcess']['value']
            print('%-6s %-25s %-25s %-15s' % (pid, local, remote, state))

    def udp(self):
        print('%-6s %-25s' % ('PID', 'Local'))
        print('%-6s %-25s' % ('---', '-----'))
        for props in _iter_query(self.__iWbemServices,
                                 'SELECT LocalAddress, LocalPort, OwningProcess '
                                 'FROM MSFT_NetUDPEndpoint'):
            local = '%s:%s' % (props['LocalAddress']['value'],
                               props['LocalPort']['value'])
            pid = props['OwningProcess']['value']
            print('%-6s %-25s' % (pid, local))

    def dns(self):
        print('%-50s %-8s %s' % ('Name', 'Type', 'Data'))
        print('%-50s %-8s %s' % ('----', '----', '----'))
        DNS_TYPES = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR',
                     15: 'MX', 28: 'AAAA', 33: 'SRV', 255: 'ANY'}
        for props in _iter_query(self.__iWbemServices,
                                 'SELECT Name, Type, Data FROM MSFT_DNSClientCache'):
            name = props.get('Name', {}).get('value', '')
            rtype_num = props.get('Type', {}).get('value', 0)
            rtype = DNS_TYPES.get(rtype_num, str(rtype_num))
            data = props.get('Data', {}).get('value', '')
            print('%-50s %-8s %s' % (name, rtype, data))


# ---------------------------------------------------------------------------
# RDP operations (Win32_TerminalServiceSetting, root/cimv2/TerminalServices)
# ---------------------------------------------------------------------------
class RdpOps:
    def __init__(self, iWbemServices):
        self.__iWbemServices = iWbemServices

    def status(self):
        for props in _iter_query(self.__iWbemServices,
                                 'SELECT AllowTSConnections, SingleSession, '
                                 'UserAuthenticationRequired '
                                 'FROM Win32_TerminalServiceSetting'):
            enabled = props['AllowTSConnections']['value']
            nla = props.get('UserAuthenticationRequired', {}).get('value', None)
            print('[*] RDP Status')
            print('  AllowTSConnections:         %s (%s)' % (
                enabled, 'Enabled' if enabled else 'Disabled'))
            if nla is not None:
                print('  UserAuthenticationRequired: %s (NLA %s)' % (
                    nla, 'Required' if nla else 'Not required'))
            return
        print('[-] Could not query RDP status')

    def _get_ts_object(self):
        iEnum = self.__iWbemServices.ExecQuery(
            'SELECT * FROM Win32_TerminalServiceSetting')
        try:
            item = iEnum.Next(0xffffffff, 1)[0]
            return item
        except Exception as e:
            if str(e).find('S_FALSE') < 0:
                raise
        finally:
            iEnum.RemRelease()
        return None

    def enable(self):
        ts = self._get_ts_object()
        if ts is None:
            print('[-] Could not find TerminalServiceSetting')
            return
        try:
            result = ts.SetAllowTSConnections(1, 1)
            ret = result.ReturnValue
            if ret == 0:
                print('[+] RDP enabled (with firewall exception)')
            else:
                print('[-] SetAllowTSConnections returned: %d' % ret)
        except Exception as e:
            print('[-] Enable RDP failed: %s' % e)

    def disable(self):
        ts = self._get_ts_object()
        if ts is None:
            print('[-] Could not find TerminalServiceSetting')
            return
        try:
            result = ts.SetAllowTSConnections(0, 0)
            ret = result.ReturnValue
            if ret == 0:
                print('[+] RDP disabled')
            else:
                print('[-] SetAllowTSConnections returned: %d' % ret)
        except Exception as e:
            print('[-] Disable RDP failed: %s' % e)


# ---------------------------------------------------------------------------
# File operations (CIM_DataFile / Win32_Directory, root/cimv2)
# ---------------------------------------------------------------------------
class FileOps:
    def __init__(self, iWbemServices):
        self.__iWbemServices = iWbemServices

    def search(self, drive, path, extension=None, name=None):
        path = path.replace('\\', '\\\\')
        query = "SELECT Name, FileSize, LastModified FROM CIM_DataFile " \
                "WHERE Drive='%s' AND Path='%s'" % (drive, path)
        if extension:
            query += " AND Extension='%s'" % extension
        if name:
            query += " AND FileName LIKE '%s'" % name.replace('*', '%')

        print('%-60s %-12s %s' % ('Name', 'Size', 'LastModified'))
        print('%-60s %-12s %s' % ('----', '----', '------------'))
        for props in _iter_query(self.__iWbemServices, query):
            print('%-60s %-12s %s' % (
                props['Name']['value'] or '',
                props['FileSize']['value'] or 0,
                props['LastModified']['value'] or ''))

    def ls(self, path):
        drive = path[:2]
        dir_path = path[2:]
        if not dir_path.endswith('\\'):
            dir_path += '\\'
        escaped = dir_path.replace('\\', '\\\\')

        print('[*] Directory listing: %s' % path)
        print('')

        print('  [Directories]')
        count = 0
        for props in _iter_query(self.__iWbemServices,
                                 "SELECT Name FROM Win32_Directory "
                                 "WHERE Drive='%s' AND Path='%s'" % (drive, escaped)):
            print('    %s' % props['Name']['value'])
            count += 1
        if count == 0:
            print('    (none)')

        print('')
        print('  [Files]')
        count = 0
        for props in _iter_query(self.__iWbemServices,
                                 "SELECT Name, FileSize FROM CIM_DataFile "
                                 "WHERE Drive='%s' AND Path='%s'" % (drive, escaped)):
            size = props['FileSize']['value'] or 0
            print('    %-60s %s bytes' % (props['Name']['value'], size))
            count += 1
        if count == 0:
            print('    (none)')
        print('')

    def copy(self, source, dest):
        source_escaped = source.replace('\\', '\\\\')
        path = "CIM_DataFile.Name='%s'" % source_escaped
        try:
            file_obj, _ = self.__iWbemServices.GetObject(path)
            result = file_obj.Copy(dest)
            ret = result.ReturnValue
            if ret == 0:
                print('[+] Copied %s -> %s' % (source, dest))
            else:
                print('[-] Copy returned: %d' % ret)
        except Exception as e:
            print('[-] Copy failed: %s' % e)

    def delete(self, filepath):
        filepath_escaped = filepath.replace('\\', '\\\\')
        path = "CIM_DataFile.Name='%s'" % filepath_escaped
        try:
            file_obj, _ = self.__iWbemServices.GetObject(path)
            result = file_obj.Delete()
            ret = result.ReturnValue
            if ret == 0:
                print('[+] Deleted: %s' % filepath)
            else:
                print('[-] Delete returned: %d' % ret)
        except Exception as e:
            print('[-] Delete failed: %s' % e)


# ---------------------------------------------------------------------------
# Share operations (Win32_Share, root/cimv2)
# ---------------------------------------------------------------------------
class ShareOps:
    def __init__(self, iWbemServices):
        self.__iWbemServices = iWbemServices

    def create(self, name, path, description=''):
        share_class, _ = self.__iWbemServices.GetObject('Win32_Share')
        try:
            result = share_class.Create(path, name, 0, None, description, None, None)
            ret = result.ReturnValue
            if ret == 0:
                print('[+] Share created: %s -> %s' % (name, path))
            else:
                SHARE_ERRORS = {
                    2: 'Access denied', 8: 'Unknown failure',
                    9: 'Invalid name', 10: 'Invalid level',
                    21: 'Invalid parameter', 22: 'Duplicate share',
                    23: 'Redirected path', 24: 'Unknown device/directory',
                    25: 'Net name not found',
                }
                err = SHARE_ERRORS.get(ret, 'Unknown error')
                print('[-] Create share returned: %d (%s)' % (ret, err))
        except Exception as e:
            print('[-] Create share failed: %s' % e)

    def delete(self, name):
        path = "Win32_Share.Name='%s'" % name
        try:
            share_obj, _ = self.__iWbemServices.GetObject(path)
            result = share_obj.Delete()
            ret = result.ReturnValue
            if ret == 0:
                print('[+] Share deleted: %s' % name)
            else:
                print('[-] Delete share returned: %d' % ret)
        except Exception as e:
            print('[-] Delete share failed: %s' % e)


# ---------------------------------------------------------------------------
# Main dispatcher
# ---------------------------------------------------------------------------
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
        namespace = NAMESPACE_MAP.get(self.__options.action, '//./root/cimv2')

        conn = WMIConnection(remoteHost, self.__username, self.__password,
                             self.__domain, self.__lmhash, self.__nthash,
                             self.__aesKey, self.__doKerberos, self.__kdcHost)
        dcom, iWbemServices = conn.connect(namespace)
        try:
            action = self.__options.action
            if action == 'reg':
                self._dispatch_reg(iWbemServices)
            elif action == 'service':
                self._dispatch_service(iWbemServices)
            elif action == 'process':
                self._dispatch_process(iWbemServices)
            elif action == 'enum':
                self._dispatch_enum(iWbemServices)
            elif action == 'defender':
                self._dispatch_defender(iWbemServices)
            elif action == 'av':
                self._dispatch_av(iWbemServices)
            elif action == 'eventlog':
                self._dispatch_eventlog(iWbemServices)
            elif action == 'net':
                self._dispatch_net(iWbemServices)
            elif action == 'rdp':
                self._dispatch_rdp(iWbemServices)
            elif action == 'file':
                self._dispatch_file(iWbemServices)
            elif action == 'share':
                self._dispatch_share(iWbemServices)
        finally:
            iWbemServices.RemRelease()
            dcom.disconnect()

    def _dispatch_reg(self, iWbemServices):
        opts = self.__options
        if not opts.reg_action:
            logging.error('No registry action specified. Use -h for help.')
            return

        if opts.reg_action == 'takeown':
            _, subkey = RegOps.parse_keyname(opts.keyName)
            RegOps.takeown(self.__options.target_ip, self.__username,
                           self.__password, self.__domain, self.__lmhash,
                           self.__nthash, self.__aesKey, self.__doKerberos,
                           self.__kdcHost, subkey)
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
        method = getattr(ops, opts.enum_action, None)
        if method:
            method()
        else:
            logging.error('Unknown enum action: %s' % opts.enum_action)

    def _dispatch_defender(self, iWbemServices):
        opts = self.__options
        if not opts.defender_action:
            logging.error('No defender action specified. Use -h for help.')
            return

        ops = DefenderOps(iWbemServices)

        if opts.defender_action == 'status':
            ops.status()
        elif opts.defender_action == 'exclusions':
            ops.exclusions()
        elif opts.defender_action == 'add-exclusion':
            ops.add_exclusion(opts.exc_type, opts.value)
        elif opts.defender_action == 'remove-exclusion':
            ops.remove_exclusion(opts.exc_type, opts.value)

    def _dispatch_av(self, iWbemServices):
        opts = self.__options
        if not opts.av_action:
            logging.error('No av action specified. Use -h for help.')
            return

        ops = AvOps(iWbemServices)

        if opts.av_action == 'list':
            ops.list()

    def _dispatch_eventlog(self, iWbemServices):
        opts = self.__options
        if not opts.eventlog_action:
            logging.error('No eventlog action specified. Use -h for help.')
            return

        ops = EventLogOps(iWbemServices)

        if opts.eventlog_action == 'list':
            ops.list()
        elif opts.eventlog_action == 'clear':
            ops.clear(opts.name)
        elif opts.eventlog_action == 'read':
            ops.read(opts.logfile,
                     getattr(opts, 'event_id', None),
                     getattr(opts, 'count', 50))

    def _dispatch_net(self, iWbemServices):
        opts = self.__options
        if not opts.net_action:
            logging.error('No net action specified. Use -h for help.')
            return

        ops = NetOps(iWbemServices)

        if opts.net_action == 'tcp':
            ops.tcp()
        elif opts.net_action == 'udp':
            ops.udp()
        elif opts.net_action == 'dns':
            ops.dns()

    def _dispatch_rdp(self, iWbemServices):
        opts = self.__options
        if not opts.rdp_action:
            logging.error('No rdp action specified. Use -h for help.')
            return

        ops = RdpOps(iWbemServices)

        if opts.rdp_action == 'status':
            ops.status()
        elif opts.rdp_action == 'enable':
            ops.enable()
        elif opts.rdp_action == 'disable':
            ops.disable()

    def _dispatch_file(self, iWbemServices):
        opts = self.__options
        if not opts.file_action:
            logging.error('No file action specified. Use -h for help.')
            return

        ops = FileOps(iWbemServices)

        if opts.file_action == 'search':
            ops.search(opts.drive, opts.path,
                       getattr(opts, 'ext', None),
                       getattr(opts, 'fname', None))
        elif opts.file_action == 'ls':
            ops.ls(opts.path)
        elif opts.file_action == 'copy':
            ops.copy(opts.source, opts.dest)
        elif opts.file_action == 'delete':
            ops.delete(opts.path)

    def _dispatch_share(self, iWbemServices):
        opts = self.__options
        if not opts.share_action:
            logging.error('No share action specified. Use -h for help.')
            return

        ops = ShareOps(iWbemServices)

        if opts.share_action == 'create':
            ops.create(opts.name, opts.path,
                       getattr(opts, 'description', ''))
        elif opts.share_action == 'delete':
            ops.delete(opts.name)


# ---------------------------------------------------------------------------
# Argparse and main
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser(
        add_help=True,
        description='WMI multitool for remote Windows operations via DCOM. '
                    'No processes are spawned on the target.')

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

    # ===================== reg =====================
    reg_parser = subparsers.add_parser('reg',
        help='Registry operations via WMI StdRegProv (no subprocess)')
    reg_sub = reg_parser.add_subparsers(help='registry actions', dest='reg_action')

    p = reg_sub.add_parser('query', help='Query registry keys and values')
    p.add_argument('-keyName', required=True, help='Registry key path')
    p.add_argument('-v', dest='valuename', help='Value name (omit to enumerate all)')

    p = reg_sub.add_parser('add', help='Add or modify a registry value')
    p.add_argument('-keyName', required=True, help='Registry key path')
    p.add_argument('-v', dest='valuename', required=True, help='Value name')
    p.add_argument('-vt', dest='valuetype', required=True,
        help='Type: REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_QWORD, REG_MULTI_SZ, REG_BINARY')
    p.add_argument('-vd', dest='valuedata', action='append', required=True,
        help='Value data (repeat for REG_MULTI_SZ)')

    p = reg_sub.add_parser('delete', help='Delete a registry key or value')
    p.add_argument('-keyName', required=True, help='Registry key path')
    p.add_argument('-v', dest='valuename', help='Value name (omit to delete key)')

    p = reg_sub.add_parser('createkey', help='Create a registry key')
    p.add_argument('-keyName', required=True, help='Registry key path')

    p = reg_sub.add_parser('takeown',
        help='Take ownership of a registry key via Remote Registry (requires RemoteRegistry service)')
    p.add_argument('-keyName', required=True,
        help='Registry key path (e.g. HKLM\\SOFTWARE\\Classes\\CLSID\\{...})')

    # ===================== service =====================
    svc_parser = subparsers.add_parser('service',
        help='Service operations via WMI Win32_Service')
    svc_sub = svc_parser.add_subparsers(help='service actions', dest='service_action')

    p = svc_sub.add_parser('list', help='List services')
    p.add_argument('-filter', dest='svc_filter', help='Filter by name (substring)')

    p = svc_sub.add_parser('start', help='Start a service')
    p.add_argument('-name', required=True, help='Service name')

    p = svc_sub.add_parser('stop', help='Stop a service')
    p.add_argument('-name', required=True, help='Service name')

    p = svc_sub.add_parser('status', help='Show detailed service status')
    p.add_argument('-name', required=True, help='Service name')

    # ===================== process =====================
    proc_parser = subparsers.add_parser('process',
        help='Process operations via WMI Win32_Process')
    proc_sub = proc_parser.add_subparsers(help='process actions', dest='process_action')

    p = proc_sub.add_parser('list', help='List running processes')
    p.add_argument('-name', help='Filter by process name')

    p = proc_sub.add_parser('kill', help='Terminate a process by PID')
    p.add_argument('-pid', type=int, required=True, help='Process ID')

    # ===================== enum =====================
    enum_parser = subparsers.add_parser('enum',
        help='System enumeration via WMI')
    enum_sub = enum_parser.add_subparsers(help='enumeration targets', dest='enum_action')

    enum_sub.add_parser('sysinfo', help='OS and computer system information')
    enum_sub.add_parser('users', help='Local user accounts')
    enum_sub.add_parser('groups', help='Local groups')
    enum_sub.add_parser('shares', help='Network shares')
    enum_sub.add_parser('disks', help='Logical disks')
    enum_sub.add_parser('network', help='Network adapter configurations')
    enum_sub.add_parser('startup', help='Startup commands / autoruns')
    enum_sub.add_parser('hotfix', help='Installed hotfixes and patches')
    enum_sub.add_parser('sessions', help='Logon sessions')
    enum_sub.add_parser('env', help='Environment variables')
    enum_sub.add_parser('bios', help='BIOS and hardware info (VM detection)')

    # ===================== defender =====================
    def_parser = subparsers.add_parser('defender',
        help='Windows Defender management (Win10+/Server2016+)')
    def_sub = def_parser.add_subparsers(help='defender actions', dest='defender_action')

    def_sub.add_parser('status', help='Defender status and RTP state')
    def_sub.add_parser('exclusions', help='List current exclusions')

    p = def_sub.add_parser('add-exclusion', help='Add a Defender exclusion')
    p.add_argument('-type', dest='exc_type', required=True,
        choices=['path', 'process', 'extension'],
        help='Exclusion type')
    p.add_argument('-value', required=True,
        help='Exclusion value (path, process name, or extension)')

    p = def_sub.add_parser('remove-exclusion', help='Remove a Defender exclusion')
    p.add_argument('-type', dest='exc_type', required=True,
        choices=['path', 'process', 'extension'],
        help='Exclusion type')
    p.add_argument('-value', required=True,
        help='Exclusion value to remove')

    # ===================== av =====================
    av_parser = subparsers.add_parser('av',
        help='Security product detection (workstation SKUs only)')
    av_sub = av_parser.add_subparsers(help='av actions', dest='av_action')

    av_sub.add_parser('list', help='List AV, antispyware, and firewall products')

    # ===================== eventlog =====================
    el_parser = subparsers.add_parser('eventlog',
        help='Event log operations via Win32_NTEventLogFile')
    el_sub = el_parser.add_subparsers(help='eventlog actions', dest='eventlog_action')

    el_sub.add_parser('list', help='List event log files')

    p = el_sub.add_parser('clear',
        help='Clear an event log (writes Event ID 1102/104)')
    p.add_argument('-name', required=True, help='Log name (e.g. Security, System)')

    p = el_sub.add_parser('read', help='Read events (always filtered)')
    p.add_argument('-logfile', required=True,
        help='Log name (e.g. Security, Application)')
    p.add_argument('-id', dest='event_id', type=int,
        help='Filter by Event ID')
    p.add_argument('-count', type=int, default=50,
        help='Max events to display (default 50)')

    # ===================== net =====================
    net_parser = subparsers.add_parser('net',
        help='Network connections and DNS cache (netstat equivalent)')
    net_sub = net_parser.add_subparsers(help='net actions', dest='net_action')

    net_sub.add_parser('tcp', help='TCP connections (MSFT_NetTCPConnection)')
    net_sub.add_parser('udp', help='UDP endpoints (MSFT_NetUDPEndpoint)')
    net_sub.add_parser('dns', help='DNS client cache (MSFT_DNSClientCache)')

    # ===================== rdp =====================
    rdp_parser = subparsers.add_parser('rdp',
        help='Remote Desktop enable/disable/status')
    rdp_sub = rdp_parser.add_subparsers(help='rdp actions', dest='rdp_action')

    rdp_sub.add_parser('status', help='Show current RDP status')
    rdp_sub.add_parser('enable', help='Enable RDP with firewall exception')
    rdp_sub.add_parser('disable', help='Disable RDP')

    # ===================== file =====================
    file_parser = subparsers.add_parser('file',
        help='File operations via CIM_DataFile (no subprocess)')
    file_sub = file_parser.add_subparsers(help='file actions', dest='file_action')

    p = file_sub.add_parser('search',
        help='Search for files (REQUIRES -drive and -path to avoid hanging target)')
    p.add_argument('-drive', required=True, help='Drive letter (e.g. C:)')
    p.add_argument('-path', required=True,
        help='Directory path with trailing backslash (e.g. \\\\Windows\\\\System32\\\\)')
    p.add_argument('-ext', dest='ext', help='File extension filter (e.g. dll)')
    p.add_argument('-name', dest='fname',
        help='Filename filter with wildcards (e.g. ntds*)')

    p = file_sub.add_parser('ls', help='List directory contents')
    p.add_argument('-path', required=True,
        help='Full directory path (e.g. C:\\\\Users)')

    p = file_sub.add_parser('copy',
        help='Copy a file (target-local only, cannot stream bytes)')
    p.add_argument('-source', required=True, help='Source file path')
    p.add_argument('-dest', required=True, help='Destination file path')

    p = file_sub.add_parser('delete', help='Delete a file')
    p.add_argument('-path', required=True, help='File path to delete')

    # ===================== share =====================
    share_parser = subparsers.add_parser('share',
        help='Network share creation and deletion')
    share_sub = share_parser.add_subparsers(help='share actions', dest='share_action')

    p = share_sub.add_parser('create', help='Create a network share')
    p.add_argument('-name', required=True, help='Share name')
    p.add_argument('-path', required=True, help='Local path to share')
    p.add_argument('-description', default='', help='Share description')

    p = share_sub.add_parser('delete', help='Delete a network share')
    p.add_argument('-name', required=True, help='Share name')

    # ===================== authentication =====================
    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action='store', metavar='LMHASH:NTHASH',
                       help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action='store_true',
                       help='Don\'t ask for password (useful for -k)')
    group.add_argument('-k', action='store_true',
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on target parameters.')
    group.add_argument('-aesKey', action='store', metavar='hex key',
                       help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    group.add_argument('-keytab', action='store',
                       help='Read keys for SPN from keytab file')

    # ===================== connection =====================
    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store', metavar='ip address',
                       help='IP Address of the domain controller')
    group.add_argument('-target-ip', action='store', metavar='ip address',
                       help='IP Address of the target machine')

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
