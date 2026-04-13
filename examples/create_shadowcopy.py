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
#   Creates or deletes VSS (Volume Shadow Copy) snapshots on a remote
#   machine via WMI DCOM. No vssadmin process is spawned on the target.
#
#   The shadow copy is created using Win32_ShadowCopy.Create() over DCOM,
#   which avoids the process creation telemetry associated with vssadmin.
#
# Usage:
#   create_shadowcopy.py [-volume C:\] [[domain/]username[:password]@]<target>
#   create_shadowcopy.py -delete -shadow-id {GUID} [[domain/]username[:password]@]<target>
#   create_shadowcopy.py -list [[domain/]username[:password]@]<target>
#
# Author:
#   Black Lantern Security
#

import sys
import logging
import argparse

from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket import version
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcom.oaut import NULL
from impacket.dcerpc.v5.dcomrt import DCOMConnection, COMVERSION
from impacket.krb5.keytab import Keytab


class ShadowCopy:
    def __init__(self, host, username='', password='', domain='', hashes=None,
                 aesKey=None, doKerberos=False, kdcHost=None):
        self.__host = host
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = aesKey
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')

    def __connect(self):
        dcom = DCOMConnection(self.__host, self.__username, self.__password,
                              self.__domain, self.__lmhash, self.__nthash,
                              self.__aesKey, oxidResolver=False,
                              doKerberos=self.__doKerberos,
                              kdcHost=self.__kdcHost)
        iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,
                                             wmi.IID_IWbemLevel1Login)
        iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
        iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
        iWbemLevel1Login.RemRelease()
        return dcom, iWbemServices

    def create(self, volume):
        dcom, iWbemServices = self.__connect()
        try:
            win32ShadowCopy, _ = iWbemServices.GetObject('Win32_ShadowCopy')
            logging.info('Creating shadow copy for volume: %s' % volume)
            result = win32ShadowCopy.Create(volume, 'ClientAccessible')
            shadowId = result.ShadowID
            logging.info('Shadow copy created: %s' % shadowId)

            # Query for the device object path
            query = "SELECT * FROM Win32_ShadowCopy WHERE ID='%s'" % shadowId
            iEnum = iWbemServices.ExecQuery(query)
            device_object = None
            try:
                item = iEnum.Next(0xffffffff, 1)[0]
                props = item.getProperties()
                device_object = props['DeviceObject']['value']
            except Exception:
                pass

            return shadowId, device_object
        finally:
            dcom.disconnect()

    def delete(self, shadowId):
        dcom, iWbemServices = self.__connect()
        try:
            wmiPath = 'Win32_ShadowCopy.ID="%s"' % shadowId
            logging.info('Deleting shadow copy: %s' % shadowId)
            iWbemServices.DeleteInstance(wmiPath)
            logging.info('Shadow copy deleted.')
        finally:
            dcom.disconnect()

    def list(self):
        dcom, iWbemServices = self.__connect()
        try:
            iEnum = iWbemServices.ExecQuery('SELECT * FROM Win32_ShadowCopy')
            shadows = []
            while True:
                try:
                    item = iEnum.Next(0xffffffff, 1)[0]
                    props = item.getProperties()
                    shadows.append({
                        'ID': props['ID']['value'],
                        'DeviceObject': props['DeviceObject']['value'],
                        'VolumeName': props['VolumeName']['value'],
                        'InstallDate': props['InstallDate']['value'],
                    })
                except Exception:
                    break
            return shadows
        finally:
            dcom.disconnect()


if __name__ == '__main__':
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True,
        description='Creates, lists, or deletes VSS shadow copies on a remote '
                    'machine via WMI DCOM. No vssadmin process is spawned on '
                    'the target.')

    parser.add_argument('target', action='store',
                        help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-com-version', action='store', metavar='MAJOR_VERSION:MINOR_VERSION',
                        help='DCOM version, format is MAJOR_VERSION:MINOR_VERSION e.g. 5.7')

    action = parser.add_argument_group('action')
    action.add_argument('-volume', action='store', default='C:\\',
                        help='Volume to create the shadow copy for (default: C:\\)')
    action.add_argument('-list', action='store_true', default=False,
                        help='List existing shadow copies on the target')
    action.add_argument('-delete', action='store_true', default=False,
                        help='Delete a shadow copy (requires -shadow-id)')
    action.add_argument('-shadow-id', action='store', metavar='ID',
                        help='Shadow copy ID for deletion (e.g. {GUID})')

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
    group.add_argument('-dc-ip', action='store', metavar='ip address',
                       help='IP Address of the domain controller. If omitted it will use the '
                            'domain part (FQDN) specified in the target parameter')
    group.add_argument('-target-ip', action='store', metavar='ip address',
                       help='IP Address of the target machine. If omitted it will use whatever '
                            'was specified as target. This is useful when target is the NetBIOS '
                            'name and you cannot resolve it')
    group.add_argument('-keytab', action='store',
                       help='Read keys for SPN from keytab file')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    logger.init(options.ts, options.debug)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    if options.com_version is not None:
        try:
            major_version, minor_version = options.com_version.split('.')
            COMVERSION.set_default_version(int(major_version), int(minor_version))
        except Exception:
            logging.error('Wrong COMVERSION format, use dot separated integers e.g. "5.7"')
            sys.exit(1)

    if options.delete and not options.shadow_id:
        logging.error('-delete requires -shadow-id')
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
        sc = ShadowCopy(options.target_ip, username, password, domain,
                        options.hashes, options.aesKey, options.k, options.dc_ip)

        if options.list:
            shadows = sc.list()
            if not shadows:
                logging.info('No shadow copies found.')
            else:
                print('')
                for s in shadows:
                    print('  Shadow ID:     %s' % s['ID'])
                    print('  Device Object: %s' % s['DeviceObject'])
                    print('  Volume Name:   %s' % s['VolumeName'])
                    print('  Install Date:  %s' % s['InstallDate'])
                    print('')

        elif options.delete:
            sc.delete(options.shadow_id)

        else:
            shadowId, deviceObject = sc.create(options.volume)
            print('')
            print('Shadow ID:     %s' % shadowId)
            print('Device Object: %s' % deviceObject)
            print('')
            print('Use this device path with Read-RawNTFS to access files:')
            print('  Read-RawNTFS -DevicePath "%s" -FileName "ntds.dit" -Output .\\ntds.dit' % deviceObject)
            print('')
            print('To delete this shadow copy:')
            print('  create_shadowcopy.py -delete -shadow-id "%s" %s' % (shadowId, options.target))

    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))
        sys.exit(1)
