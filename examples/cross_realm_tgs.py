#!/usr/bin/env python3
"""
Cross-realm Kerberos ticket tool.

Given a ccache with a TGT for realm A, automatically obtains a service ticket
for a target in realm B by following the referral chain:

  1. Present TGT to source KDC → get krbtgt/REALM_B referral TGT
  2. Present referral TGT to target KDC → get service ticket (cifs/, ldap/, etc.)

Handles multi-hop referrals automatically.

Usage:
    # Auto two-hop: source realm TGT → target in different realm
    python3 cross_realm_tgs.py -ccache ./krb5cc_user -target server.child.domain.com \\
        -dc-ip1 10.1.1.1 -dc-ip2 10.2.2.2

    # Custom SPN (default is cifs,host)
    python3 cross_realm_tgs.py -ccache ./krb5cc_user -target server.domain.com \\
        -dc-ip1 10.1.1.1 -dc-ip2 10.2.2.2 -service ldap

    # Single-hop (already have a cross-realm TGT)
    python3 cross_realm_tgs.py -ccache ./referral.ccache -target server.domain.com \\
        -dc-ip2 10.2.2.2
"""

import sys, os, argparse, datetime

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

from impacket.krb5.ccache import CCache
from impacket.krb5.asn1 import AP_REQ, TGS_REQ, TGS_REP, AS_REP, Authenticator, \
    seq_set, seq_set_iter, KRB_ERROR, EncTGSRepPart
from impacket.krb5.types import Principal, KerberosTime, Ticket
from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import KerberosError
from impacket.krb5.crypto import Key, _enctype_table
from pyasn1.type.univ import noValue
from pyasn1.codec.der import encoder, decoder
import struct, socket, random, binascii, subprocess

DEBUG = False


def dbg(msg):
    if DEBUG:
        print(f'    [DBG] {msg}')


def resolve_kdc(realm, kdc_map=None):
    """Resolve KDC IP for a realm via DNS SRV, then A record fallback."""
    if kdc_map and realm.upper() in kdc_map:
        ip = kdc_map[realm.upper()]
        dbg(f'KDC for {realm} from map: {ip}')
        return ip

    srv_name = f'_kerberos._tcp.{realm.lower()}'
    try:
        result = subprocess.run(
            ['dig', '+short', 'SRV', srv_name],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            for line in result.stdout.strip().split('\n'):
                parts = line.split()
                if len(parts) >= 4:
                    host = parts[3].rstrip('.')
                    try:
                        ip = socket.getaddrinfo(host, 88, 0, socket.SOCK_STREAM)[0][4][0]
                        dbg(f'KDC for {realm} via SRV: {host} -> {ip}')
                        return ip
                    except Exception:
                        continue
    except Exception as e:
        dbg(f'SRV lookup failed for {realm}: {e}')

    for name in [realm.lower(), realm]:
        try:
            ip = socket.getaddrinfo(name, 88, 0, socket.SOCK_STREAM)[0][4][0]
            dbg(f'KDC for {realm} via A ({name}): {ip}')
            return ip
        except Exception:
            pass

    return None


def send_raw(data, host, port=88):
    messageLen = struct.pack('!i', len(data))
    af, socktype, proto, _, sa = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)[0]
    s = socket.socket(af, socktype, proto)
    s.settimeout(10)
    s.connect(sa)
    s.sendall(messageLen + data)
    recvDataLen = struct.unpack('!i', s.recv(4))[0]
    r = s.recv(recvDataLen)
    while len(r) < recvDataLen:
        r += s.recv(recvDataLen - len(r))
    s.close()
    return r


def decode_tgt(ticket_data):
    try:
        return decoder.decode(ticket_data, asn1Spec=TGS_REP())[0]
    except:
        return decoder.decode(ticket_data, asn1Spec=AS_REP())[0]


def get_tgt_from_ccache(ccache):
    """Find the best TGT in a ccache file."""
    for c in ccache.credentials:
        sname = '/'.join(c['server'].prettyPrint().split(b'@')[0].decode().split('/'))
        if 'krbtgt' in sname.lower():
            return c
    return None


def build_tgs_req(decoded_ticket, cipher, session_key, target_spn, target_realm, client_realm=None):
    """Build a TGS-REQ using the given ticket."""
    ticket = Ticket()
    ticket.from_asn1(decoded_ticket['ticket'])

    ticket_sname = '/'.join(str(s) for s in decoded_ticket['ticket']['sname']['name-string'])
    ticket_realm_val = str(decoded_ticket['ticket']['realm'])
    dbg(f'Building TGS-REQ:')
    dbg(f'  Ticket sname: {ticket_sname}')
    dbg(f'  Ticket realm: {ticket_realm_val}')
    dbg(f'  Target SPN:   {target_spn}')
    dbg(f'  Target realm (req-body): {target_realm}')
    dbg(f'  Cipher:       etype={cipher.enctype} ({type(cipher).__name__})')
    dbg(f'  Session key type: {session_key.enctype}')
    dbg(f'  Session key:  {binascii.hexlify(session_key.contents[:8]).decode()}...')

    # Use client_realm from the ticket if not overridden
    if client_realm is None:
        client_realm = str(decoded_ticket['crealm'])

    dbg(f'  Authenticator crealm: {client_realm}')
    clientName = Principal()
    clientName.from_asn1(decoded_ticket, 'crealm', 'cname')
    dbg(f'  Authenticator cname:  {clientName}')

    apReq = AP_REQ()
    apReq['pvno'] = 5
    apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)
    apReq['ap-options'] = constants.encodeFlags([])
    seq_set(apReq, 'ticket', ticket.to_asn1)

    authenticator = Authenticator()
    authenticator['authenticator-vno'] = 5
    authenticator['crealm'] = client_realm.encode('utf-8')

    clientName = Principal()
    clientName.from_asn1(decoded_ticket, 'crealm', 'cname')
    seq_set(authenticator, 'cname', clientName.components_to_asn1)

    now = datetime.datetime.now(datetime.timezone.utc)
    authenticator['cusec'] = now.microsecond
    authenticator['ctime'] = KerberosTime.to_asn1(now)

    encodedAuthenticator = encoder.encode(authenticator)
    encryptedEncodedAuthenticator = cipher.encrypt(session_key, 7, encodedAuthenticator, None)

    apReq['authenticator'] = noValue
    apReq['authenticator']['etype'] = cipher.enctype
    apReq['authenticator']['cipher'] = encryptedEncodedAuthenticator

    tgsReq = TGS_REQ()
    tgsReq['pvno'] = 5
    tgsReq['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REQ.value)
    tgsReq['padata'] = noValue
    tgsReq['padata'][0] = noValue
    tgsReq['padata'][0]['padata-type'] = int(constants.PreAuthenticationDataTypes.PA_TGS_REQ.value)
    tgsReq['padata'][0]['padata-value'] = encoder.encode(apReq)

    reqBody = seq_set(tgsReq, 'req-body')
    reqBody['kdc-options'] = constants.encodeFlags([
        constants.KDCOptions.canonicalize.value,
        constants.KDCOptions.forwardable.value,
        constants.KDCOptions.renewable.value,
    ])

    serverName = Principal(target_spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
    seq_set(reqBody, 'sname', serverName.components_to_asn1)
    reqBody['realm'] = target_realm

    till = now + datetime.timedelta(days=1)
    reqBody['till'] = KerberosTime.to_asn1(till)
    reqBody['nonce'] = random.getrandbits(31)
    seq_set_iter(reqBody, 'etype', (
        int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),
        int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),
        int(constants.EncryptionTypes.rc4_hmac.value),
    ))

    return encoder.encode(tgsReq)


def send_tgs_req(message, kdc_ip):
    """Send TGS-REQ and return either a TGS-REP or raise on error."""
    dbg(f'Sending TGS-REQ to {kdc_ip}:88 ({len(message)} bytes)')
    r = send_raw(message, kdc_ip)
    dbg(f'Received response: {len(r)} bytes')

    # Check for KRB_ERROR
    try:
        error_decoded = decoder.decode(r, asn1Spec=KRB_ERROR())[0]
        krbError = KerberosError(packet=error_decoded)
        dbg(f'KRB-ERROR received:')
        dbg(f'  error-code: {error_decoded["error-code"]}')
        dbg(f'  crealm:     {str(error_decoded["crealm"]) if error_decoded["crealm"].hasValue() else "(empty)"}')
        dbg(f'  realm:      {str(error_decoded["realm"])}')
        sname_parts = [str(s) for s in error_decoded['sname']['name-string']] if error_decoded['sname'].hasValue() else []
        dbg(f'  sname:      {"/".join(sname_parts)}')
        if error_decoded['e-text'].hasValue():
            dbg(f'  e-text:     {str(error_decoded["e-text"])}')
        if error_decoded['e-data'].hasValue():
            dbg(f'  e-data:     {binascii.hexlify(bytes(error_decoded["e-data"])).decode()[:120]}...')
        raise krbError
    except KerberosError:
        raise
    except:
        pass

    tgs_rep = decoder.decode(r, asn1Spec=TGS_REP())[0]
    dbg(f'TGS-REP received:')
    dbg(f'  crealm: {str(tgs_rep["crealm"])}')
    cname_parts = [str(s) for s in tgs_rep['cname']['name-string']]
    dbg(f'  cname:  {"/".join(cname_parts)}')
    ticket_sname = [str(s) for s in tgs_rep['ticket']['sname']['name-string']]
    dbg(f'  ticket sname: {"/".join(ticket_sname)}')
    dbg(f'  ticket realm: {str(tgs_rep["ticket"]["realm"])}')
    dbg(f'  enc-part etype: {int(tgs_rep["enc-part"]["etype"])}')
    return tgs_rep


def decrypt_tgs_rep(tgs_rep, session_key):
    """Decrypt TGS-REP enc-part and return new session key."""
    cipherText = tgs_rep['enc-part']['cipher']
    newCipher = _enctype_table[int(tgs_rep['enc-part']['etype'])]
    dbg(f'Decrypting TGS-REP enc-part:')
    dbg(f'  etype: {int(tgs_rep["enc-part"]["etype"])} ({type(newCipher).__name__})')
    dbg(f'  using session key type: {session_key.enctype}')
    dbg(f'  key usage: 8')
    plainText = newCipher.decrypt(session_key, 8, cipherText)
    encPart = decoder.decode(plainText, asn1Spec=EncTGSRepPart())[0]
    new_key = Key(encPart['key']['keytype'], bytes(encPart['key']['keyvalue']))
    dbg(f'  new session key type: {new_key.enctype}')
    dbg(f'  new session key: {binascii.hexlify(new_key.contents[:8]).decode()}...')
    if encPart['srealm'].hasValue():
        dbg(f'  srealm in enc-part: {str(encPart["srealm"])}')
    return new_key


def save_ccache(tgs_raw, old_session_key, out_name):
    """Save a TGS response to a ccache file."""
    cc = CCache()
    cc.fromTGS(tgs_raw, old_session_key, old_session_key)
    cc.saveFile(out_name)


def get_ticket_info(decoded):
    """Extract readable info from a decoded Kerberos reply."""
    crealm = str(decoded['crealm'])
    cname = str(decoded['cname']['name-string'][0])
    sname_parts = [str(s) for s in decoded['ticket']['sname']['name-string']]
    srealm = str(decoded['ticket']['realm'])
    return cname, crealm, '/'.join(sname_parts), srealm


def main():
    parser = argparse.ArgumentParser(
        description='Cross-realm Kerberos ticket tool — auto referral chain',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Two-hop: source realm TGT → service ticket in target realm
  %(prog)s -ccache ./krb5cc_user -target server.child.domain.com -dc-ip1 10.1.1.1 -dc-ip2 10.2.2.2

  # Single-hop: already have cross-realm TGT
  %(prog)s -ccache ./referral.ccache -target server.domain.com -dc-ip2 10.2.2.2

  # Custom service (ldap instead of cifs)
  %(prog)s -ccache ./krb5cc_user -target dc01.domain.com -dc-ip1 10.1.1.1 -dc-ip2 10.2.2.2 -service ldap
""")
    parser.add_argument('-ccache', required=True, help='Source ccache file with TGT')
    parser.add_argument('-target', required=True, help='Target hostname (e.g. server.domain.com)')
    parser.add_argument('-service', default='cifs,host', help='Comma-separated service types (default: cifs,host). Use ldap for LDAP access.')
    parser.add_argument('-dc-ip1', help='Source realm KDC IP (for getting referral TGT). Skip if ccache already has cross-realm TGT.')
    parser.add_argument('-dc-ip2', required=True, help='Target realm KDC IP (for getting service ticket)')
    parser.add_argument('-target-realm', help='Override target realm (auto-detected from referral if not set)')
    parser.add_argument('-client-realm', help='Override client home realm for multi-hop referrals (e.g. PARENT.DOMAIN.COM)')
    parser.add_argument('-kdc-map', help='Realm-to-IP map for intermediate KDCs (e.g. DOMAIN.COM:10.1.1.1,OTHER.COM:10.2.2.2)')
    parser.add_argument('-debug', action='store_true')
    args = parser.parse_args()

    global DEBUG
    DEBUG = args.debug

    services = [s.strip() for s in args.service.split(',') if s.strip()]
    spn = f'{services[0]}/{args.target}'

    # Load ccache
    ccache = CCache.loadFile(args.ccache)
    dbg(f'Loaded ccache: {args.ccache}')
    try:
        dbg(f'  Default principal: {ccache.principal.prettyPrint().decode()}')
        dbg(f'  Default realm: {ccache.principal.realm["data"].decode()}')
    except Exception:
        dbg(f'  (could not parse default principal)')
    dbg(f'  Credentials in ccache: {len(ccache.credentials)}')
    for i, c in enumerate(ccache.credentials):
        c_client = c['client'].prettyPrint().decode() if hasattr(c['client'], 'prettyPrint') else str(c['client'])
        c_server = c['server'].prettyPrint().decode() if hasattr(c['server'], 'prettyPrint') else str(c['server'])
        dbg(f'    [{i}] client={c_client} server={c_server}')

    cred = get_tgt_from_ccache(ccache)
    if not cred:
        print('[-] No krbtgt ticket found in ccache')
        sys.exit(1)

    tgt = cred.toTGT()
    ticket_data = tgt['KDC_REP']
    cipher = tgt['cipher']
    session_key = tgt['sessionKey']
    decoded = decode_tgt(ticket_data)
    dbg(f'Decoded TGT from ccache:')
    dbg(f'  cipher etype: {cipher.enctype} ({type(cipher).__name__})')
    dbg(f'  session key etype: {session_key.enctype}')
    dbg(f'  session key: {binascii.hexlify(session_key.contents[:8]).decode()}...')

    cname, crealm, sname, srealm = get_ticket_info(decoded)
    print(f'[*] Source ccache: {cname}@{crealm}')
    print(f'[*] Current ticket: {sname}@{srealm}')
    print(f'[*] Target: {spn}')

    # Determine ticket type
    ticket_sname_parts = [str(s) for s in decoded['ticket']['sname']['name-string']]
    ticket_realm = str(decoded['ticket']['realm'])
    is_same_realm_tgt = (len(ticket_sname_parts) == 2 and
                         ticket_sname_parts[0].lower() == 'krbtgt' and
                         ticket_sname_parts[1].upper() == crealm.upper())

    # ── Determine target realm ─────────────────────────────────────────
    if args.target_realm:
        target_realm = args.target_realm.upper()
    else:
        parts = args.target.split('.', 1)
        target_realm = parts[1].upper() if len(parts) > 1 else None

    # Client's home realm — must stay constant through all referral hops
    if args.client_realm:
        client_home_realm = args.client_realm.upper()
    else:
        try:
            client_home_realm = ccache.principal.realm['data'].decode()
        except Exception:
            client_home_realm = crealm
    dbg(f'Client home realm: {client_home_realm}')
    dbg(f'Target realm: {target_realm}')

    # Parse KDC map for intermediate realms
    kdc_map = {}
    if args.kdc_map:
        for entry in args.kdc_map.split(','):
            if ':' in entry:
                r, ip = entry.rsplit(':', 1)
                kdc_map[r.strip().upper()] = ip.strip()
        dbg(f'KDC map: {kdc_map}')

    # Do we need to follow a referral chain?
    needs_referral = is_same_realm_tgt or (
        len(ticket_sname_parts) == 2 and
        ticket_sname_parts[0].lower() == 'krbtgt' and
        target_realm and
        ticket_sname_parts[1].upper() != target_realm
    )

    if needs_referral and is_same_realm_tgt and not args.dc_ip1:
        print(f'[-] TGT is for same realm ({crealm}) — need -dc-ip1 to get cross-realm referral')
        sys.exit(1)

    # ── Referral loop: follow chain until we reach target realm ────────
    if needs_referral:
        current_decoded = decoded
        current_cipher = cipher
        current_session_key = session_key

        if is_same_realm_tgt:
            current_kdc = args.dc_ip1
        else:
            inter_realm = ticket_sname_parts[1].upper()
            current_kdc = args.dc_ip1 or resolve_kdc(inter_realm, kdc_map)
            if not current_kdc:
                print(f'[-] Cannot resolve KDC for {inter_realm}. Use -dc-ip1 or -kdc-map.')
                sys.exit(1)

        seen_realms = set()
        max_hops = 10

        for hop in range(1, max_hops + 1):
            hop_sname = [str(s) for s in current_decoded['ticket']['sname']['name-string']]
            if hop_sname[0].lower() == 'krbtgt' and len(hop_sname) > 1:
                kdc_realm = hop_sname[1].upper()
            else:
                kdc_realm = str(current_decoded['ticket']['realm']).upper()

            if kdc_realm in seen_realms:
                print(f'[-] Referral loop detected (already visited {kdc_realm})')
                sys.exit(1)
            seen_realms.add(kdc_realm)

            print(f'\n[*] Hop {hop}: requesting {spn} from {kdc_realm} KDC ({current_kdc})')

            message = build_tgs_req(current_decoded, current_cipher, current_session_key,
                                    spn, kdc_realm, client_realm=client_home_realm)

            tgs_rep = None
            try:
                tgs_rep = send_tgs_req(message, current_kdc)
            except KerberosError as e:
                err_code = e.getErrorCode()

                if err_code == constants.ErrorCodes.KDC_ERR_WRONG_REALM.value:
                    pkt = e.getErrorPacket()
                    hint = None
                    if pkt and pkt['crealm'].hasValue():
                        hint = str(pkt['crealm']).upper()
                    if hint:
                        print(f'[*] KDC redirected to realm: {hint}')
                        message = build_tgs_req(current_decoded, current_cipher, current_session_key,
                                                f'krbtgt/{hint}', hint, client_realm=client_home_realm)
                        try:
                            tgs_rep = send_tgs_req(message, current_kdc)
                        except KerberosError as e2:
                            print(f'[-] Explicit krbtgt/{hint} failed: {e2}')
                            sys.exit(1)
                    elif target_realm:
                        print(f'[*] No realm hint, trying krbtgt/{target_realm}...')
                        message = build_tgs_req(current_decoded, current_cipher, current_session_key,
                                                f'krbtgt/{target_realm}', target_realm,
                                                client_realm=client_home_realm)
                        try:
                            tgs_rep = send_tgs_req(message, current_kdc)
                        except KerberosError as e2:
                            print(f'[-] Failed: {e2}')
                            sys.exit(1)
                    else:
                        print(f'[-] KDC_ERR_WRONG_REALM but no realm hint. Use -target-realm.')
                        sys.exit(1)

                elif err_code == constants.ErrorCodes.KDC_ERR_S_PRINCIPAL_UNKNOWN.value and target_realm:
                    print(f'[*] SPN not found in {kdc_realm}, trying krbtgt/{target_realm}...')
                    message = build_tgs_req(current_decoded, current_cipher, current_session_key,
                                            f'krbtgt/{target_realm}', target_realm,
                                            client_realm=client_home_realm)
                    try:
                        tgs_rep = send_tgs_req(message, current_kdc)
                    except KerberosError as e2:
                        print(f'[-] Failed: {e2}')
                        sys.exit(1)
                else:
                    print(f'[-] KDC error at hop {hop}: {e}')
                    sys.exit(1)

            ref_cname, ref_crealm, ref_sname, ref_srealm = get_ticket_info(tgs_rep)
            print(f'[+] Got: {ref_sname}@{ref_srealm}')

            new_session_key = decrypt_tgs_rep(tgs_rep, current_session_key)

            ref_raw = encoder.encode(tgs_rep)
            if ref_sname.lower().startswith('krbtgt/'):
                ref_target = ref_sname.split('/')[1]
                ref_filename = f'krb_referral_{ref_target.lower().replace(".", "_")}.ccache'
            else:
                ref_filename = f'krb_{services[0]}_{args.target.split(".")[0].lower()}.ccache'
            save_ccache(ref_raw, current_session_key, ref_filename)
            print(f'[+] Saved: {ref_filename}')

            if not ref_sname.lower().startswith('krbtgt/'):
                print(f'\n[+] Service ticket obtained after {hop} hop(s)!')
                # Request remaining service types using the cross-realm TGT from the previous hop
                out_ccache = CCache()
                out_ccache.fromTGS(ref_raw, current_session_key, current_session_key)
                remaining = [s for s in services if s.lower() != ref_sname.split('/')[0].lower()]
                for svc_type in remaining:
                    svc_spn = f'{svc_type}/{args.target}'
                    print(f'[*] Requesting {svc_spn} from {ref_srealm} KDC ({current_kdc})')
                    msg = build_tgs_req(current_decoded, current_cipher, current_session_key,
                                        svc_spn, ref_srealm, client_realm=client_home_realm)
                    try:
                        extra_rep = send_tgs_req(msg, current_kdc)
                        extra_cname, extra_crealm, extra_sname, extra_srealm = get_ticket_info(extra_rep)
                        print(f'[+] Got: {extra_sname}@{extra_srealm}')
                        extra_raw = encoder.encode(extra_rep)
                        tmp_cc = CCache()
                        tmp_cc.fromTGS(extra_raw, current_session_key, current_session_key)
                        out_ccache.credentials.extend(tmp_cc.credentials)
                    except KerberosError as e:
                        print(f'[-] Failed to get {svc_spn}: {e}')

                svc_filename = f'krb_{args.target.split(".")[0].lower()}.ccache'
                out_ccache.saveFile(svc_filename)
                print(f'\n[+] Saved {len(out_ccache.credentials)} ticket(s) to {svc_filename}')
                print(f'[*] Use:')
                print(f'    export KRB5CCNAME=./{svc_filename}')
                if 'ldap' in services:
                    print(f'    bloodhound-python -c All -k -no-pass -d {target_realm.lower()} -dc {args.target}')
                else:
                    print(f'    smbclient.py -k -no-pass {args.target}')
                    print(f'    atexec.py -k -no-pass {args.target} <command>')
                return

            ref_realm = ref_sname.split('/')[1].upper()

            if target_realm and ref_realm == target_realm:
                decoded = tgs_rep
                cipher = _enctype_table[int(new_session_key.enctype)]
                session_key = new_session_key
                print(f'[*] Reached target realm {target_realm} after {hop} hop(s)')
                break

            # Intermediate referral — resolve next KDC
            print(f'[*] Intermediate referral to {ref_realm}')
            if ref_realm.upper() in kdc_map:
                next_kdc = kdc_map[ref_realm.upper()]
            elif args.dc_ip2 and target_realm and ref_realm == target_realm:
                next_kdc = args.dc_ip2
            else:
                next_kdc = resolve_kdc(ref_realm, kdc_map)
            if not next_kdc:
                print(f'[-] Cannot resolve KDC for {ref_realm}')
                print(f'    Use: -kdc-map {ref_realm}:<ip>')
                sys.exit(1)
            print(f'[*] Resolved {ref_realm} KDC: {next_kdc}')

            current_decoded = tgs_rep
            current_cipher = _enctype_table[int(new_session_key.enctype)]
            current_session_key = new_session_key
            current_kdc = next_kdc
        else:
            print(f'[-] Too many referral hops ({max_hops})')
            sys.exit(1)

    else:
        if not target_realm:
            target_realm = ticket_sname_parts[1].upper() if len(ticket_sname_parts) > 1 else None
        if not target_realm:
            print('[-] Cannot determine target realm. Use -target-realm.')
            sys.exit(1)
        print(f'[*] Already have cross-realm TGT to {target_realm}')

    # ── Final step: Get service tickets from target realm KDC ──────────
    out_ccache = None
    first_service = True
    for svc_type in services:
        svc_spn = f'{svc_type}/{args.target}'
        print(f'\n[*] Requesting {svc_spn} from {target_realm} KDC ({args.dc_ip2})')
        dbg(f'Final: SPN={svc_spn} realm={target_realm} crealm={client_home_realm} KDC={args.dc_ip2}')

        message = build_tgs_req(decoded, cipher, session_key,
                                svc_spn, target_realm, client_realm=client_home_realm)

        try:
            tgs_rep = send_tgs_req(message, args.dc_ip2)
        except KerberosError as e:
            print(f'[-] Failed to get {svc_spn}: {e}')
            continue

        svc_cname, svc_crealm, svc_sname, svc_srealm = get_ticket_info(tgs_rep)
        print(f'[+] Got: {svc_sname}@{svc_srealm}')

        new_session_key = decrypt_tgs_rep(tgs_rep, session_key)
        tgs_raw = encoder.encode(tgs_rep)

        if first_service:
            out_ccache = CCache()
            out_ccache.fromTGS(tgs_raw, session_key, session_key)
            first_service = False
        else:
            # Add additional credential to existing ccache
            tmp_ccache = CCache()
            tmp_ccache.fromTGS(tgs_raw, session_key, session_key)
            out_ccache.credentials.extend(tmp_ccache.credentials)
    if out_ccache is None:
        print('[-] No service tickets obtained')
        sys.exit(1)

    svc_filename = f'krb_{args.target.split(".")[0].lower()}.ccache'
    out_ccache.saveFile(svc_filename)

    print(f'\n[+] Saved {len(out_ccache.credentials)} ticket(s) to {svc_filename}')
    print(f'[*] Use:')
    print(f'    export KRB5CCNAME=./{svc_filename}')
    if 'ldap' in services:
        print(f'    bloodhound-python -c All -k -no-pass -d {target_realm.lower()} -dc {args.target}')
    else:
        print(f'    smbclient.py -k -no-pass {args.target}')
        print(f'    atexec.py -k -no-pass {args.target} <command>')


if __name__ == '__main__':
    main()
