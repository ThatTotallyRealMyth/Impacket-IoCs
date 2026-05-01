# Dissecting Impacket for Good and Bad 

## Quick reference

- [Kerberos and ticketing](#cat-kerberos-and-ticketing)
  - [IoC 01 - Kerberos Multiple Systematic Differences in AS-REQ](#ioc-01)
  - [IoC 02 - AS-REQ requested lifetime has `till == rtime == now + 1 day`](#ioc-02)
  - [IoC 03 - Sparse/Mismatched AS-REQ encryption type lists](#ioc-03)
  - [IoC 04 - `GetNPUsers.py` AS-REP roast request starts RC4-only, then retries AES](#ioc-04)
  - [IoC 05 - Generic TGS-REQ etype ordering: RC4, DES3, DES, then current cipher](#ioc-05)
  - [IoC 06 - S4U2Proxy TGS-REQ always adds RBCD `PA-PAC-OPTIONS`](#ioc-06)
  - [IoC 07 - Kerberos AP-REQ body differences in LDAP SASL bind](#ioc-07)
  - [IoC 08 - Impacket TGS-REQ does not carry PA-DATA PA-PAC-OPTIONS](#ioc-08)
  - [IoC 26 - `ticketer.py` forged tickets default to a 10-year lifetime with `endtime == renew-till`](#ioc-26)
  - [IoC 27 - `ticketer.py` PAC has fixed `LogonCount = 500`, empty `LogonServer`, and default admin-heavy group RIDs](#ioc-27)
  - [IoC 28 - `ticketer.py` writes KDC reply nonce `123456789` into forged EncRepPart](#ioc-28)
  - [IoC 29 - `raiseChild.py` forged parent access injects Enterprise Admin SID `-519` as an ExtraSid](#ioc-29)
  - [IoC 37 - Kerberos SPNEGO advertises the legacy Microsoft Kerberos OID but wraps the AP-REQ with the standard Kerberos OID](#ioc-37)
  - [IoC 38 - LDAP Kerberos bind sends raw `AP-REQ` as the SPNEGO mechToken](#ioc-38)
  - [IoC 39 - SMB/LDAP Kerberos AP-REQ authenticators omit the RFC 4121 checksum and sequence number](#ioc-39)
- [SMB](#cat-smb)
  - [IoC 09 - SMB2/3 client uses ASCII-letter `ClientGuid`](#ioc-09)
  - [IoC 10 - SMB2/3 negotiate request contains multiple omissions compared to Windows](#ioc-10)
  - [IoC 11 - SMB1 client negotiate offers only `NT LM 0.12`](#ioc-11)
- [NTLM and SPNEGO](#cat-ntlm-and-spnego)
  - [IoC 12 - NTLM implementation omissions in various fields](#ioc-12)
  - [IoC 20 - `ntlmrelayx` LDAP computer creation: 8 uppercase letters plus `$`](#ioc-20)
  - [IoC 21 - `ntlmrelayx` DNS WPAD bypass creates 12-letter random A record first](#ioc-21)
  - [IoC 41 - NTLMv2 client challenge is eight printable alphanumeric bytes](#ioc-41)
  - [IoC 42 - LDAP Sicily NTLM binds stamp `MsvAvTargetName` as `cifs/<dc-host>` instead of LDAP](#ioc-42)
  - [IoC 53 - Authenticated DCE/RPC often uses raw NTLMSSP instead of SPNEGO](#ioc-53)
  - [IoC 54 - Impacket's WMI `IWbemLevel1Login::NTLMLogin` implementation contains a spec violation and potential remote/local host contradiction](#ioc-54)
  - [IoC 55 - Impacket WMI scripts skip various exchanges before `NTLMLogin`](#ioc-55)
  - [IoC 57 - NTLM Type 1 uses a static no-version flag shape](#ioc-57)
  - [IoC 58 - NTLMv2 response omits Windows AV pairs and sends a NULL host name](#ioc-58)
- [LDAP and Active Directory objects](#cat-ldap-and-active-directory-objects)
  - [IoC 34 - `BadSuccessor.py` creates dMSAs named `dMSA-<8 uppercase alnum>` with fixed migration attributes](#ioc-34)
  - [IoC 48 - `addcomputer.py` default computer objects use `DESKTOP-[A-Z0-9]{8}$`](#ioc-48)
- [DCE/RPC, DCOM, and WMI](#cat-dce-rpc-dcom-and-wmi)
  - [IoC 13 - DCE/RPC bind is missing the second context item](#ioc-13)
  - [IoC 14 - DCE/RPC SCMR sets MachineName to "DUMMY" when accessing SCManager](#ioc-14)
  - [IoC 15 - DCE/RPC SCMR EnumServicesStatusW RPC invocation sends no offered buffer](#ioc-15)
  - [IoC 40 - Authenticated DCE/RPC uses `auth_context_id = 79231 + ctx_id` and `0xff` auth padding](#ioc-40)
  - [IoC 50 - DCE/RPC bind usually offers only 32-bit NDR](#ioc-50)
  - [IoC 51 - DCE/RPC ISystemActivate RemoteCreateInstance request contains various odd entries and omissions](#ioc-51)
  - [IoC 52 - DCE/RPC PDUs do not contain `Verification Trailer`](#ioc-52)
  - [IoC 56 - WMI DCOM activation uses a sparse four-property activation blob](#ioc-56)
  - [IoC 59 - DCOM ORPC causality ID uses Impacket's non-standard UUID generator](#ioc-59)
  - [IoC 60 - WMI/DCOM session skips the IOXIDResolver ServerAlive2 preflight](#ioc-60)
  - [IoC 61 - DCOM object release uses IRemUnknown with single PublicRef releases](#ioc-61)
  - [IoC 62 - DCOM activation leaves ClientImpersonationLevel at zero](#ioc-62)
  - [IoC 63 - DCOM activation serialization uses `0xcccccccc` fillers and `0xfa` property padding](#ioc-63)
  - [IoC 64 - WKSSVC calls use a ten-NUL `ServerName`](#ioc-64)
  - [IoC 66 - rpcrelayclient uses invalid/future use reserved "DummyOp" opnum 255](#ioc-66)
- [Example-script execution artifacts](#cat-example-script-execution-artifacts)
  - [IoC 16 - `psexec.py` RemCom named pipes, including typoed main pipe](#ioc-16)
  - [IoC 17 - Random 4-letter service name and random 8-letter `.exe`](#ioc-17)
  - [IoC 18 - `smbexec.py` `__output_<8 letters>` and `%SYSTEMROOT%\<8 letters>.bat`](#ioc-18)
  - [IoC 19 - `atexec.py` scheduled task has fixed 2015 `StartBoundary`](#ioc-19)
  - [IoC 25 - `wmipersist.py` permanent WMI subscription names `EF_<name>` and `TI_<name>`](#ioc-25)
  - [IoC 43 - `dcomexec.py` writes command output to `\127.0.0.1\<share>\__<epoch-prefix>`](#ioc-43)
  - [IoC 65 - RemCom `Machine` field is random four-letter ASCII](#ioc-65)
- [secretsdump, DRSUAPI, and VSS](#cat-secretsdump-drsuapi-and-vss)
  - [IoC 22 - `secretsdump.py` DRSBind advertises `dwExtCaps = 0xffffffff`](#ioc-22)
  - [IoC 23 - `secretsdump.py` DRSGetNCChanges requests one object with zero USNs](#ioc-23)
  - [IoC 24 - `secretsdump.py` VSS method uses predictable `vssadmin` and temp-copy sequence](#ioc-24)
  - [IoC 36 - `keylistattack.py` / `secretsdump.py` sends `KERB-KEY-LIST-REQ [161]` for `krbtgt` with RC4-only requested key list](#ioc-36)
- [MSSQL](#cat-mssql)
  - [IoC 30 - MSSQL LOGIN7 has constant `ClientID = 01:02:03:04:05:06` and spoofed SSMS metadata](#ioc-30)
  - [IoC 31 - MSSQL PRELOGIN uses fixed version bytes, `MSSQLServer`, and encryption-off negotiation](#ioc-31)
  - [IoC 32 - `mssqlshell.py` upload path echoes base64 chunks to `.b64`, decodes with `certutil`, then validates MD5](#ioc-32)
  - [IoC 33 - `mssqlshell.py` SQL Agent execution creates self-deleting `IdxDefrag<GUID>` CmdExec jobs](#ioc-33)
- [ntlmrelayx HTTP, WebDAV, RDP, and SCCM](#cat-ntlmrelayx-http-webdav-rdp-and-sccm)
  - [IoC 35 - ntlmrelayx HTTP/WinRM local-auth challenge has empty AV pairs and printable challenge material](#ioc-35)
  - [IoC 44 - ntlmrelayx WPAD serves a fixed PAC body with compact `FindProxyForURL` formatting](#ioc-44)
  - [IoC 45 - ntlmrelayx WebDAV bait returns `webdavrelay` XML with fixed 2016/2017 timestamps](#ioc-45)
  - [IoC 46 - ntlmrelayx multi-relay redirects to `/<10 uppercase letters-or-digits>`](#ioc-46)
  - [IoC 47 - ntlmrelayx RDP relay presents a self-signed certificate with CN `RDP-Server`](#ioc-47)
  - [IoC 49 - ntlmrelayx SCCM policy attack speaks with old ConfigMgr client strings](#ioc-49)
- [Conclusion](#conclusion)

<a id="cat-kerberos-and-ticketing"></a>

## Kerberos and ticketing

<a id="ioc-01"></a>

### IoC 01 - Kerberos Multiple Systematic Differences in AS-REQ
**Surface:** Kerberos AS-REQ Network activity/requests

Impacket's is built in a way thats different in several ways from how a Windows client typically fills the same request. The mismatches include `kdc-options`, flag choices, encryption types, and other request-body fields. 

Below is the AS-REQ body sent by Impacket:

```python
...
Kerberos
    Record Mark: 184 bytes
        0... .... .... .... .... .... .... .... = Reserved: Not set
        .000 0000 0000 0000 0000 0000 1011 1000 = Record Length: 184
    as-req
        pvno: 5
        msg-type: krb-as-req (10)
        padata: 1 item
            PA-DATA pA-PAC-REQUEST
                padata-type: pA-PAC-REQUEST (128)
                    padata-value: 3005a0030101ff
                        include-pac: True
        req-body
            Padding: 0
            kdc-options: 50800000
                0... .... = reserved: False
                .1.. .... = forwardable: True
                ..0. .... = forwarded: False
                ...1 .... = proxiable: True
                .... 0... = proxy: False
                .... .0.. = allow-postdate: False
                .... ..0. = postdated: False
                .... ...0 = unused7: False
                1... .... = renewable: True
                .0.. .... = unused9: False
                ..0. .... = unused10: False
                ...0 .... = opt-hardware-auth: False
                .... 0... = unused12: False
                .... .0.. = unused13: False
                .... ..0. = constrained-delegation: False
                .... ...0 = canonicalize: False
                0... .... = request-anonymous: False
                .0.. .... = unused17: False
                ..0. .... = unused18: False
                ...0 .... = unused19: False
                .... 0... = unused20: False
                .... .0.. = unused21: False
                .... ..0. = unused22: False
                .... ...0 = unused23: False
                0... .... = unused24: False
                .0.. .... = unused25: False
                ..0. .... = disable-transited-check: False
                ...0 .... = renewable-ok: False
                .... 0... = enc-tkt-in-skey: False
                .... .0.. = unused29: False
                .... ..0. = renew: False
                .... ...0 = validate: False
            cname
                name-type: kRB5-NT-PRINCIPAL (1)
                cname-string: 1 item
                    CNameString: sccmadmin
            realm: SCCMLAB.LOCAL
            sname
                name-type: kRB5-NT-PRINCIPAL (1)
                sname-string: 2 items
                    SNameString: krbtgt
                    SNameString: SCCMLAB.LOCAL
            till: Apr 30, 2026 02:34:00.000000000 EDT
            rtime: Apr 30, 2026 02:34:00.000000000 EDT
            nonce: 1243175638
            etype: 1 item
                ENCTYPE: eTYPE-AES256-CTS-HMAC-SHA1-96 (18)
    [Response in: 768]
```

And here's our actual Windows server: 

```python
Kerberos
    Record Mark: 305 bytes
        0... .... .... .... .... .... .... .... = Reserved: Not set
        .000 0000 0000 0000 0000 0001 0011 0001 = Record Length: 305
    as-req
        pvno: 5
        msg-type: krb-as-req (10)
        padata: 2 items
            PA-DATA pA-ENC-TIMESTAMP
                padata-type: pA-ENC-TIMESTAMP (2)
                    padata-value: 303da003020117a2360434cff2544e8d4e3026beee22640631d1054a9cc91ffbf8dac3ad1983a8510c06f4c65512c0ca55efe6d2fd818f70ba3fca28e631ff
                        etype: eTYPE-ARCFOUR-HMAC-MD5 (23)
                        cipher: cff2544e8d4e3026beee22640631d1054a9cc91ffbf8dac3ad1983a8510c06f4c65512c0ca55efe6d2fd818f70ba3fca28e631ff
                            Missing keytype 23 usage 1 (id=missing.1)
            PA-DATA pA-PAC-REQUEST
                padata-type: pA-PAC-REQUEST (128)
                    padata-value: 3005a0030101ff
                        include-pac: True
        req-body
            Padding: 0
            kdc-options: 40810010
                0... .... = reserved: False
                .1.. .... = forwardable: True
                ..0. .... = forwarded: False
                ...0 .... = proxiable: False
                .... 0... = proxy: False
                .... .0.. = allow-postdate: False
                .... ..0. = postdated: False
                .... ...0 = unused7: False
                1... .... = renewable: True
                .0.. .... = unused9: False
                ..0. .... = unused10: False
                ...0 .... = opt-hardware-auth: False
                .... 0... = unused12: False
                .... .0.. = unused13: False
                .... ..0. = constrained-delegation: False
                .... ...1 = canonicalize: True
                0... .... = request-anonymous: False
                .0.. .... = unused17: False
                ..0. .... = unused18: False
                ...0 .... = unused19: False
                .... 0... = unused20: False
                .... .0.. = unused21: False
                .... ..0. = unused22: False
                .... ...0 = unused23: False
                0... .... = unused24: False
                .0.. .... = unused25: False
                ..0. .... = disable-transited-check: False
                ...1 .... = renewable-ok: True
                .... 0... = enc-tkt-in-skey: False
                .... .0.. = unused29: False
                .... ..0. = renew: False
                .... ...0 = validate: False
            cname
                name-type: kRB5-NT-PRINCIPAL (1)
                cname-string: 1 item
                    CNameString: sccmadmin
            realm: SCCMLAB.LOCAL
            sname
                name-type: kRB5-NT-SRV-INST (2)
                sname-string: 2 items
                    SNameString: krbtgt
                    SNameString: SCCMLAB.LOCAL
            till: Sep 12, 2037 22:48:05.000000000 EDT
            rtime: Sep 12, 2037 22:48:05.000000000 EDT
            nonce: 173139575
            etype: 7 items
                ENCTYPE: eTYPE-ARCFOUR-HMAC-MD5 (23)
                ENCTYPE: eTYPE-ARCFOUR-HMAC-OLD (-133)
                ENCTYPE: eTYPE-ARCFOUR-MD4 (-128)
                ENCTYPE: eTYPE-ARCFOUR-HMAC-MD5-56 (24)
                ENCTYPE: eTYPE-ARCFOUR-HMAC-OLD-EXP (-135)
                ENCTYPE: eTYPE-AES256-CTS-HMAC-SHA1-96 (18)
                ENCTYPE: eTYPE-AES128-CTS-HMAC-SHA1-96 (18)
            addresses: 1 item SCCM<20>
                HostAddress SCCM<20>
                    addr-type: nETBIOS (20)
                    NetBIOS Name: SCCM<20> (Server service)
```

Noticeable differences include the fact that the Windows server sets `kdc-options: 40810010` while Impacket will use `kdc-options: 50800000`, additionally the real Windows client will usually include the `HostAddress`, `addr-type` and `NetBIOS Name`

Finally, the `etype` list for impacket is monolithic in nature. Impacket will offer aes-256 and then offer RC4. Meanwhile Windows clients offer alot more diverse and numerous encryption types depending on the enctype support set up for the service account, domain policies and other settings. 

Some others in a digestible format include:

| Feature          | Impacket                       | Windows                          |
| ---------------- | ------------------------------ | -------------------------------- |
| `kdc-options`    | Proxiable bit set              | Proxiable never set              |
| `kdc-options`    | No canonicalize / renewable-ok | Both present                     |
| `sname` type     | `NT‑PRINCIPAL (1)`             | `NT‑SRV‑INST (2)`                |
| `till` / `rtime` | Short, fixed offset            | Far‑future sentinel dates        |
| `etype`          | Single AES cipher (often)      | Broad list including RC4         |
| `addresses`      | Absent                         | Host NetBIOS name present        |

<a id="ioc-02"></a>

### IoC 02 - AS-REQ requested lifetime has `till == rtime == now + 1 day`
**Surface:** Kerberos AS-REQ network telemetry

Impacket sets both requested ticket end time and renew-till time to the same UTC value: current time plus one day. The default values, from what I can gather for renew-till time is generally 7 days. Additionally the ticket end time value depends on a few things. For example, normally it would be 10 hours, but for protected  users both the renew-till and the ticket endtime would be enforced to 240 minutes. This is useful in certain abuses where we may find the protected users being impersonated during delegation abuse and the tickets lifetimes don't match what one expects. 

**Where the IoC exists**  
Decode AS-REQ `req-body.till` and `req-body.rtime`. Alert when both are equal or nearly equal and are approximately 24 hours after the request timestamp. Raise confidence when the same request also has sparse encryption type negotiation.

**Relevant code**

`impacket/krb5/kerberosv5.py:158-160`

```python

now = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)

reqBody['till'] = KerberosTime.to_asn1(now)

reqBody['rtime'] = KerberosTime.to_asn1(now)

```

The pre-authenticated rebuild repeats the same behavior at `impacket/krb5/kerberosv5.py:315-317`.

<a id="ioc-03"></a>

### IoC 03 - Sparse/Mismatched AS-REQ encryption type lists
**Surface:** Kerberos AS-REQ network telemetry
  
Impacket often sends unusually sparse encryption type lists. With a password and no NT hash it initially asks for AES256 only. With NT hash material it asks for RC4 only. This differs from broader Windows client etype lists.

**How to find it**

Alert or enrich AS-REQs where the `etype` list is a singleton:
- `aes256-cts-hmac-sha1-96` only
- `rc4-hmac` only

Correlate with a follow-on retry after `KDC_ERR_ETYPE_NOSUPP`.  

We can see how Impacket makes the first offer:
![Pasted image 20260430182245](images/Pasted%20image%2020260430182245.png)

Comparing that from our Windows client performing the AS-REQ, the etypes list has 6 entries:

![Pasted image 20260430182342](images/Pasted%20image%2020260430182342.png)

As noted earlier, unlike Impacket, real Windows clients also send the Address/HostAddress sub fields within the AS-REQ. 
**Where the IoC exists**

`impacket/krb5/kerberosv5.py:167-185`

```python

if nthash == b'':

    ...

    supportedCiphers = (int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),)

else:

    supportedCiphers = (int(constants.EncryptionTypes.rc4_hmac.value),)

seq_set_iter(reqBody, 'etype', supportedCiphers)

```


This is obviously incredibly out of the ordinary and for 99.7% of detection engineers workplaces; it is almost improbable that there's ever a Kerberos attempt only sending AES 256 keys and then only sending RC4 keys. If there is, I'm certain they are trivially excluded/made an exception for.

<a id="ioc-04"></a>

### IoC 04 - `GetNPUsers.py` AS-REP roast request starts RC4-only, then retries AES
**Surface:** Kerberos AS-REQ/KDC error telemetry

`GetNPUsers.py` initially requests only RC4 for roastable users. If the KDC rejects that with `KDC_ERR_ETYPE_NOSUPP`, it resends with AES256 and AES128. That two-step downgrade/upgrade pattern is a strong tool fingerprint.

**How to find it**

Look for the same client and target account sending:

1. AS-REQ with no encrypted timestamp and `etype = [rc4-hmac]`

2. KDC returns `KDC_ERR_ETYPE_NOSUPP`

3. Immediate AS-REQ retry with `etype = [aes256, aes128]`

**Relevant code**  

`examples/GetNPUsers.py:146-160`

```python

supportedCiphers = (int(constants.EncryptionTypes.rc4_hmac.value),)

seq_set_iter(reqBody, 'etype', supportedCiphers)

...

supportedCiphers = (int(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value),

                    int(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value),)

```

<a id="ioc-05"></a>

### IoC 05 - Generic TGS-REQ etype ordering: RC4, DES3, DES, then current cipher
**Surface:** Kerberos TGS-REQ network telemetry

For standard TGS requests, Impacket orders requested service-ticket encryption types as RC4, DES3, DES-CBC-MD5, and finally the current ticket cipher. That order is unusual in modern Windows environments and is useful when DES is disabled in policy but still appears in client request preferences. This is also confounded by the fact that rc4 as of April 2025 has now also been deprecated. It is also straightforward to detect the exact order of the encryption types. 

We can see this on a target system in which there's a mismatch between what Impacket sent and what the Windows client sent. This is what Impacket sent within a TGS-REQ packet:

![Pasted image 20260430181457](images/Pasted%20image%2020260430181457.png)

Additionally, if we end up going for ARCFOUR-HMAC-MD5, Impacket sets in a way that it will appear twice in the list :) even though a Windows client never adds duplicate enctypes in the etype subfield. 

With the predicable/standard ENCTYPES with the bottom one being the supported one. Now looking at the same Windows server and we see different and one more enctype being offered:

![Pasted image 20260430181751](images/Pasted%20image%2020260430181751.png)

**How to find it**

Decode TGS-REQ `etype` and alert when it contains this order:

- `rc4-hmac`

- `des3-cbc-sha1-kd`

- `des-cbc-md5`

- the client's current ticket/session cipher

**Relevant code**

`impacket/krb5/kerberosv5.py:445-451`

```python

seq_set_iter(reqBody, 'etype',

    (

        int(constants.EncryptionTypes.rc4_hmac.value),

        int(constants.EncryptionTypes.des3_cbc_sha1_kd.value),

        int(constants.EncryptionTypes.des_cbc_md5.value),

        int(cipher.enctype)

    )

)

```

<a id="ioc-06"></a>

### IoC 06 - S4U2Proxy TGS-REQ always adds RBCD `PA-PAC-OPTIONS`
**Surface:** Kerberos TGS-REQ network telemetry

`getST.py` adds `PA-PAC-OPTIONS` with the `resource_based_constrained_delegation` bit when constructing S4U2Proxy requests. This is a strong Impacket S4U/RBCD indicator when observed with `additional-tickets`.

**How to find it**

Decode TGS-REQ padata and request body. Alert when:

- `PA-TGS-REQ` is present

- `PA-PAC-OPTIONS` is present

- PAC option `resource_based_constrained_delegation` is set

- `additional-tickets` is populated

**Relevant code**

`examples/getST.py:322-339`

```python

paPacOptions = PA_PAC_OPTIONS()

paPacOptions['flags'] = constants.encodeFlags((constants.PAPacOptions.resource_based_constrained_delegation.value,))

...

opts.append(constants.KDCOptions.cname_in_addl_tkt.value)

opts.append(constants.KDCOptions.canonicalize.value)

opts.append(constants.KDCOptions.forwardable.value)

opts.append(constants.KDCOptions.renewable.value)

```

The same construction appears again at `examples/getST.py:738-755`.

<a id="ioc-07"></a>

### IoC 07 - Kerberos AP-REQ body differences in LDAP SASL bind
**Surface:** Kerberos AP-REQ body within LDAP/DC SASL facilitated bind

When using Kerberos protocol to authenticate to a domain controller, Impacket and the standard Windows server will use SPNEGO to negotiate the actual authentication exchange between them. The bind contains the `AP-REQ` that contains the relevant Kerberos authentication material.  A standard Windows client will set the `ap-options: 20000000` which indicates that [mutual authentication](https://learn.microsoft.com/en-us/windows/win32/ad/about-mutual-authentication-using-kerberos) is required. Conversely Impacket sets it to `ap-options: 0000000`. 

Secondly is that Impacket, in the `sname` section, only ever fills out two items, while Windows clients will often fill out three. The difference comes to the sub `SNameString` values where the Windows client adds the service name, LDAP in full caps, the FQDN of the DC as well as the domain name. Impacket adds the service name is lowercase(ldap) as well as omitting the domain name. 

We can see both differences by first looking at the ap-req from our Windows server:

![Pasted image 20260430173651](images/Pasted%20image%2020260430173651.png)

And now from Impacket:

![Pasted image 20260430173737](images/Pasted%20image%2020260430173737.png)

As we can see the gaps between the two. I am not sure if the differences appear in other contexts when binding to other services but this appears to be consistent when using Impacket to bind to a domain controller.  I have been able to confirm that when using DCE/RPC, we do see the Mutual-Required flag being set within our bind request.

I also observed the differences in TGS-REQ packets in which the Sname-string entries are three for a standard Windows client but 2 for Impacket with the missing domain name alongside the service and host FQDN

<a id="ioc-08"></a>

### IoC 08 - Impacket TGS-REQ does not carry PA-DATA PA-PAC-OPTIONS
When Impacket performs sends a TGS-REQ packet, it does so with only one item in the padata field instead of 2. Impacket does not include the `PA-DATA pA-PAC-OPTIONS` field in the ticket, which a standard Windows client does. 

Looking here, we can see that Impacket does not set this field:
![Pasted image 20260430175639](images/Pasted%20image%2020260430175639.png)

Whereas referring to our Windows client, we can see that the field is present as well as the value `branch-aware: True` is set:

![Pasted image 20260430175742](images/Pasted%20image%2020260430175742.png)

We can see from the following section in Microsoft's [MS-KILE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/2c42487d-2572-4090-999d-0a2d73d8c946) that the `pA-PAC-OPTIONS` field is expected to be set by clients.

<a id="ioc-26"></a>

### IoC 26 - `ticketer.py` forged tickets default to a 10-year lifetime with `endtime == renew-till`
**Surface:** Kerberos ticket inspection, service-side PAC/ticket validation logs where decrypted, endpoint ticket cache forensics

When forging tickets from scratch, `ticketer.py` defaults `-duration` to `87600` hours, which is 10 years. It then sets both `endtime` and `renew-till` to that same timestamp.

**Expected / proper baseline**

Microsoft's default Kerberos policy is 10 hours for "Maximum lifetime for user ticket" and 7 days for "Maximum lifetime for user ticket renewal." References: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/maximum-lifetime-for-user-ticket and https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/maximum-lifetime-for-user-ticket-renewal.

**How to find it**

When tickets can be decrypted or parsed from an endpoint cache, alert on:

- `endtime` roughly 10 years after `starttime` / `authtime`

- `renew-till` equal to `endtime`

- especially for privileged users or service tickets used from nonstandard hosts  

**Relevant code**
`examples/ticketer.py:600,721-722,1129`

```python
ticketDuration = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=int(self.__options.duration))

...

encTicketPart['endtime'] = KerberosTime.to_asn1(ticketDuration)

encTicketPart['renew-till'] = KerberosTime.to_asn1(ticketDuration)

...

parser.add_argument('-duration', action="store", default = '87600', ...)
```

  This is probably one of the weaker detections on the list. It is trivial to change in the Impacket code base, but it can still catch unmodified tooling or less careful operators. The stronger point is that it is unusual for `renew-till` and `endtime` to be the same. The main expected case is Protected Users Group membership, where both values are set to 240 minutes instead of the more common 10-hour/7-day split.

<a id="ioc-27"></a>

### IoC 27 - `ticketer.py` PAC has fixed `LogonCount = 500`, empty `LogonServer`, and default admin-heavy group RIDs
**Surface:** PAC inspection, service-side ticket validation with key access, forensic parsing of kirbi/ccache artifacts

The basic PAC generated by `ticketer.py` contains several static values that do not come from Active Directory: `LogonCount = 500`, `LogonServer = ''`, default `UserId = 500`, and group RIDs `513,512,520,518,519`.

**Expected / proper baseline**

Microsoft's PAC `KERB_VALIDATION_INFO` is authorization information provided by the DC. `LogonCount` should reflect the account's `LogonCount`, `UserId` should be the account RID, group membership should match AD, and `LogonServer` should contain the NetBIOS name of the Kerberos KDC that handled the AS request. Reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/69e86ccc-85e3-41b9-b514-7d969cd0ed73.

**How to find it**

Inspect decrypted PAC `KERB_VALIDATION_INFO` and alert on combinations such as:

- `LogonCount == 500`

- `LogonServer` empty

- `UserId == 500` for a ticket whose `cname` is not actually the built-in Administrator

- group set exactly `[513,512,520,518,519]`. This is easy to change because it lives in the example script rather than deep in the protocol implementation, but the other fields above are stronger.

**Relevant code**

`examples/ticketer.py:185-213,1121-1122`

```python
kerbdata['LogonCount'] = 500

...

kerbdata['UserId'] = int(self.__options.user_id)

...

kerbdata['LogonServer'] = ''

...

parser.add_argument('-groups', action="store", default = '513, 512, 520, 518, 519', ...)
```

As we can see above, since there's the ability for an operator to specify the groups, it isn't a very strong detection. However, detecting the difference between that and the UserId value is pretty powerful and surefire way to detect Impacket's ticketer.py.

<a id="ioc-28"></a>

### IoC 28 - `ticketer.py` writes KDC reply nonce `123456789` into forged EncRepPart
**Surface:** Ticket cache / kirbi / ccache forensic parsing, decrypted EncASRepPart or EncTGSRepPart

The forged reply structure created by `ticketer.py` uses a constant nonce of `123456789`. This like other elements in the encrypted PAC, aren't detectable over the network. Since all my research was done in a lab environment, I extracted the krbtgt aes 256 key and used it to create a keytab file to import to wireshark to allow me to decrypt the relevant attributes.

**Expected / proper baseline**

Kerberos replies should contain the nonce from the matching request. RFC 4120 says the client-generated nonce is used to associate replies with requests, must be random, and must not be reused. Reference: https://datatracker.ietf.org/doc/html/rfc4120. That value is neither random nor RFC compliant : D

**How to find it**

alert if the decrypted `EncKDCRepPart.nonce` is decimal `123456789` (`0x075bcd15`). This is pretty much I mean a guaranteed hit since following the spec would lead to the generation of more "random" uniqueness. 

**Relevant code**  

`examples/ticketer.py:840-845`  

```python

encRepPart['last-req'][0]['lr-type'] = 0

encRepPart['last-req'][0]['lr-value'] = KerberosTime.to_asn1(datetime.datetime.now(datetime.timezone.utc))

encRepPart['nonce'] = 123456789

encRepPart['key-expiration'] = KerberosTime.to_asn1(ticketDuration)

```

<a id="ioc-29"></a>

### IoC 29 - `raiseChild.py` forged parent access injects Enterprise Admin SID `-519` as an ExtraSid
**Surface:** PAC inspection, cross-domain Kerberos ticket validation, privileged access investigations

`raiseChild.py` abuses child-to-parent trust by adding the parent forest Enterprise Admins SID as an ExtraSid and replacing the ticket's group list with the same "golden" group set used elsewhere: `513,512,520,518,519`.

**Expected / proper baseline**

Cross-domain SIDs and ExtraSids can exist legitimately, but a child-domain principal presenting an ExtraSid ending in `-519` for Enterprise Admins should be rare and highly privileged. Microsoft PAC documentation says `ExtraSids` contains SIDs for groups outside the account domain, and `SidCount`/`UserFlags` must reflect its presence. Reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/69e86ccc-85e3-41b9-b514-7d969cd0ed73.

**How to find it**

The PAC would contain the following that one can alert on:
- account realm is a child domain

- `ExtraSids` contains parent forest SID ending in `-519`

- group list is exactly `513,512,520,518,519`

- `UserFlags` has the ExtraSids bit set

**Relevant code**

`examples/raiseChild.py:942-972,1151-1153`
  
```python
groups = (513, 512, 520, 518, 519)

...

validationInfo['Data']['UserFlags'] |= 0x20

...

validationInfo['Data']['ExtraSids'].append(sidRecord)

...

goldenTicket, cipher, sessionKey = self.makeGolden(..., entepriseSid + '-519')
```

<a id="ioc-37"></a>

### IoC 37 - Kerberos SPNEGO advertises the legacy Microsoft Kerberos OID but wraps the AP-REQ with the standard Kerberos OID
**Surface:** SMB2/3 SessionSetup, DCE/RPC bind auth token, SPNEGO token captures

In several Kerberos-over-SPNEGO paths, Impacket sets the SPNEGO `mechTypes` list to only the legacy/truncated Microsoft Kerberos OID `1.2.840.48018.1.2.2`, but then wraps the optimistic mechanism token with the standard Kerberos OID `1.2.840.113554.1.2.2`. That mixed "outer Microsoft OID, inner standard OID" pattern is a neat protocol fingerprint.
  
**Expected / proper baseline**  

MS-SPNG says implementations should use the standard Kerberos OID `1.2.840.113554.1.2.2` for Kerberos mechType identification, while Windows also accepts the historical truncated OID for compatibility. Reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/f663e38f-f4c8-4ed8-9bfe-51772e667116. The thing that we are detecting here is the mismatch between the advertised value and what's being wrapped. We can see the behavior as such here:

![Pasted image 20260429172128](images/Pasted%20image%2020260429172128.png)

- **`mechTypes` List:** Advertises **only** the legacy Microsoft Kerberos OID.
    - `MechType: 1.2.840.48018.1.2.2` (MS KRB5 - Legacy)

Now interestingly, because of IoC 33, we can't actually see the mismatch in OIDs in this specific capture.  Due to our next finding, we know there is no GSS-API wrapper at all due to the spec violations. The raw Kerberos `AP-REQ` inside does not contain an OID in this context however other Impacket paths that would otherwise have this included would bubble up this mismatch.

And then now comparing with a LDAP bind against the DC from our Windows Server:

![Pasted image 20260429172541](images/Pasted%20image%2020260429172541.png)

- **`mechTypes` List:** Advertises **both** the legacy and standard OIDs.
    - `MechType: 1.2.840.48018.1.2.2` (MS KRB5 - Legacy)
    - `MechType: 1.2.840.113554.1.2.2` (KRB5 - Standard)

**How to find it**

 Inspecting the SPNEGO `NegTokenInit` and noting when:  

- `mechTypes` contains only `1.2.840.48018.1.2.2`

- optimistic `mechToken` is a Kerberos initial context token carrying OID `1.2.840.113554.1.2.2`

- no NEGOEX or NTLM OID is offered in the same `mechTypes` list

**Relevant code**  

`impacket/krb5/kerberosv5.py:627,676-677` and `impacket/smb3.py:782,824-825`
  
```python
blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]

...

blob['MechToken'] = struct.pack('B', ASN1_AID) + asn1encode(

    struct.pack('B', ASN1_OID) + asn1encode(TypesMech['KRB5 - Kerberos 5']) +

    KRB5_AP_REQ + encoder.encode(apReq))
```

<a id="ioc-38"></a>

### IoC 38 - LDAP Kerberos bind sends raw `AP-REQ` as the SPNEGO mechToken
**Surface:** LDAP SASL `GSS-SPNEGO` bind packet capture

The helper used by Impacket's LDAP examples builds a SPNEGO `NegTokenInit`, advertises Kerberos, but places a raw ASN.1 `AP-REQ` directly into `mechToken` instead of a Kerberos GSS initial context token. On the wire, the SPNEGO `mechToken` begins with the Kerberos AP-REQ application tag instead of the GSS initial-context framing and Kerberos token ID.  

**Expected / proper baseline**

RFC 4121 defines Kerberos GSS initial context tokens with token IDs such as `KRB_AP_REQ` (`01 00`) and describes the Kerberos mechanism token format used inside GSS-API. Reference: https://www.rfc-editor.org/rfc/rfc4121.

Looking at the Windows server:

![Pasted image 20260429173639](images/Pasted%20image%2020260429173639.png)

The `mechToken` starts with `60 82 06 e2...`

- `0x60` is the ASN.1 tag for `[APPLICATION 0]`, which is the GSS-API framing wrapper defined in RFC 4121 that we noted above.
- Wireshark correctly parses this as a `GSS-API Generic Security Service Application Program Interface` token. It identifies the `KRB5 OID` inside, and then the `krb5_tok_id: KRB5_AP_REQ (0x0001)`, which is the correct inner token identifier.

 Lets now turn to looking at the Impacket bind:

![Pasted image 20260429173823](images/Pasted%20image%2020260429173823.png)
The `mechToken` starts with `6e 82 05 8c...:`

- `0x6E` is the ASN.1 application tag for a raw Kerberos `AP-REQ` message itself.
- Wireshark's GSS-API/SPNEGO dissector is not expecting this. It fails to find the expected GSS-API framing, so it doesn't identify a `KRB5 OID` or a `krb5_tok_id`. It just hands the raw blob to the Kerberos dissector.

For a side by side comparison without the decoding colour scheme. This is how it looks like for our Windows server:

```
Simple Protected Negotiation
    negTokenInit
        mechToken: 608206e2...
        krb5_blob: 608206e2...
            KRB5 OID: 1.2.840.113554.1.2.2 (KRB5 - Kerberos 5) <-- Parsed correctly
            krb5_tok_id: KRB5_AP_REQ (0x0001)                  <-- Parsed correctly
            Kerberos
                ap-req
                    pvno: 5
                    msg-type: krb-ap-req (14)
                    ...
```

And then with our Impacket capture, it looks like this:

```
Simple Protected Negotiation
    negTokenInit
        mechToken: 6e82058c...
        krb5_blob: 6e82058c...
            Kerberos                           <-- No GSS-API framing found
                ap-req                         <-- Raw Kerberos message
                Missing keytype 18 usage 2...  <-- Dissector fails due to spec violation
```

Gave me a bit of a chuckle when I went down this rabbit hole and finally clicked once I consulted with the Impacket source code. 

TLDR: Impacket places a raw Kerberos `AP-REQ` (noticeable as tag `0x6E`) directly into the SPNEGO `mechToken`, instead of the required GSS-API initial context token (noticeable as tag `0x60`) which contains the `AP-REQ` inside.

**How to find it**

For LDAP `bindRequest` with mechanism `GSS-SPNEGO`, decode the SPNEGO token and alert when:

- `mechTypes` contains Kerberos with legacy OID only(`1.2.840.48018.1.2.2 MS KRB5`)

- `mechToken` starts as a raw Kerberos `AP-REQ` rather than a GSS initial context token

- the same client/tool then performs LDAP add/modify/search operations

This is a very effective fingerprint for Impacket LDAP activity over kerberos authentication. In fact I might think this is one of the most powerful detections I have found.

**Relevant code**

`impacket/examples/utils.py:155-197`

```python

blob = SPNEGO_NegTokenInit()

blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]

...

blob['MechToken'] = encoder.encode(apReq)
  

request = ldap3.operation.bind.bind_operation(connection.version, ldap3.SASL, user, None, 'GSS-SPNEGO', blob.getData())

```

<a id="ioc-39"></a>

### IoC 39 - SMB/LDAP Kerberos AP-REQ authenticators omit the RFC 4121 checksum and sequence number
**Surface:** Decrypted Kerberos AP-REQ authenticator, service-side instrumentation, lab packet decryption with service key

For SMB3 Kerberos and the LDAP Kerberos helper, Impacket builds the AP-REQ authenticator with only `authenticator-vno`, `crealm`, `cname`, `cusec`, and `ctime`. It omits the GSS-API checksum type `0x8003` and omits the authenticator sequence number. Interestingly, Impacket's DCE/RPC Kerberos path does add those fields, making the omission in the SMB/LDAP paths a lot more obvious in context.

**Expected / proper baseline**

RFC 4121 says the authenticator in a Kerberos GSS `KRB_AP_REQ` must include the checksum field and optional sequence number, and the checksum type must be `0x8003`. The checksum carries flags, channel bindings, and delegation data. Reference: https://www.rfc-editor.org/rfc/rfc4121.

**How to find it**

When checking the decrypted AP-REQ authenticators for SMB/LDAP and noting when:

- `cksum` is absent

- `seq-number` is absent(note technically this is optional but Windows has it)

- the AP-REQ arrived inside SPNEGO for SMB SessionSetup or LDAP bind

This is a GSS wrapping quirk in specific Impacket code paths that provide a really good/robust catch all detection on a large swatch of Impacket activity. 

**Relevant code**

`impacket/smb3.py:804-813` and `impacket/examples/utils.py:174-183`

```python
authenticator = Authenticator()

authenticator['authenticator-vno'] = 5

authenticator['crealm'] = domain

seq_set(authenticator, 'cname', userName.components_to_asn1)

...

authenticator['cusec'] = now.microsecond

authenticator['ctime'] = KerberosTime.to_asn1(now)

  

encodedAuthenticator = encoder.encode(authenticator)
```

The DCE/RPC Kerberos path does set `cksumtype = 0x8003` and `seq-number = 0` at `impacket/krb5/kerberosv5.py:654-663`, so this detection should be scoped to SMB/LDAP Kerberos AP-REQs.

<a id="cat-smb"></a>

## SMB

<a id="ioc-09"></a>

### IoC 09 - SMB2/3 client uses ASCII-letter `ClientGuid`
**Surface:** SMB2 NEGOTIATE request

Impacket generates the SMB2 client GUID as 16 bytes ASCII letters. Native Windows SMB clients use binary GUID entropy, so an all-letter GUID is a strong client fingerprint that is reasonable to pick up among the pile of others.

**How to find it**

Analyze the SMB2/3 NEGOTIATE and alert when:

- `ClientGuid` is 16 bytes long

- every byte is ASCII `[A-Za-z]`

**Relevant code**

`impacket/smb3.py:197`
```python

self.ClientGuid = ''.join([random.choice(string.ascii_letters) for i in range(16)])

```

This can be seen in the screenshot provided for IoC 7, where we can see the difference in clientGUIDs between the two. 

Engineers may potentially be able to use regex to extract clientGUIDs and somehow be able to run them against a check. I would tag this as a medium level detection but a simple bash command such as this would be a good-ish base:

```bash
echo "$clientGUID" | tr -d '-' | xxd -r -p | xdd
```

You will then end up noticing that the output is just a bunch of letters :)

<a id="ioc-10"></a>

### IoC 10 - SMB2/3 negotiate request contains multiple omissions compared to Windows
**Surface:** SMB2/3 NEGOTIATE request

When no preferred dialect is forced, Impacket offers SMB dialects in a fixed ascending order and uses `0xff` bytes as negotiate-context padding. For SMB 3.1.1, it also generates a 32-byte pre-auth salt from ASCII letters. 

Additionally, Impacket offers only one Capability compared to the expected 7 and 2 `NegotiateContextCount` as opposed to the expected 6. Under the Impacket proposed encryption capability, it only offers one cipher algorithm, AES-128-CCM whereas a standard Windows server would offer 4(AES-126/254 as well as CCM/GCM).

In combination, these offer good, early network level detections for any Impacket tool that depends on using the Impacket SMB protocol implementation

![Pasted image 20260429115809](images/Pasted%20image%2020260429115809.png)
The above image is from a Windows 2022 server client initiating a SMB2 negotiate request. 

When looking at the Capabilities field, our Server 2022 is stating it can support 7. Note that it states it doesn't support Notification sending hence why we see 8 values but only set/offer 7. 

The value `0x0000007f` in the Capabilities field of an SMB2 Negotiate request is a **combination** (bitwise OR) of multiple flags. Breaking it down, `0x0000007f` in hex = `0x7f` = `01111111` in binary (lowest 7 bits set).

That means flags 0 through 6 are all set (bits 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40). Which matches the 7 we determined the Windows Server 2022 is offering.

We can then analyze these in table form for easier understanding and see that:

| Hex Value    | Flag Name                            | Meaning                          |
| ------------ | ------------------------------------ | -------------------------------- |
| `0x00000001` | `SMB2_GLOBAL_CAP_DFS`                | Supports Distributed File System |
| `0x00000002` | `SMB2_GLOBAL_CAP_LEASING`            | Supports OpLock Leasing          |
| `0x00000004` | `SMB2_GLOBAL_CAP_LARGE_MTU`          | Supports large MTU               |
| `0x00000008` | `SMB2_GLOBAL_CAP_MULTI_CHANNEL`      | Supports Multi-Channel           |
| `0x00000010` | `SMB2_GLOBAL_CAP_PERSISTENT_HANDLES` | Supports persistent handles      |
| `0x00000020` | `SMB2_GLOBAL_CAP_DIRECTORY_LEASING`  | Supports directory leasing       |
| `0x00000040` | `SMB2_GLOBAL_CAP_ENCRYPTION`         | Supports SMB 3.0 encryption      |

Now looking at the same from Impacket, triggered by using impacket-smbclient:
![Pasted image 20260429115940](images/Pasted%20image%2020260429115940.png)

The value `0x00000040` in the Capabilities field of an SMB2 Negotiate request is the `SMB2_GLOBAL_CAP_ENCRYPTION` flag, as noted from the table above. 

Focusing in on the two "Negotiate Context" values, Impacket only offers two encryption algorithms:
![Pasted image 20260429120045](images/Pasted%20image%2020260429120045.png)

also noting that the salt provided above by Impacket is 32 byte ASCII letters, which you may confirm using the previously provided bash command, compared with the expected Microsoft one seen below which is not limited to letters. 
Whereas in comparison to the Windows 2022 server, we see that 4 ciphers are offered by the system:
![Pasted image 20260429120151](images/Pasted%20image%2020260429120151.png)

**How to find it**

Analyzing a SMB2 NEGOTIATE request for if it has:

- Pre-auth salt of length 32 where all bytes are ASCII `[A-Za-z]`

- Negotiate-context padding bytes equal to `ff`

- Client capabilities only `SMB2_GLOBAL_CAP_ENCRYPTION`

- Client encryption cipherID offered are only that of AES-128 CCM

**Relevant code**

`impacket/smb3.py:581-588`

```python
negSession['Capabilities'] = self._Connection['Capabilities']

negSession['ClientGuid'] = self.ClientGuid

negSession['Dialects'] = [SMB2_DIALECT_002, SMB2_DIALECT_21, SMB2_DIALECT_30, SMB2_DIALECT_302, SMB2_DIALECT_311]

```

`impacket/smb3.py:607-617`

```python
preAuthIntegrityCapabilities['SaltLength'] = 32

preAuthIntegrityCapabilities['Salt'] = ''.join([rand.choice(string.ascii_letters) for _ in range(...)]

pad = b'\xFF' * ((8 - (negotiateContext['DataLength'] % 8)) % 8)
```

<a id="ioc-11"></a>

### IoC 11 - SMB1 client negotiate offers only `NT LM 0.12`
NOTE: Take the following indication with a pinch of salt as it may be an incorrect assumption from my end. 

**Surface:** SMB1 NEGOTIATE request  

Impacket's SMB1 client sends only the `NT LM 0.12` dialect. Older Windows stacks usually offered multiple dialect strings. In most of your environment's, an SMBv1 client connection only offering a single-dialect `NT LM 0.12` request would otherwise be unique unless an application developer manually developed such that the SMB1 system will only be offered `NT LM 0.12`. Using the following [source](https://argonsys.com/microsoft-cloud/library/smb-is-dead-long-live-smb/), we see that the dialects otherwise offered for a SMBv1 requesting system:

```
Dialect: PC NETWORK PROGRAM 1.0 <<<<<< These are all the old SMB1 dialects Dialect: LANMAN1.0 
Dialect: Windows for Workgroups 3.1a 
Dialect: LM1.2X002 
Dialect: LANMAN2.1 
Dialect: NT LM 0.12
```

**How to find it**

Alert on SMB1 negotiate requests where the dialect array contains only a single entry of:

- `NT LM 0.12`
- session setup `NativeOS = Unix` and `NativeLanMan = Samba`

With the later session setup having `NativeOS = Unix` and `NativeLanMan = Samba`. This interestingly enough is mentioned in the code base where the developer intentionally uses the above hoping to not be signatured. 

**Relevant code**

`impacket/smb.py:2998-3007`


```python
negSession = SMBCommand(SMB.SMB_COM_NEGOTIATE)

...

negSession['Data'] = b'\x02NT LM 0.12\x00'

```

`impacket/smb.py:3566-3569`

```python
sessionSetup['Data']['NativeOS']      = 'Unix'

sessionSetup['Data']['NativeLanMan']  = 'Samba'
```

<a id="cat-ntlm-and-spnego"></a>

## NTLM and SPNEGO

<a id="ioc-12"></a>

### IoC 12 - NTLM implementation omissions in various fields
**Surface:** NTLMSSP over SMB, HTTP, LDAP, RPC

Impacket's Type 1 builder for NTLM does not offer/send a NTLM version, whereas the real/expected flow does pass appropriate NTLM version on first attempt. 

We can see this done here, where the following is a connection from a Server 2022:

![Pasted image 20260429130721](images/Pasted%20image%2020260429130721.png)

Comparing that with Impacket's smbclient connecting to the same host(domain controller), we see that there's no version being passed in the type one message:

![Pasted image 20260429130823](images/Pasted%20image%2020260429130823.png)

Exploring now the NTLM_AUTH Message type(Message Type 3), we can see other differences/gaps between Impacket and the Windows client.  The first of which that is detectable without requiring decoding is the absence of a `mechListMIC` as well as a `NTLMSSP Verifier` Structure. Looking at the type 3 NTLM message from impacket-smbclient:

![Pasted image 20260429131917](images/Pasted%20image%2020260429131917.png)

Now comparing that with our Windows Server:

![Pasted image 20260429132004](images/Pasted%20image%2020260429132004.png)

As we can see, we have a `NTLMSSP Verifier` Value as well as the `mechListMIC` value that the Impacket type 3 NTLM message lacks. Something to also note is that I have no answer for is that even though both systems connected to the DC, enforcing signing; the Impacket message states `Signing Enabled` whereas the Windows server type 3 message states `Signing required`. Both my Windows server and the impacket-smbclient connected to a Server 2022 DC enforcing SMB signing.

Another difference is the setting of the Lan Manager Response. We can see Impacket sets a value, as well as having an absent LanV2 Manager Response value:

![Pasted image 20260429131458](images/Pasted%20image%2020260429131458.png)

Now we can compare that instead with the real/expected behavior:

![Pasted image 20260429132302](images/Pasted%20image%2020260429132302.png)

Finally, Impacket does not set a `Host Name:` value compared with a Windows client that will set its own hostname always. Noting our Windows server has the hostname SCCM, we can see here:

![Pasted image 20260429132510](images/Pasted%20image%2020260429132510.png)

Whereas our Impacket message does not set one:

![Pasted image 20260429132540](images/Pasted%20image%2020260429132540.png)

An extra detection we can bake into this is if an adversary was to try to be more stealthy by adding a hostname, we can add a detection to ensure that the IP address initiating the type 3 message, matches the entry in its hostname. 

Some systems, such as older Linux servers, *may* not do this. In those cases, it may be practical to maintain an allowlist of known systems that cannot populate this field and let Type 3 messages from those systems pass without issue.

**How to find it**

Observe NTLM messages when:

- `NEGOTIATE_VERSION` is absent unless a caller explicitly passed a version in type 1 messages
- `Host Name` is NULL in type 3 messages(noting the previously mentioned caveats)
- Lan Manager Response with no LanV2 Challenge Response in type 3 messages
- Absent `mechListMIC` value as well as `NTLMSSP Verifier` field in type 3 messages

**Relevant code**

`impacket/ntlm.py:622-628`

  
```python

if version is not None:

    auth['flags'] |= NTLMSSP_NEGOTIATE_VERSION

    auth['os_version'] = version
```

<a id="ioc-20"></a>

### IoC 20 - `ntlmrelayx` LDAP computer creation: 8 uppercase letters plus `$`
**Surface:** LDAP add, AD object creation, DC logs
  
Considering how generally rare new domain computer editions are, Im confident that this won't be tripping up any false positives as in most orgs, letters and numbers are used when creating computers/servers. When `ntlmrelayx` creates a computer through LDAP and no name/password is supplied, it generates an eight-letter uppercase computer name ending in `$`, sets `userAccountControl` to `4096`, and populates only HOST and RestrictedKrbHost SPNs.

**How to find it**  

Alert on computer object creation where:

- `sAMAccountName` matches `^[A-Z]{8}\$$`

- `userAccountControl = 4096`

- `servicePrincipalName` contains only HOST and RestrictedKrbHost variants for short and FQDN hostnames

- creation occurs over LDAPS or StartTLS from a non-DC host

**Relevant code**

`impacket/examples/ntlmrelayx/attacks/ldapattack.py:147-176`

```python
newComputer = (''.join(random.choice(string.ascii_letters) for _ in range(8)) + '$').upper()

newPassword = ''.join(random.choice(string.ascii_letters + string.digits + '.,;:!$-_+/*(){}#@<>^') for _ in range(15))

...

'userAccountControl': 4096,

'servicePrincipalName': spns,

'sAMAccountName': newComputer,
```

<a id="ioc-21"></a>

### IoC 21 - `ntlmrelayx` DNS WPAD bypass creates 12-letter random A record first
**Surface:** AD-integrated DNS LDAP modifications

When adding `wpad`, `ntlmrelayx` first creates a random 12-letter lowercase A record to bypass the Global Query Block List, then points `wpad` as an NS record at that random name.

**How to find it**

Monitor AD-integrated DNS writes and alert when:

- a random lowercase 12-character DNS node is created

- shortly followed by a `wpad` NS record pointing at that node

- `nTSecurityDescriptor` grants broad Everyone rights on the DNS node

**Relevant code**

`impacket/examples/ntlmrelayx/attacks/ldapattack.py:863-875`

```python

if is_name_wpad:

    a_record_name = ''.join(random.choice(string.ascii_lowercase) for _ in range(12))

...

'dnsRecord': new_dns_record(ipaddr, "A"),

'name': a_record_name,

'nTSecurityDescriptor': ACL_ALLOW_EVERYONE_EVERYTHING,
```

<a id="ioc-41"></a>

### IoC 41 - NTLMv2 client challenge is eight printable alphanumeric bytes
**Surface:** NTLM AUTHENTICATE_MESSAGE, NTLMv2_RESPONSE, LMv2 response in SMB/LDAP/HTTP/RPC captures
  
Impacket generates the NTLMv2 `ChallengeFromClient` using Python `random.choice` over digits and ASCII letters. That means the 8-byte client nonce is always printable alphanumeric (`[0-9A-Za-z]{8}`), not arbitrary random bytes. The same 8 bytes are visible at the end of the LMv2 response and inside the NTLMv2 client challenge blob.
  
**Expected / proper baseline**

MS-NLMP defines `ChallengeFromClient` as an 8-byte client nonce in the NTLMv2 client challenge. Microsoft defines it as an 8-byte nonce, not a printable string like the way Impacket has done(which is actually a recurring theme). References: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/aee311d6-21a7-4470-92a5-c4ecb022a87b and https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/c0250a97-2940-40c7-82fb-20d208c71e96.

Looking at Impacket's `NTLM Client Challenge` in a type 3 message packet:

![Pasted image 20260429134054](images/Pasted%20image%2020260429134054.png)

Now comparing that back to our Windows server:

![Pasted image 20260429134144](images/Pasted%20image%2020260429134144.png)

Comparing the two using bash, we can see that the one sent by Impacket printable ASCII characters whereas the one sent by Windows is non printable bytes present:

```bash
┌──(kali㉿kali)-[~/personalprojects/blogs/hunting-impacket]
└─$ echo "3772757646657869" | xxd -r -p | xxd
00000000: 3772 7576 4665 7869                      7ruvFexi                                                   
┌──(kali㉿kali)-[~/personalprojects/blogs/hunting-impacket]
└─$ echo "2a851c6113830858" | xxd -r -p | xxd
00000000: 2a85 1c61 1383 0858                      *..a...X

┌──(kali㉿kali)-[~/personalprojects/blogs/hunting-impacket]
└─$ diff <(echo "3772757646657869" | xxd -r -p | xxd) <(echo "2a851c6113830858" | xxd -r -p | xxd)
1c1
< 00000000: 3772 7576 4665 7869                      7ruvFexi
---
> 00000000: 2a85 1c61 1383 0858                      *..a...X
```

**How to find it**

Decode NTLM Type 3 / AUTHENTICATE messages and alert when:

- `NTLMv2_CLIENT_CHALLENGE.ChallengeFromClient` matches `^[A-Za-z0-9]{8}$`

- or Lan Manager Response bytes 16-23 match `^[A-Za-z0-9]{8}$`

- Absent LMV2 client challenge Field

Note that the Lan Manager Response also uses `Offset: 128` in the Windows capture, whereas Impacket uses `108`; both show `Length/MaxLen = 24`. I am not sure whether this is caused by one client sending a value while the other does not, but I am including it in case readers have additional context. 

**Relevant code**

`impacket/ntlm.py:665,704,975-976`  

```python

clientChallenge = b("".join([random.choice(string.digits+string.ascii_letters) for _ in range(8)]))

...

exportedSessionKey = b("".join([random.choice(string.digits+string.ascii_letters) for _ in range(16)]))

...

temp += clientChallenge # ChallengeFromClient 8 bytes

lmChallengeResponse = hmac_md5(responseKeyNT, serverChallenge + clientChallenge) + clientChallenge
```

<a id="ioc-42"></a>

### IoC 42 - LDAP Sicily NTLM binds stamp `MsvAvTargetName` as `cifs/<dc-host>` instead of LDAP
**Surface:** LDAP NTLM bind packet capture, NTLMv2 client challenge AV pairs

In the LDAP "Sicily" NTLM bind path, Impacket calls `getNTLMSSPType3()` without a `service` argument, so the NTLMv2 target SPN AV pair defaults to `cifs/<server DNS hostname>`. The SASL GSS-SPNEGO LDAP path correctly passes `service='ldap'`, which makes the difference between Impacket LDAP auth paths a more accurate detection.
  
**Expected / proper baseline**

MS-NLMP defines `MsvAvTargetName` as the SPN of the target server, encoded as Unicode. For LDAP authentication, a target SPN should be LDAP-oriented when a client supplies one. Reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/83f5e789-660d-4781-8491-5f8c6641f75e.  

**How to find it**

Analyzing the NTLMv2 client challenge AV pairs during LDAP bind and seeing if:  

- application protocol is LDAP

- NTLM authentication is the Sicily bind style

- `MsvAvTargetName` starts with `cifs/`

- target host matches the LDAP/DC host

This, like other LDAP related detections are best used when being chained together. Something that might be worth nothing though is that I don't believe that Impacket performs Sicily authentication by default as it uses SASL instead. 

**Relevant code**

`impacket/ldap/ldap.py:386,432` and `impacket/ntlm.py:956`

```python
# Sicily LDAP NTLM path: no service argument, so ntlm.py defaults to service='cifs'
type3, exportedSessionKey = getNTLMSSPType3(negotiate, bytes(type2), user, password, domain, lmhash, nthash, channel_binding_value=channel_binding_value)

  

# SASL path does pass LDAP

type3, exportedSessionKey = getNTLMSSPType3(..., service='ldap', ...)

...

av_pairs[NTLMSSP_AV_TARGET_NAME] = f"{service}/".encode('utf-16le') + av_pairs[NTLMSSP_AV_DNS_HOSTNAME][1]
```

<a id="ioc-53"></a>

### IoC 53 - Authenticated DCE/RPC often uses raw NTLMSSP instead of SPNEGO
**Surface:** Authenticated DCE/RPC bind, packet capture with RPC auth decoding, RPC ETW

When using Impacket and running a packet capture, we notice that authenticated DRSUAPI, ISystemActivator, and IWbemLevel1Login binds appear with `Auth type: NTLMSSP (10)`. The Windows clients are generally expected to be using `Auth type: SPNEGO (9)` for comparable authenticated RPC activity. Note that Impacket also uses SPNEGO when we use Kerberos authentication but doesn't appear to do so at all when it comes to NTLM authentication. 

**Expected / Proper Baseline**

Windows clients often wrap Kerberos or NTLM negotiation in SPNEGO, especially for domain-authenticated RPC. Raw NTLMSSP can occur legitimately but almost exclusively reserved for older devices/systems, so this is best used as a correlation feature rather than a standalone alert. An additional context to convert it potentially into its own standalone alert is to add correlation context such as Windows version, initiator connection details etc. 

**How To Find It**

Use this as part of a cluster:

- DCE/RPC auth type is `NTLMSSP (10)` directly

- interface is DRSUAPI, ISystemActivator, IWbem, WINREG, or similar

- same client also has the 32-bit-only NDR bind shape

- `Auth Context ID == 79231`

- Other IoCs mentioned that may empower this detection or add a robust chain

<a id="ioc-54"></a>

### IoC 54 - Impacket's WMI `IWbemLevel1Login::NTLMLogin` implementation contains a spec violation and potential remote/local host contradiction
**Surface:** DCOM IWbemLevel1Login traffic, packet capture with decrypted DCE/RPC, RPC ETW with decoded WMI/DCOM parameters

Impacket's implementation of `IWbemLevel1Login::NTLMLogin` sends the namespace as `//./root/cimv2` as well as setting `WszPreferredLocale == NULL`.  Thirdly, with the namespace setting, Impacket causes a contradiction since `\\.\root\cimv2` assumes a local connection/resource access.

We can observe the way Impacket populates these fields via wmiquery.py:

![Pasted image 20260501112528](images/Pasted%20image%2020260501112528.png)

**Expected / Proper Baseline**

Windows WMI/DCOM clients normally identify the remote namespace using the remote host structure following the MS-DCOM specification(and not the Windows SDK permissibility) and provide locale information especially. 

When looking at [MS-WMI] 3.1.4.1.1:

> **"wszNetworkResource:** The string MUST represent the namespace on the server to which the returned IWbemServices object is associated. **This parameter MUST NOT be NULL and MUST match the namespace syntax as specified in section 2.2.2.**"

And from [MS-WMI] 2.2.2, the ABNF grammar:

```plain
MACHINE-PATH = BACKSLASH BACKSLASH <MACHINENAME> BACKSLASH
NAMESPACE = [STRING-IDENTIFIER] <SUB-NAMESPACE>
SUB-NAMESPACE = [ BACKSLASH <NAMESPACE> ]
```

The spec defines namespace paths using **backslashes**, not forward slashes. The `MACHINE-PATH` requires `\\<MACHINENAME>\`.
The `//./` prefix with forward slashes is consistent with the spec in context of:

- `//./` is the **Win32 device namespace prefix** (used locally for named pipes, mailslots, etc.), not a WMI namespace path
- Forward slashes (`/`) are **never** used in WMI namespace paths per spec, always backslashes (`\`)
- The dot (`.`) as server name indicates local machine, which contradicts a remote DCOM activation
We can see this here within Windows:

![Pasted image 20260501112426](images/Pasted%20image%2020260501112426.png)

Caveat is while I interpret this to be a spec violation as Windows does not do this(as per the Product Behavior appendix confirming that Windows follows MUST/SHOULD directives), the Win32 SDK documentation states:

> _"A namespace object path contains server and namespace elements, and is **formatted using either forward or backward slashes**."_

```plain
\\Server\Namespace
- or -
//Server/Namespace
```

And for local:

```plain
\\.\Namespace
```

Finally From **MS-DCOM Section 2.2.22.1** `CustomHeader`, Windows clients will fill  the `MSHCTX` [values](https://learn.microsoft.com/en-gb/windows/win32/api/wtypesbase/ne-wtypesbase-mshctx?redirectedfrom=MSDN) (like `MSHCTX_DIFFERENTMACHINE = 0x00000002`) within the `destCtx` field. This information is derived from Appendix B footnote <22> within the MS-DCOM specification:

> _"On Windows, DCOM clients set this field to MSHCTX_DIFFERENTMACHINE (0x00000002)"_

While unconfirmed and fully speculative from my end, this appears to be a mismatch because Impacket is specifying a local namespace, `//./root/cim2` while specifying that the data to be marshalled is on a different system. I may not be fully understanding the data model so feel free to correct me! 

**How To Find It**

Decode `IWbemLevel1Login::NTLMLogin` and flag:

- `WszNetworkResource == "//./root/cimv2"`

- `WszPreferredLocale == NULL`

- `destCtx == 2` while the resource specified is a local one(Take this with a pinch of salt as it is speculative in nature)

<a id="ioc-55"></a>

### IoC 55 - Impacket WMI scripts skip various exchanges before `NTLMLogin`
**Surface:** DCOM/WMI call sequence, packet capture with decrypted DCE/RPC, RPC ETW

Before proceeding, it is helpful to understand the expected authentication sequence defined in [MS-WMI 3.2.3]:

1. `RemoteCreateInstance`(CLSID_WbemLevel1Login) → returns IWbemLevel1Login IPID
2. `IRemUnknown::RemQueryInterface`(IWbemLevel1Login IPID, `IID_IWbemLoginClientID`) returns `IWbemLoginClientID` IPID (or error, which MUST be ignored)
3. `IWbemLoginClientID::SetClientInfo`(...) on that IPID
4. `IWbemLevel1Login::EstablishPosition`(...)
5. `IWbemLevel1Login::NTLMLogin`(...)

NOTE: `IRemUnknown::RemQueryInterface` and `IRemUnknown2::RemQueryInterface2` are DCOM-level calls (not WMI-specific), so they would appear as separate DCE/RPC requests with:

- **Interface UUID**: `00000131-0000-0000-c000-000000000046` (`IRemUnknown`)
- **Interface UUID**: `00000143-0000-0000-c000-000000000046` (`IRemUnknown2`)
- **Opnums**: 3 (`RemQueryInterface`), 4 (`RemAddRef`), 5 (`RemRelease`)

Now another set of fingerprinting, that confusingly kicks in from our above discussion in MS-WMI 3.2.3 takes us to [MS-DCOM Section 3.2.4.1.1]:

1. RemoteCreateInstance(CLSID_WbemLevel1Login)
   → Returns OBJREF with OXID + IPID for IWbemLevel1Login object

2. OXID resolution (IOXIDResolver)
   → Returns RPC bindings + IRemUnknown IPID for the object exporter

3. Connect to object exporter using resolved bindings
   → Bind to IRemUnknown (00000131...) or IRemUnknown2 (00000143...)

4. IRemUnknown::RemQueryInterface(IRemUnknown IPID, IID_IWbemLoginClientID)
   → Returns IPID for IWbemLoginClientID on same object exporter

5. Make ORPC calls on returned IPIDs

The Impacket WMI session setup creates `IWbemLevel1Login`, calls `NTLMLogin`, and then releases interfaces. Although Impacket contains support for some of the structures below in `wmi.py`, the behavior is easy to miss because it is nested inside the library and is not heavily documented.

Impacket using wmiexec/wmiquery is observed to not use the `SetClientInfo` to obtain the actual remote server name and PID as well as not using the `EstablishPosition` method to determine the locales that are supported between the two client/server. 

Impacket's `DCOMConnection` class maintains a "fake" object table locally and so It doesn't need to query `IRemUnknown`. Impacket then constructs ORPC calls directly using the IPID from `RemoteCreateInstance` without verifying interface availability via `RemQueryInterface`

We can see how much shorter/lighter the Impacket path is in comparison to the expected process listed by the spec:

![Pasted image 20260501134952](images/Pasted%20image%2020260501134952.png)


**Expected / Proper Baseline**

Native Windows WMI/DCOM clients are expected to perform either all or most of the above sequences. A direct `RemoteCreateInstance -> NTLMLogin` flow would not be expected to be observed between two Windows clients. 

**[MS-WMI](https://learn.microsoft.com/de-at/openspecs/windows_protocols/ms-wmi/38d52a83-1613-4c56-8418-12ad1145eeaa) 3.2.3 (Initialization / Locale Negotiation):**

> _"If the client has multiple preferred locales or any locale string that does not match the 'MS_xxx' format as the pszPreferredLocale parameter to IWbemLevel1Login::NTLMLogin, **the client MUST determine whether the server supports the locale and filter out unsupported locales before calling IWbemLevel1Login::NTLMLogin**. To determine supported locales, **the client MUST call IWbemLevel1Login::EstablishPosition**."_

> _"If the return value is E_NOTIMPL, the client MUST choose the first locale that matches the 'MS_xxx' format and MUST remove other locales from the string."_

> _"If the locale list is empty after unsupported locales are filtered out, the client MUST pass NULL for pszPreferredLocale."_

What we can interpret here is that the sending of NULL in the `pszPreferredLocale`, the behavior Impacket defaults to, is "meant" to occur after the local negotiation and unsupported elements between the two systems are gutted.  The NULL value therefore can be okay *if* there was a `EstablishPosition` exchange that happened. 

Additionally, we don't see various proceeding negotiations/steps that otherwise should be occurring. The Windows client, by contrast, implements the full MS-DCOM connection/activation profile that's given per 3.2.4.1.1, including OXID resolution, `IRemUnknown` connection, interface querying, and reference counting. 

Once that's done, the Windows clients will then perform the wider context of the MS-WMI connection. Note that the screenshots below were from the exchange of a Windows client with a server:

- `RemQueryInterface` for `IWbemLoginClientID`
	![Pasted image 20260501135449](images/Pasted%20image%2020260501135449.png)
- `RemQueryInterface` for `IWbemLoginClientIDEx`
	![Pasted image 20260501135506](images/Pasted%20image%2020260501135506.png)
- `IWbemLoginClientID::SetClientInfo`
	![Pasted image 20260501135532](images/Pasted%20image%2020260501135532.png)
- `IWbemLoginClientIDEx::SetClientInfoEx`
	![Pasted image 20260501135550](images/Pasted%20image%2020260501135550.png)
- `IWbemLevel1Login::EstablishPosition` for `Locale` negotiation
	![Pasted image 20260501135615](images/Pasted%20image%2020260501135615.png)
- then `IWbemLevel1Login::NTLMLogin`
	![Pasted image 20260501135629](images/Pasted%20image%2020260501135629.png)

We can the above noted flow in the Windows clients are live here:
![Pasted image 20260501134644](images/Pasted%20image%2020260501134644.png)

**How To Find It**  

For DCOM WMI sessions, flag:

- `RemoteCreateInstance` for `IWbemLevel1Login`

- followed quickly by `IWbemLevel1Login::NTLMLogin`

- with no preceding `IWbemLoginClientID::SetClientInfo`

- and no preceding `IWbemLevel1Login::EstablishPosition`

<a id="ioc-57"></a>

### IoC 57 - NTLM Type 1 uses a static no-version flag shape
**Confidence:** High

  

**Surface:** NTLMSSP Type 1 negotiate inside SMB, RPC, HTTP, LDAP relay, or SPNEGO

  

Across the Impacket capture, NTLM Type 1 messages repeatedly used:

  

```text

Negotiate Flags: 0xe0888235

Negotiate Version: Not set

Calling workstation domain: NULL

Calling workstation name: NULL

```

  

The Windows baseline commonly sent a versioned Type 1 with a Windows build:

  

```text

Negotiate Flags: 0xe2088297

Version 10.0 (Build 20348)

```

  

Notably, Impacket sets `NTLMSSP_NEGOTIATE_TARGET_INFO` in the Type 1 when NTLMv2 is used, while the Windows baseline Type 1 did not.

  

**Expected / Proper Baseline**

  

Windows NTLM clients often include the `NTLMSSP_NEGOTIATE_VERSION` flag and a real OS version field. Impacket's default Type 1 is short, versionless, and very stable.

  

**How To Find It**

  

Decode NTLMSSP Type 1 and flag:

  

- flags exactly `0xe0888235`, or the cluster:

- `Negotiate Version == false`

- `Negotiate Target Info == true`

- workstation/domain fields empty

- signing/sealing/key-exchange flags present

  

**Relevant Code**

  

```python

if use_ntlmv2:

   auth['flags'] |= NTLMSSP_NEGOTIATE_TARGET_INFO

auth['flags'] |= NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY | NTLMSSP_NEGOTIATE_UNICODE | \

                 NTLMSSP_REQUEST_TARGET |  NTLMSSP_NEGOTIATE_128 | NTLMSSP_NEGOTIATE_56

  

if version is not None:

    auth['flags'] |= NTLMSSP_NEGOTIATE_VERSION

    auth['os_version'] = version

```



Evidence:


<a id="ioc-58"></a>

### IoC 58 - NTLMv2 response omits Windows AV pairs and sends a NULL host name
**Confidence:** Medium-High

  

**Surface:** NTLMSSP Type 3 authenticate, NTLMv2 response AV pairs, packet capture, auth telemetry with decoded NTLM

  

The Impacket NTLMv2 responses in the capture include the basic server-provided target info plus a synthesized target name, but omit Windows client AV pairs commonly present in the Windows baseline:

  

- no `Flags` AV pair

- no `Restrictions` AV pair

- no `Channel Bindings` AV pair unless channel binding is explicitly supplied

- Type 3 `Host name: NULL`

  

The Windows baseline included:

  

```text

Flags: 0x00000002

Restrictions

Channel Bindings: 00000000000000000000000000000000

Host name: SCCM

```

  

**Expected / Proper Baseline**

Windows clients commonly include workstation identity and additional AV pairs in NTLMv2 authenticate messages. A NULL host with missing restrictions/channel-binding AV pairs is a useful Impacket correlation feature.

**How To Find It**

Decode NTLMSSP Type 3 and flag:


- `Host name == NULL`

- NTLMv2 AV pairs contain no `Flags`

- no `Restrictions`

- no `Channel Bindings`

- target name is synthesized from service plus server DNS hostname
  

**Relevant Code**

  
```python

if av_pairs[NTLMSSP_AV_DNS_HOSTNAME] is not None:

    av_pairs[NTLMSSP_AV_TARGET_NAME] = f"{service}/".encode('utf-16le') + av_pairs[NTLMSSP_AV_DNS_HOSTNAME][1]

...

if channel_binding_value:

    av_pairs[NTLMSSP_AV_CHANNEL_BINDINGS] = channel_binding_value

...

ntlmChallengeResponse['host_name'] = type1.getWorkstation().encode('utf-16le')

```

<a id="cat-ldap-and-active-directory-objects"></a>

## LDAP and Active Directory objects

<a id="ioc-34"></a>

### IoC 34 - `BadSuccessor.py` creates dMSAs named `dMSA-<8 uppercase alnum>` with fixed migration attributes
**Surface:** LDAP add/modify logs, AD object attributes, directory change monitoring

If no name is supplied, `badsuccessor.py` generates a delegated managed service account named `dMSA-[A-Z0-9]{8}`. The object has fixed attributes including `msDS-ManagedPasswordInterval = 30`, `msDS-DelegatedMSAState = 2`, `msDS-SupportedEncryptionTypes = 28`, `accountExpires = 9223372036854775807`, and by default links `msDS-ManagedAccountPrecededByLink` to `Administrator`. I should flag that the accountExpiry, as per [Microsoft](https://learn.microsoft.com/en-us/windows/win32/adschema/a-accountexpires) is just the default value Windows sets and so should not be used as a reliable IoC.

This might be a more fitting detection for the broader abuse of Badsuccessor then a reliable Impacket detection but maybe someone finds it useful! Ultimately, I would like to add a fuller coverage scheme as much as I can. 

**Expected / proper baseline**  

`msDS-DelegatedMSAState` is a Windows Server 2025 attribute used to track whether a delegated MSA has been linked to a service account. Reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-ada2/c354638a-5e30-43e5-b7f0-9233d83fec8b. In normal operations, dMSA creation should follow a controlled migration/naming process and should not unexpectedly target `Administrator`. 

**How to find it**

Monitor LDAP object creations or AD snapshots for:

- `objectClass = msDS-DelegatedManagedServiceAccount`

- `cn` / `sAMAccountName` matches `dMSA-[A-Z0-9]{8}\$`

- `msDS-ManagedAccountPrecededByLink` resolves to `Administrator` or another privileged account

- `msDS-DelegatedMSAState = 2`

- `msDS-SupportedEncryptionTypes = 28`

**Relevant code**  

`examples/badsuccessor.py:402-404,505-578,678-682`

```python

random_suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

return 'dMSA-%s' % random_suffix

...

'objectClass': ['msDS-DelegatedManagedServiceAccount'],

'sAMAccountName': '%s$' % self.__dmsaName,

'msDS-ManagedPasswordInterval': 30,

'msDS-DelegatedMSAState': 2,

'msDS-SupportedEncryptionTypes': 28,

'accountExpires': 9223372036854775807,

...

target_account = self.__targetAccount if self.__targetAccount else 'Administrator'
```

<a id="ioc-48"></a>

### IoC 48 - `addcomputer.py` default computer objects use `DESKTOP-[A-Z0-9]{8}$`
**Surface:** AD object attributes, LDAP add events, Windows security event 4741, directory replication logs


When no computer name is supplied, `addcomputer.py` creates `DESKTOP-` plus eight uppercase alphanumeric characters and a trailing `$`. Windows-generated desktop names commonly use a `DESKTOP-` prefix too, so the name alone is not enough; the stronger pattern is the generated name plus sparse LDAP attributes: `dnsHostName`, `userAccountControl=0x1000`, and only the four default `HOST` / `RestrictedKrbHost` SPNs.

**Expected / proper baseline**

Real domain-joined Windows computers usually have additional attributes attached or at the absolute minimum consistent naming conventions. Another one of those detections that I think is pretty meh but as noted before, this project was as much a learning experience for me as it is a guide for others. 

I think I have given plenty of solid ones to earn the fluff I put in here! 

**How to find it**

Check for newly created computer accounts where:

- `sAMAccountName` matches `^DESKTOP-[A-Z0-9]{8}\$$`

- creator is a normal user account or unexpected service principal

- `servicePrincipalName` contains only `HOST/<name>`, `HOST/<fqdn>`, `RestrictedKrbHost/<name>`, `RestrictedKrbHost/<fqdn>`

- OS/build attributes are absent after a reasonable join window

**Relevant code**

`examples/addcomputer.py:194-203,237-238,379-381`


```python
spns = [

    'HOST/%s' % computerHostname,

    'HOST/%s.%s' % (computerHostname, self.__domain),

    'RestrictedKrbHost/%s' % computerHostname,

    'RestrictedKrbHost/%s.%s' % (computerHostname, self.__domain),

]

return 'DESKTOP-' + (''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(8)) + '$')

```

<a id="cat-dce-rpc-dcom-and-wmi"></a>

## DCE/RPC, DCOM, and WMI

<a id="ioc-13"></a>

### IoC 13 - DCE/RPC bind is missing the second context item
**Surface:** DCE/RPC bind PDUs over SMB named pipes, TCP, or RPC over HTTP


Impacket's DCE/RPC implementation uses initial `call_id = 1` on the Bind and only sends through 1 context item:

![Pasted image 20260429143231](images/Pasted%20image%2020260429143231.png)

Compared with enumerating services remotely from the Windows server, we send an additional context item:

![Pasted image 20260429143430](images/Pasted%20image%2020260429143430.png)

Note that I have not been able to appropriately hunt and trace down which versions of Windows would default to sending this as opposed to not. For readers capable, this may be a useful to check within your environments to at least try to capture as many systems that would have this. 

**How to find it**

Decode DCE/RPC bind PDUs and add risk when:
  
- `max_tfrag = 4280`

- `max_rfrag = 4280`

- initial `call_id = 1`

- transfer syntax is NDR32 `8a885d04-1ceb-11c9-9fe8-08002b104860 v2.0`

- Only one context item sent, with a missing `Bind Time Feature Negotiation Context` being sent.

To expand on this additionally, the [Microsoft](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/87964b3c-1785-4aae-a993-734999441ed3) does not state/expand on if this is required to be spec compliant. Likely that a certain version of Windows started including this and thus can be used as a good threshold to remove/clear false positives within the environment. 

**Relevant code**

`impacket/dcerpc/v5/rpcrt.py:1153-1169`

```python
('max_tfrag', '<H=4280'),

('max_rfrag', '<H=4280'),

('assoc_group', '<L=0'),
...
self['max_tfrag'] = 4280

self['max_rfrag'] = 4280

self['assoc_group'] = 0
```

`impacket/dcerpc/v5/rpcrt.py:1078` and `impacket/dcerpc/v5/rpcrt.py:1470-1471`

```python
('call_id','<L=1')

self.transfer_syntax = uuidtup_to_bin(('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0'))

self.__callid = 1
```

<a id="ioc-14"></a>

### IoC 14 - DCE/RPC SCMR sets MachineName to "DUMMY" when accessing SCManager
**Surface:** DCE/RPC/SCMR Accessing SCManager

When Impacket tooling is used that requires users be local administrators on target systems, Impacket depends on accessing the relevant named pipe to then access SCManager remotely. When doing so, Impacket passes the `lpMachineName` argument to the target system as DUMMY.

**How to find the IoC**

* SVCCTL Protocol has `OpenSCManagerW request` call
* The field `Pointer To MachineName` contains uint 16 DUMMY

We can see this in the following by remotely using Impacket to list remote services from a domain controller:

![Pasted image 20260429144704](images/Pasted%20image%2020260429144704.png)


**Relevant Code**
`impacket/impacket/dcerpc/v5/scmr.py: 1357`

```python
def hROpenSCManagerW(dce, lpMachineName='DUMMY\x00', lpDatabaseName='ServicesActive\x00', dwDesiredAccess=SERVICE_START | SERVICE_STOP | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS | SC_MANAGER_ENUMERATE_SERVICE):
    openSCManager = ROpenSCManagerW()
    openSCManager['lpMachineName'] = checkNullString(lpMachineName)
    openSCManager['lpDatabaseName'] = checkNullString(lpDatabaseName)
    openSCManager['dwDesiredAccess'] = dwDesiredAccess
    return dce.request(openSCManager)
```

<a id="ioc-15"></a>

### IoC 15 - DCE/RPC SCMR EnumServicesStatusW RPC invocation sends no offered buffer
**Surface:** DCE/RPC/SCMR calls invoking the EnumServiceStatusW RPC call

When Impacket is connecting via SVCCTL and making the EnumServicesStatusW call, uses a zero buffer probe approach. In this, Impacket sends a request with `Offered = 0` and  `Pointer to Resume Index` is **NULL**. Impacket does this to trigger a response that includes WERR_MORE_DATA error where the server will then tell Impacket the bytes needed. The initial request as sent by Impacket:

![Pasted image 20260429160603](images/Pasted%20image%2020260429160603.png)

And in violation of MS-SCMR:

> _"The client MUST set lpResumeIndex to 0 on the first call. If the server fails the call with ERROR_MORE_DATA (234), then the server MUST return a non-zero value in lpResumeIndex that the client MUST then specify in the subsequent calls."_

As we can see, Impacket violates the spec! Impacket will pass `NULL`  for `lpResumeIndex` on the retry.  However, since `cbBufSize` is now the full size needed(based on the servers response), the server can fit all services in one shot, and with that, the resume index becomes irrelevant and the call succeeds. This appears to be a shortcut Impacket put that works because the buffer is now large enough for the complete enumeration.

In Windows, we see that typically the call **guesses** a large enough buffer up front. We also see the call provides a valid `Pointer to Resume Index`, initialized to `0`, rather than a NULL pointer. The server will reply with `STATUS_BUFFER_OVERFLOW FSCTL_PIPE_TRANSCEIVE`, which indicates to us that our buffer wasnt large enough. We can see the initial request sent by a native Windows call:

![Pasted image 20260429160701](images/Pasted%20image%2020260429160701.png)

Note the difference between this and Impacket. We generally expect native Windows utilities/tools to send/include a explicit service type, an initial offer for buffer size, and a pointer to resume index.

Overall the violation of the spec alongside the additional network class to asking for the exact required buffer size, provides a decent way to catch Impacket DCE/RPC use

<a id="ioc-40"></a>

### IoC 40 - Authenticated DCE/RPC uses `auth_context_id = 79231 + ctx_id` and `0xff` auth padding
**Surface:** DCE/RPC bind, alter-context, request PDUs with NTLM or Kerberos authentication
  
For authenticated DCE/RPC, Impacket sets the security trailer `auth_context_id` to `self._ctx + 79231`. With the usual first presentation context, that means `auth_context_id = 79231` (`0x0001357f`). When padding is needed before the security trailer, Impacket fills the padding with `0xff` bytes.

**Expected / proper baseline**

MS-RPCE defines `auth_context_id` as the numeric identifier for the security context used on the RPC connection; Microsoft's secure RPC examples use client-chosen context ID `1`, and the server indexes security contexts by this field. References: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/ab45c6a5-951a-4096-b805-7347674dc6ab and https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/074feef6-d1dd-4066-8434-16cc4763dd8b.

This can be seen here when inspecting a `ISystemActivator RemoteCreateInstance Request` triggered by using Impacket's wmiquery.py:

![Pasted image 20260430221635](images/Pasted%20image%2020260430221635.png)

**How to find it**

Upon decoding/analyzing the relevant DCE/RPC security trailers and checking on:

- `auth_context_id == 79231` on first authenticated bind/request

- subsequent altered contexts use `79232`, `79233`, etc.

- authentication padding bytes are `ff ff ...` immediately before `sec_trailer`

This pairs well with the earlier identified behavior associated with Impacket's DCE/RPC. 

**Relevant code**

`impacket/dcerpc/v5/rpcrt.py:1580-1587,1682-1683,1726-1728`

```python
sec_trailer['auth_type']   = self.__auth_type

sec_trailer['auth_level']  = self.__auth_level

sec_trailer['auth_ctx_id'] = self._ctx + 79231

...

packet['pduData'] += b'\xFF'*pad
```

The same value appears in many other places and so acts as a good IoC for other relevant code paths. This can be seen by simply searching the number in the Impacket repo on github:

![Pasted image 20260430221742](images/Pasted%20image%2020260430221742.png)

<a id="ioc-50"></a>

### IoC 50 - DCE/RPC bind usually offers only 32-bit NDR
**Surface:** DCE/RPC bind packets over SMB named pipes or TCP endpoint mapper, packet capture, RPC ETW with bind details  

Across the Impacket DCE/RPC world, SVCCTL, WINREG, SAMR, EPM, DRSUAPI, SRVSVC, ISystemActivator, and IWbemLevel1Login binds commonly present one context item with only 32-bit NDR.

The Windows equivalents usually offer more than that: 32-bit NDR, 64-bit NDR, and bind-time feature negotiation. For SVCCTL specifically, Windows offered 32-bit NDR plus bind-time feature negotiation, while Impacket offered only 32-bit NDR.

**Expected / Proper Baseline**  

Windows RPC clients commonly negotiate more than the bare 32-bit NDR transfer syntax when supported. In the provided Windows capture:

- SRVSVC: 32-bit NDR + 64-bit NDR + bind-time feature negotiation

- EPMv4: 32-bit NDR + 64-bit NDR + bind-time feature negotiation

- WINREG: 32-bit NDR + 64-bit NDR + bind-time feature negotiation

- SVCCTL: 32-bit NDR + bind-time feature negotiation

**How To Find It**

Flag RPC binds where:

- abstract syntax is a Windows admin interface such as SVCCTL, WINREG, SAMR, SRVSVC, DRSUAPI, EPMv4

- `Num Ctx Items == 1`

- only transfer syntax is `8a885d04-1ceb-11c9-9fe8-08002b104860` / 32-bit NDR

- no NDR64 transfer syntax

- no bind-time feature negotiation transfer syntax `6cb71c2c-9812-4540-0300-000000000000`

- Combine with other IoCs mentioned such as fixed frag length, absence of `Verification Trailer` etc etc 

**Relevant Code**
  
```python
def bind(self, iface_uuid, alter = 0, bogus_binds = 0,

         transfer_syntax = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')):

    ...

    item['AbstractSyntax'] = iface_uuid

    item['TransferSyntax'] = uuidtup_to_bin(transfer_syntax)

    item['ContextID'] = ctx

    item['TransItems'] = 1

    bind.addCtxItem(item)

```

<a id="ioc-51"></a>

### IoC 51 - DCE/RPC ISystemActivate RemoteCreateInstance request contains various odd entries and omissions
**Surface:** DCE/RPC bind, ISystemActivator packet capture, RPC telemetry

When inspecting the `ISystemActivator` RemoteCreateInstance request, we notice many unique oddities present within the Impacket request that are missing that otherwise would be sent/expected by Windows. Impacket upon using wmiquery, will send/include in the request the four properties for `RemoteCreateInstance`: 000001ab (`InstantiationInfoData`), 000001a4 (`LocationInfoData`), 000001aa (`ScmRequestInfoData`)  and 000001a5 (`ActivationContextInfoData`). Of these three of them are required. 

![Pasted image 20260430235044](images/Pasted%20image%2020260430235044.png)

Digging into the spec, `RemoteCreateInstance` says `pActProperties` **MUST** be an `OBJREF_CUSTOM` whose CLSID is `CLSID_ActivationPropertiesIn`, and its object data **MUST** contain an activation properties blob. Inside that blob, three properties are required and several are optional. The required ones are `InstantiationInfoData`, `ScmRequestInfoData`, and `LocationInfoData`; `SecurityInfoData`, `ActivationContextInfoData`, `InstanceInfoData`, and `SpecialPropertiesData` are optional by the base protocol. All of which can be seen in the following entry for the [MS-DCOM](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/64af4c57-5466-4fdf-9761-753ea926a494) specification. 

Additionally, Windows product behavior explicitly says Windows clients include `SecurityInfoData`; Windows servers ignore it. It also says Windows clients send a `COSERVERINFO` structure in the server-info field, and that `pwszName` is set to the remote server name used for the activation. This is useful because standard network monitoring can often extract it, giving defenders a way to detect a bind going to a system whose name or IP is not represented inside the relevant PDU. 

Additional noticed gaps that were consistent included:

Type-serialization `PrivateHeader.Filler`:  
Windows 0x00000000, Impacket 0xcccccccc  
  
trailing/unused `serialized bytes`:  
Windows `zero-filled`, Impacket `0xfa-filled`

![Pasted image 20260430235925](images/Pasted%20image%2020260430235925.png)

`InstantiationInfoData.classCtx`:  
Windows 0x14, Impacket 0x00  

A discussion about this subtlety as I explored the spec: `0x00` is not “in-process server”; `CLSCTX_INPROC_SERVER` is `0x01` [reference](https://learn.microsoft.com/en-us/windows/win32/api/wtypesbase/ne-wtypesbase-clsctx). `0x00` is what could be considered(could be wrong??) a “no class context flags.” For a remote `RemoteCreateInstance` over TCP/135, that to me seems a bit odd because the client is not clearly requesting a remote or local server execution context. In our Windows captures, Windows sends `ClassContext: 20 (0x14)` while the Impacket sample sends `ClassContext: 0 (0x00000000)`. The MS-DCOM [spec](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/00ad4108-3772-4cda-87df-b2514d4f983b) appears to validate my idea on the expected value being different than Impacket's. 

`InstantiationInfoData.thisSize / EntirePropertySize`:  
Windows 88, Impacket 0

Microsoft [defines](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/00ad4108-3772-4cda-87df-b2514d4f983b) this size, in bytes, of the structure, as marshaled by the NDR Type Serialization 1 engine. It follows to reason that this should never be 0 bytes otherwise that just defeats the point? also again refering to the Appendix of the spec it does appear Windows will send a plausible number. Another important caveat is that the spec does say that Windows servers will ignore the value anyways and so why I suspect Impacket just sends 0. 

Finally, Impacket does not set the proper `ActivationContextInfo` to a non null `OBJREF` object within it that would otherwise be expected:

![Pasted image 20260501090843](images/Pasted%20image%2020260501090843.png)
As seen fro above, `ActivationContextInfoData.pIFDClientCtx` is NULL, despite a MUST being used in the MS-DCOM specification in [3.2.4.1.1.2](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/647893cd-f63a-4df4-8fe1-a962fbcac0d7). Specifically: **It MUST set the pIFDClientCtx field of the `ActivationContextInfoData` structure to an OBJREF containing a marshaled Context structure.**

**Expected / Proper Baseline**

Microsoft’s Windows product behavior says Windows DCOM clients send all the listed properties, including optional ones, except `InstanceInfoData` unless doing persistent activation. That means Windows normally sends `SpecialPropertiesData` and `SecurityInfoData` as per the [Appendix B Product Behaviour](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/acc42954-4073-4f05-b850-efd562022077) section.

![Pasted image 20260430235155](images/Pasted%20image%2020260430235155.png)

We can then conclude that Impacket omits two optional properties that Windows normally would be expected to send:  
000001b9 `SpecialPropertiesData` / `SpecialSystemProperties`  
000001a6 `SecurityInfoData`

As mentioned earlier the Windows client provided structure `SecurityInfoData` provides details on the remote/target system we are accessing. The first request may include the IP or DNS name but the second request will generally contain the DNS name of the remote system: 

![Pasted image 20260430235516](images/Pasted%20image%2020260430235516.png)

Continuing on from Impacket deviations,  `ActivationContextInfoData`. the MS-DCOM [states](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/f07e681a-16f9-4194-a453-63c7972f2161) the object resolver reads the `Context` structure contained in `pIFDClientCtx` and supplies client context properties to the application/higher layer when the object class has an application identifier. We can see that in comparison with Impacket, Windows creates a non null OBJREF context:

![Pasted image 20260501091820](images/Pasted%20image%2020260501091820.png)

**How To Find It**

This like a fair bit of other of these will require holistic/enrichment data. This like other oddities on their own may be a bit more common but once you start to combine/stack relevant ones together, you will find it to be very anomalous behavior. I combined this with two other DCOM IoCs and in a 10k endpoint environment only found a little under 200 instances that met the criteria. Of those, more than half were from the pentest while the others came from 2 other benign sources. 

Flag DCE/RPC client sessions where repeated binds across admin interfaces negotiate:

- Dont contain the `Verification Trailer`

- `max_rfrag == 4280`

- `ActivationContextInfoData.ClientPtr` is set to NULL

- A 0x00 `InstantiationInfoData.classCtx

- `0xfa` filled in Unused Buffer sections of the PDU

- Absent `SecurityInfoData` activation property blob

- Raw NTLMSSP Authentication instead of SPNEGO(Note that this will have to be baselined as per the environment)

- combined with single-context 32-bit NDR binds and an absence of Bind Time Security Negotiation item 


**Relevant Code**

There is non? There's no many differences and gaps but I'm sure one can easily search the Impacket repo.

<a id="ioc-52"></a>

### IoC 52 - DCE/RPC PDUs do not contain `Verification Trailer`
**Surface:** Authenticated DCE/RPC bind, alter_context, request auth verifier, packet capture with RPC auth decoding


When authenticating using DCE/RPC with Impacket, in my example confirmed when connecting with wmiquery.py or using the `ISystemActivator` `RemoteCreateInstance request`, the PDU/Last PDU provided by Impacket does not contain the `Verification Trailer` structure. When looking at the wmiquery packet capture, we can see the structure is omitted:

![Pasted image 20260430225343](images/Pasted%20image%2020260430225343.png)

When reading [MS-RPCE](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/290c38b1-92fe-4229-91e6-4fc376610c15) section 2.2.2.13 we can TLDR: verification trailers **MUST only appear in request PDUs**, and **SHOULD** be placed after stub data and before auth padding. It also says implementations **SHOULD** add the trailer on request PDUs that have portions of the PDU that cannot be protected by the security provider in transit. This does only apply within exchanges in which the security provider in use does not provide integrity protection, as specified in [C706](https://pubs.opengroup.org/onlinepubs/9629399/toc.pdf) section 13.2.5

As per the spec referenced above, the structure must be expected to appear below the stub data and above the authentication data.

**Expected / Proper Baseline**

Windows clients, especially after the rollout of [DCOM Hardening](https://techcommunity.microsoft.com/blog/windows-itpro-blog/dcom-authentication-hardening-what-you-need-to-know/3657154) appear to consistently follow in providing the Verification Trailer structure within the final requesting PDU. We can see this here for example on our Windows Server 2022:

![Pasted image 20260430225247](images/Pasted%20image%2020260430225247.png)

**How To Find It**

* Detect when a remote access request is initiated without providing the `Verification Trailer` within the final PDU

<a id="ioc-56"></a>

### IoC 56 - WMI DCOM activation uses a sparse four-property activation blob
**Surface:** DCOM `ISystemActivator::RemoteCreateInstance`, packet capture with decrypted DCE/RPC, RPC ETW
  

For WMI activation, Impacket's `RemoteCreateInstance` request uses a more bare-minimum activation blob:

- `NumActivationPropertyStructs: 4`

- property GUIDs: `000001ab`, `000001a5`, `000001a4`, `000001aa`

- `ClassContext: 0`

- `ActivationFlags: 0`

- `MachineNamePtr: NULL`

- `ProcessId: 0`

- no client context property

Windows clients, pursuant to the relevant MS-DCOM/MS-WMI specifications spoken about in IoC 62 use a larger activation blob:

- `NumActivationPropertyStructs: 6`

- included extra property GUIDs `000001b9` and `000001a6`

- `ClassContext: 20`

- had a `ClientContext` OBJREF

- carried context metadata before the WMI login flow
  
**Expected / Proper Baseline**
  
Native Windows DCOM activation for WMI carries more activation properties and a nonzero class context, and it more closely mirrors the relevant specifications. In comparison, Impacket's WMI activation is much more skeletal. As discussed in the previous WMI/DCOM sections, many of these artifacts are not major on their own, but in an enterprise environment they can support strong correlation-based detections. 

**How To Find It**

Decode `ISystemActivator::RemoteCreateInstance` for `CLSID_WbemLevel1Login` / `8bc3f05e-d86b-11d0-a075-00c04fb68820` and flag:

- exactly four activation property structs

- `ClassContext == 0`

- `MachineNamePtr == NULL`

- No `ClientContext` OBJREF present

- requested interface `IWbemLevel1Login`

<a id="ioc-59"></a>

### IoC 59 - DCOM ORPC causality ID uses Impacket's non-standard UUID generator
**Surface:** DCOM ORPC requests, WMI/DCOM packet capture, Wireshark-decoded `ORPCThis`


Every DCOM ORPC request carries a causality identifier (`CID`) in `ORPCThis`. The Microsoft DCOM documentation describes this as a GUID used to associate causally related ORPC calls. In the  Impacket WMI trace generated as part of this research, the CID is `6afcd935-0594-4800-5500-c40935bab67d`. `4800-5500` → `5` (not a valid variant), `0` (not a valid version)

Impacket's Uses `impacket.uuid.generate()` which packs four random 31-bit integers without setting UUID version (`0x4`) or variant (`0x8-0xB`) bits. Resulting CIDs have invalid variant/version values (e.g., `5500` in the fourth group).

 TLDR: `impacket.uuid.generate()` packs four random 31-bit integers and does not set UUID version or variant bits.

**Expected / Proper Baseline**
  
Windows-generated DCOM CIDs in the baseline look like normal version-4, RFC4122-variant GUIDs.
 
Normal Windows CIDs were consistently observed to begin with `8`, `9`, `a`, or `b`, for example:

```text
d1ef1a17-7cd3-4ad1-8d72-94e7b90db75f

58d18629-e215-42a2-9931-7d183c2abacb

721a15aa-4cd6-47f2-a7b4-fa3260833111
```

From above, **Windows CIDs** follow this: `4ad1-8d72` → `8` (variant), `4` (version)

 In practice this is a very strong Impacket fingerprint when in context of all the other detections as it allows us to better filter out hard known legitimate data.
 
**How To Find It**

Decode DCOM `ORPCThis.Causality ID` and flag CIDs where:

- the UUID variant is not RFC4122 (`clock_seq_hi_and_reserved & 0xc0 != 0x80`)

- or the UUID version nibble is absent/unexpected  

We can use a visual test to pick this up like:

```
Look at any DCOM Causality ID:

        d1ef1a17-7cd3-4ad1-8d72-94e7b90db75f
                      ↑    ↑
                      │    │
                   Check M  Check N
                      │    │
                      ▼    ▼

        Is M == 4?          Is N in {8,9,a,b}?
           │                      │
           ▼                      ▼
        ┌─────┐               ┌─────┐
        │ YES │               │ YES │
        └──┬──┘               └──┬──┘
           │                     │
           └──────────┬──────────-|
                      │
                   Windows ✓
                      │
        ┌─────────────┴─────────────┐
        │                           │
        ▼                           ▼
     M != 4                        N not in {8,9,a,b}
        │                             │
        └─────────────┬───────────────┘
                      │
                   Impacket ✓
                   (or broken client)
```

Correlate with WMI/DCOM activity such as `ISystemActivator::RemoteCreateInstance`, `IWbemLevel1Login::NTLMLogin`, and `IRemUnknown::RemRelease`.

**Relevant Code**  

 `impacket/uuid.py`
```python

def generate():

    # UHm... crappy Python has an maximum integer of 2**31-1.

    top = (1<<31)-1

    return pack("IIII", randrange(top), randrange(top), randrange(top), randrange(top))

```
  
`impacket/dcerpc/v5/dcomrt.py`
```python
ORPCthis['cid'] = generate()

ORPCthis['extensions'] = NULL

ORPCthis['flags'] = 1

```

- MS-DCOM causality identifier reference: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/e3884865-47e6-40c3-8b24-0ffd0309f4b7>

<a id="ioc-60"></a>

### IoC 60 - WMI/DCOM session skips the IOXIDResolver ServerAlive2 preflight
**Surface:** DCOM/WMI packet capture, RPC endpoint mapper and TCP/135 flows
  
The Windows baseline performs an `IOXIDResolver` bind and `ServerAlive2` call before WMI activation. That call returns COM version and resolver binding information, which lets the client select compatible object resolver bindings.
  
In the Impacket WMI flow, the client goes straight to `ISystemActivator::RemoteCreateInstance`. No call to `IOXIDResolver::ServerAlive2` is observed. 
  

**Expected / Proper Baseline**

As already spoken about in depth in the earlier IoC:

```text

Bind: IOXIDResolver

ServerAlive2 request

ServerAlive2 response

ISystemActivator::RemoteCreateInstance

```

The Impacket sequence is:

```text

ISystemActivator::RemoteCreateInstance

IWbemLevel1Login::NTLMLogin

IRemUnknown::RemRelease

```

  
This is best treated as a lifecycle fingerprint to be combined with others. Impacket has a `ServerAlive2()` implementation, but normal WMI usage through `DCOMConnection(..., oxidResolver=False)` does not invoke it by default.

**How To Find It**

For remote WMI/DCOM sessions, flag when a client:

- talks to TCP/135 / DCOM activation

- sends `ISystemActivator::RemoteCreateInstance`

- does not first issue `IOXIDResolver::ServerAlive2` from the same client/server pair in the nearby flow window

This becomes stronger when combined with entries 61, 62, 63, 67, 69, and 70.

**Relevant Code**

`impacket/dcerpc/v5/dcomrt.py`
```python

def __init__(..., authLevel=RPC_C_AUTHN_LEVEL_PKT_PRIVACY, oxidResolver=False, ...):

    self.__oxidResolver = oxidResolver

```

We can see above that the DCOMConnection class Impacket exposes by default sets oxidResolver to false

```python

def ServerAlive2(self):

    self.__portmap.connect()

    self.__portmap.bind(IID_IObjectExporter)

    request = ServerAlive2()

    resp = self.__portmap.request(request)

```


Sources:
- MS-DCOM `ServerAlive2` reference: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/c898afd6-b75d-4641-a2cd-b50cb9f5556d>

<a id="ioc-61"></a>

### IoC 61 - DCOM object release uses IRemUnknown with single PublicRef releases
**Surface:** DCOM/WMI packet capture, `IRemUnknown` / `IRemUnknown2` calls


The Impacket WMI trace releases DCOM object references using `IRemUnknown::RemRelease` with exactly one interface reference and `PublicRefs=1, PrivateRefs=0`.

```text

Alter_context: IRemUnknown, 32-bit NDR

IRemUnknown::RemRelease Cnt=1 Refs=1-0

```
  

**Expected / Proper Baseline**

Windows baseline:

```text

Bind: IRemUnknown2, 32-bit NDR, 64-bit NDR, bind-time feature negotiation

IRemUnknown2::RemRelease Cnt=3 Refs=5-0,5-0,5-0

```

MS-DCOM allows `RemRelease` to carry an array of `REMINTERFACEREF` structures, so the Impacket behavior is not necessarily invalid. The detection value is the repeated combination of older interface, no batching, and one public ref per release.
  
**How To Find It**

  
Decode DCOM object lifetime calls and flag:

- `IRemUnknown` UUID `00000131-0000-0000-c000-000000000046`

- `RemRelease` opnum 5

- `InterfaceRefs == 1`

- `PublicRefs == 1`

- repeated in a WMI/DCOM session that never binds `IRemUnknown2`


**Relevant Code**

  
 `impacket/dcerpc/v5/dcomrt.py`
```python
def RemRelease(self):

    request = RemRelease()

    request['ORPCthis'] = self.get_cinstance().get_ORPCthis()

    request['ORPCthis']['flags'] = 0

    request['cInterfaceRefs'] = 1

    element = REMINTERFACEREF()

    element['ipid'] = self.get_iPid()

    element['cPublicRefs'] = 1

    request['InterfaceRefs'].append(element)

    resp = self.request(request, IID_IRemUnknown, self.get_ipidRemUnknown())

```


Sources:

- MS-DCOM `IRemUnknown` reference: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/7f621d16-8448-4f9a-9567-793845db2bc7>

- MS-DCOM `REMINTERFACEREF` reference: <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/69bc8015-c524-4988-b7fa-96094f0f74e9>

<a id="ioc-62"></a>

### IoC 62 - DCOM activation leaves ClientImpersonationLevel at zero
**Surface:** DCOM `RemoteCreateInstance` activation blob, Wireshark-decoded `ScmRequestInfo`


This one is excellent because the code almost tells on itself. In Impacket's `ScmRequestInfo`, the intended assignment is commented out:

  

```python

#scmInfo['remoteRequest']['ClientImpLevel'] = 2

```

  

As a result, the activation blob in the Impacket trace contains:

  

```text

ClientImpersonationLevel: 0

NumProtocolSequences: 1

ProtocolSeq: 7

```

  

The Windows baseline for the same WMI/DCOM activation contains:


```text

ClientImpersonationLevel: 2

NumProtocolSequences: 1

ProtocolSeq: 7

```


**Expected / Proper Baseline**

As per [MS-DCOM] 3.2.4.1.2 (Activation Request Parameters):

"The client MUST specify the impersonation level requested by the application, if one was supplied; otherwise, it MUST specify a default impersonation level of at least RPC_C_IMPL_LEVEL_IMPERSONATE (2)."

The supplied Windows client consistently used `ClientImpersonationLevel: 2` in the DCOM activation `ScmRequestInfo`. Impacket leaves the field at the structure default, producing `0`, which isnt the spec defined default; which would be 2?

**How To Find It**

Decode `ISystemActivator::RemoteCreateInstance` and inspect:
  
- `IActProperties`

- `ScmRequestInfo`

- `RemoteRequest`

- `ClientImpersonationLevel`

Flag remote WMI/DCOM activation where `ClientImpersonationLevel == 0`, especially with `ProtocolSeq == 7` and the sparse four-property activation blob from entry 63. Additionally, we expect that there should be more than one entry in `pRequestedProtseqs` since the expectation is that Windows will extract the information for network protocols dynamically instead of setting it in stone. My idea came from the following microsoft [Windows Protocols](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/ba4c4d80-ef81-49b4-848f-9714d72b5c01#gt_630dc751-f394-4ced-b924-e1ab05c44cac) entry. 

**Relevant Code**

```python

scmInfo = ScmRequestInfoData()

scmInfo['pdwReserved'] = NULL

#scmInfo['remoteRequest']['ClientImpLevel'] = 2

scmInfo['remoteRequest']['cRequestedProtseqs'] = 1

scmInfo['remoteRequest']['pRequestedProtseqs'].append(7)

```


Source: `impacket/dcerpc/v5/dcomrt.py`

<a id="ioc-63"></a>

### IoC 63 - DCOM activation serialization uses `0xcccccccc` fillers and `0xfa` property padding
**Surface:** DCOM `RemoteCreateInstance` activation blob, packet capture with decoded activation properties


Impacket's Type Serialization v1 headers use `0xcccccccc` filler values, and its DCOM activation property padding uses `0xfa` bytes. In the supplied Impacket activation request, Wireshark shows repeated:
  

```text

Filler: 0xcccccccc

Unused buffer: fafafafa

Unused buffer: fafafafafafa

```


The Windows clients use zeroed filler and zeroed unused buffers:

```text

Filler: 0x00000000

Unused buffer: 00000000

Unused buffer: 000000000000

```

  
**Expected / Proper Baseline**


Windows appears to zero these reserved/filler fields in the observed DCOM activation traffic, while Impacket uses `0xcccccccc` fillers and `0xfa` padding. Because the fields are reserved or used as padding, this is primarily an implementation fingerprint. Baseline your environment to confirm the exact size and pattern before treating it as a high-confidence standalone alert.

**How To Find It**


In `ISystemActivator::RemoteCreateInstance`, inspect the activation properties and flag:

  

- `CommonHeader.Filler == 0xcccccccc`

- `PrivateHeader.Filler == 0xcccccccc`

- unused activation-property buffers filled with `fa fa fa ...`

  
This signal is especially good because it appears multiple times inside a single activation blob.


**Relevant Code**
  
```python

class CommonHeader(NDRSTRUCT):

    ...

    if data is None:

        self['Version'] = 1

        self['Endianness'] = 0x10

        self['CommonHeaderLength'] = 8

        self['Filler'] = 0xcccccccc

```

  

```python

class PrivateHeader(NDRSTRUCT):

    ...

    if data is None:

        self['Filler'] = 0xcccccccc

```

  

```python

properties += marshaled + b'\xFA'*pad

```

  

Sources:

- `impacket/dcerpc/v5/rpcrt.py`

- `impacket/dcerpc/v5/dcomrt.py`

<a id="ioc-64"></a>

### IoC 64 - WKSSVC calls use a ten-NUL `ServerName`
**Surface:** WKSSVC RPC over SMB named pipe, packet capture with DCE/RPC decoding, RPC ETW
  

Many Impacket Workstation Service helper calls set `ServerName` to `'\x00' * 10`. It creates a protocol-level fingerprint across multiple WKSSVC operations, which means that difference usage of the same underlying code can yield great detection levels. 

**Expected / Proper Baseline**

Normal Windows callers generally target the local machine with a NULL pointer or provide an actual server/computer name. A populated field consisting only of repeated NULL characters has yet to be observed in any of the Windows captures

**How To Find It**

Decode WKSSVC RPC requests and flag a non-null `ServerName` field that resolves to an all-NUL string, especially across these calls:


- `NetrWkstaGetInfo`

- `NetrJoinDomain2`

- `NetrValidateName2`

- `NetrUseEnum`

- `NetrUseGetInfo`

- `NetrGetJoinInformation`

  

This is a strong protocol-shape indicator when observed from non-Windows administrative hosts or immediately before domain join / machine-account manipulation.

  

**Relevant Code**

```python

def hNetrWkstaGetInfo(dce, level):

    request = NetrWkstaGetInfo()

    request['ServerName'] = '\x00'*10

    request['Level'] = level

    return dce.request(request)

```

  
The same `ServerName = '\x00' * 10` pattern appears throughout the helper wrappers in `impacket/dcerpc/v5/wkst.py`.


Source: `impacket/dcerpc/v5/wkst.py`

<a id="ioc-64"></a>
<a id="cat-example-script-execution-artifacts"></a>

## Example-script execution artifacts

<a id="ioc-16"></a>

### IoC 16 - `psexec.py` RemCom named pipes, including typoed main pipe
**Surface:** Named pipe telemetry, SMB create/open events, Sysmon Event ID 17/18, Zeek/Snort etc

Impacket's PsExec implementation uses RemCom-compatible pipe names. The main communication pipe is typoed as `\RemCom_communicaton`, missing the second "i". That typo like all typos and odd strings, providers powerful detection features for us to pick up on :).


**How to find it**

Alert on named pipe creation/open where pipe name matches:

- `\RemCom_communicaton`

- `\RemCom_stdout*`

- `\RemCom_stdin*`

- `\RemCom_stderr*`

**Relevant code**

`examples/psexec.py:61-63`


```python
RemComSTDOUT = "RemCom_stdout"

RemComSTDIN = "RemCom_stdin"

RemComSTDERR = "RemCom_stderr"
```

`examples/psexec.py:164-165`

```python
tid = s.connectTree('IPC$')

fid_main = self.openPipe(s,tid,r'\RemCom_communicaton',0x12019f)
```

<a id="ioc-17"></a>

### IoC 17 - Random 4-letter service name and random 8-letter `.exe`
**Surface:** Windows service creation logs, Security 4697, System 7045, EDR service telemetry

When a caller does not provide names, Impacket's service installer creates a 4-letter service name and uploads an 8-letter `.exe`. This is common behind Impacket's PsExec-style service execution.

**How to find it**

Alert on new services where:

- service name matches `^[A-Za-z]{4}$`

- display name equals service name

- binary path ends in `\<A-Za-z>{8}.exe`

- service is created over remote SCMR within a 3-5 min time span after an SMB file upload  occurs

**Relevant code**

`impacket/examples/serviceinstall.py:31-38`

```python
self.__service_name = serviceName if len(serviceName) > 0  else  ''.join([random.choice(string.ascii_letters) for i in range(4)])

self.__binary_service_name = ''.join([random.choice(string.ascii_letters) for i in range(8)]) + '.exe'
```

`impacket/examples/serviceinstall.py:98-101`

```python
command = '%s\\%s' % (path, self.__binary_service_name)

resp = scmr.hRCreateServiceW(..., lpBinaryPathName=command + '\x00', dwStartType=scmr.SERVICE_DEMAND_START)
```

<a id="ioc-18"></a>

### IoC 18 - `smbexec.py` `__output_<8 letters>` and `%SYSTEMROOT%\<8 letters>.bat`
**Surface:** Service command line, process command line, filesystem, SMB file telemetry

`smbexec.py` creates an output file named `__output_` plus eight random letters. It writes a temporary batch file directly under `%SYSTEMROOT%` with an eight-letter name, then launches it through `%COMSPEC%`.


**How to find it**  

Alert on command lines or file events matching:

- `\\%COMPUTERNAME%\<share>\__output_[A-Za-z]{8}`

- `%SYSTEMROOT%\<A-Za-z>{8}.bat`

- Local Impacket server mode share/directory names `TMP` and `__tmp`

**Relevant code**

`examples/smbexec.py:59-61`

```python
OUTPUT_FILENAME = '__output_' + ''.join([random.choice(string.ascii_letters) for i in range(8)])

SMBSERVER_DIR   = '__tmp'

DUMMY_SHARE     = 'TMP'
```

`examples/smbexec.py:284-287`

```python
batchFile = '%SYSTEMROOT%\\' + ''.join([random.choice(string.ascii_letters) for _ in range(8)]) + '.bat'

command = self.__shell + 'echo ' + data + ' ^> ' + self.__output + ' 2^>^&1 > ' + batchFile + ' & ' + \

          self.__shell + batchFile
```

<a id="ioc-19"></a>

### IoC 19 - `atexec.py` scheduled task has fixed 2015 `StartBoundary`
**Surface:** Task Scheduler Operational logs, Security process events, SMB reads/deletes

`atexec.py` registers a scheduled task XML with a hard-coded 2015 start boundary and redirects output to `%windir%\Temp\<random>.tmp`, then retrieves it from `ADMIN$\Temp`.

**How to find it**  

Alert when a newly registered scheduled task XML or related task event includes:

- `<StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>`

- output redirection to `%windir%\Temp\<*.tmp>`

- follow-on SMB read/delete of `ADMIN$\Temp\<same>.tmp`

**Relevant code**

`examples/atexec.py:123-130`

```python
cmd = "cmd.exe"

args = "/C %s > %%windir%%\\Temp\\%s 2>&1" % (self.__command, tmpFileName)
...
<StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>
```

`examples/atexec.py:221-237`

```python
smbConnection.getFile('ADMIN$', 'Temp\\%s' % tmpFileName, output_callback)
...
smbConnection.deleteFile('ADMIN$', 'Temp\\%s' % tmpFileName)
```

<a id="ioc-25"></a>

### IoC 25 - `wmipersist.py` permanent WMI subscription names `EF_<name>` and `TI_<name>`
**Surface:** WMI repository, Sysmon WMI events, WMI-Activity ETW/Event Viewer

`wmipersist.py` creates a permanent WMI subscription using a predictable object trio: an `ActiveScriptEventConsumer`, an `__EventFilter` named `EF_<operator-name>`, and, in timer mode, an `__IntervalTimerInstruction` named `TI_<operator-name>`. The default timer filter query is also very specific: `select * from __TimerEvent where TimerID = "TI_<name>" `, including the trailing space.


**Expected / proper baseline**

Permanent WMI event subscriptions are legitimate, but names and queries are normally product- or admin-defined rather than this `EF_`/`TI_` pairing. Microsoft documents that `__FilterToConsumerBinding` links the filter and consumer, and Sysmon can log WMI activity as Event IDs 19-21. See Microsoft WMI binding documentation: https://learn.microsoft.com/en-us/windows/win32/wmisdk/binding-an-event-filter-with-a-logical-consumer and Sysmon event filtering: https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-configuration-files.

**How to find it**
  
We would want to hunt `root\subscription` for the following:

- `ActiveScriptEventConsumer.Name = <name>` with `ScriptingEngine = VBScript`

- `__EventFilter.Name = EF_<same-name>`

- `__IntervalTimerInstruction.TimerId = TI_<same-name>`

- `__FilterToConsumerBinding.Filter = __EventFilter.Name="EF_<same-name>"`

- `__FilterToConsumerBinding.Consumer = ActiveScriptEventConsumer.Name="<same-name>"`

**Relevant code**

`examples/wmipersist.py:116-159`

```python
activeScript.ScriptingEngine = 'VBScript'

...

eventFilter.Name = 'EF_%s' % self.__options.name

...

wmiTimer.TimerId = 'TI_%s' % self.__options.name

...

eventFilter.Query = 'select * from __TimerEvent where TimerID = "TI_%s" ' % self.__options.name

...

filterBinding.Filter = '__EventFilter.Name="EF_%s"' % self.__options.name

filterBinding.Consumer = 'ActiveScriptEventConsumer.Name="%s"' % self.__options.name
```

<a id="ioc-43"></a>

### IoC 43 - `dcomexec.py` writes command output to `\\127.0.0.1\<share>\__<epoch-prefix>`
**Surface:** WMI/DCOM-created process command line, Sysmon process creation, Windows 4688, SMB ADMIN$ file access

`dcomexec.py` uses a very odd output filename: two underscores plus the first five characters of Python's `time.time()` string. On current epoch values this produces a short file such as `__1766`, then redirects output to `\\127.0.0.1\ADMIN$\__1766` by default. That local-loopback UNC redirection plus  `__\d{4,5}`. 

**Expected / proper baseline**
  
Normal administrative DCOM/WMI automation does not usually redirect command output to a loopback ADMIN$ UNC path with a two-underscore epoch-derived filename or actually use a redirect filename to begin with! I don't necessarily like these ones as there's many of them that feel more like gotchas that I picked up by using using EVENmonitor(https://github.com/NeffIsBack/EVENmonitor). 
**How to find it**

Hunt process creation and command-line telemetry for:

- `\\127.0.0.1\ADMIN$\__\d{4,5}` or `\\127.0.0.1\<share>\__\d{4,5}`

- DCOM/WMI parentage plus `1> \\127.0.0.1\...\__... 2>&1`

- SMB file create/read/delete of a root-level ADMIN$ file matching `^__\d{4,5}$`

Nothing too fancy or special but sometimes that's all that's needed. 

**Relevant code**

`examples/dcomexec.py:64,212,389,458`

```python

OUTPUT_FILENAME = '__' + str(time.time())[:5]

self._output = '\\' + OUTPUT_FILENAME

command += ' 1> ' + '\\\\127.0.0.1\\%s' % self._share + self._output + ' 2>&1'

```

<a id="ioc-66"></a>

### IoC 66 - rpcrelayclient uses `DummyOp` structure with future use reserved opnum 255

***Surface:** NTLM relay attacks, DCE/RPC relaying, Authentication spoofing and Network/ETW telemetry

ntlmrelayx’s RPC relay client sends a dummy DCE/RPC request using opnum = 255 after completing the RPC authentication exchange. For the supported relay targets in this code path, TSCH and ICPR, opnum 255 is not a valid method. ntlmrelayx/rpcrelayclient expect the server to return `nca_s_op_rng_error / RPC_S_PROCNUM_OUT_OF_RANGE` and treats that response as proof that authentication succeeded.

**Expected/Proper Baseline**

Non as this is not a real OpEnum and sticks out in context. This is a strong ntlmrelayx RPC relay fingerprint when observed immediately after an authenticated bind as it also uses the DummyOp to keep a target connection alive and so can be further added detection source.

**Relevant Code:**
```python
class DummyOp(NDRCALL):
    opnum = 255
    structure = (
    )
...


        try:
            req = DummyOp()
            self.session.request(req)
        except DCERPCException as e:
            if 'nca_s_op_rng_error' in str(e) or 'RPC_E_INVALID_HEADER' in str(e):
                return None, STATUS_SUCCESS
            elif 'rpc_s_access_denied' in str(e):
                return None, STATUS_ACCESS_DENIED
            else:
                LOG.info("Unexpected rpc code received from %s: %s" % (self.stringbinding, str(e)))
                return None, STATUS_ACCESS_DENIED

    def killConnection(self):
        if self.session is not None:
            self.session.get_rpc_transport().disconnect()
            self.session = None

    def keepAlive(self):
        try:
            req = DummyOp()
            self.session.request(req)
        except DCERPCException as e:
            if 'nca_s_op_rng_error' not in str(e) or 'RPC_E_INVALID_HEADER' not in str(e):
                raise
```
This is particualrly nice when factoring in that it provides an additional route to detect AD-CS ESC11 abuse as well as ESC8 when enlisting the use of RPC servers. 

**Source:**
`impacket/examples/ntlmrelayx/clients/rpcrelayclient.py`:L119

<a id="ioc-65"></a>
### IoC 65 - RemCom `Machine` field is random four-letter ASCII
**Surface:** SMB named pipe payload inspection, endpoint telemetry from RemCom-style service execution, full packet capture with SMB payload visibility

  
Impacket's PsExec-style RemCom client fills the RemCom protocol `Machine` field with four random ASCII letters. A real client identifier should normally reflect a meaningful machine/client name, not a tiny random mixed-case token.
  

**Expected / Proper Baseline**


PsExec-like tooling that identifies the caller should provide a real client hostname or stable machine identifier. A four-character random string like `aZqB` otherwise sticks out in a normal environment.
  
**How To Find It**

Inspect writes to the RemCom main communication pipe and flag:


- Named pipe: `\RemCom_communicaton`

- RemCom message `Machine` field matches `^[A-Za-z]{4}$`

- Value does not match the source host's NetBIOS/DNS name


This pairs naturally with the already-known misspelled RemCom pipe name, but it is an independent payload-level fingerprint, that albeit can trivially be remediated. The logic here is that one or three are remediable, but can someone handle 30? 60? :) 

**Relevant Code**

```python

packet = RemComMessage()

pid = os.getpid()

  

packet['Machine'] = ''.join([random.choice(string.ascii_letters) for _ in range(4)])

packet['Command'] = self.__command

packet['ProcessID'] = pid

```

Source: `examples/psexec.py`, also present in related RemCom-using examples.

<a id="cat-secretsdump-drsuapi-and-vss"></a>

## secretsdump, DRSUAPI, and VSS

<a id="ioc-22"></a>

### IoC 22 - `secretsdump.py` DRSBind advertises `dwExtCaps = 0xffffffff`
**Surface:** DRSUAPI RPC traffic, DC replication telemetry

During DCSync-style extraction, Impacket builds a `DRSBind` request with `dwExtCaps` set to all bits: `0xffffffff`. That all-capabilities value is a strong implementation quirk when visible in DRSUAPI telemetry.

**How to find it**

Decode DRSUAPI `DRSBind` and alert when:
  
- `SiteObjGuid = NULLGUID`

- `Pid = 0`

- `dwExtCaps = 0xffffffff`

- caller is not a DC. Note that ESC8+coercion abuse may lead to DC compromise so a smarter detection would be when the caller doesn't match the IP/MAC of the known Domain Controllers.  

**Relevant code**

`impacket/examples/secretsdump.py:524-538`

```python
request = drsuapi.DRSBind()

request['puuidClientDsa'] = drsuapi.NTDSAPI_CLIENT_GUID

...

drs['SiteObjGuid'] = drsuapi.NULLGUID

drs['Pid'] = 0

...

drs['dwExtCaps'] = 0xffffffff
```

<a id="ioc-23"></a>

### IoC 23 - `secretsdump.py` DRSGetNCChanges requests one object with zero USNs
**Surface:** DRSUAPI RPC traffic, DC replication telemetry  

Impacket-secretsdump requests replication data one object at a time using `DRSGetNCChanges` V8, zeroes both high-watermark USNs, uses no up-to-date vector, and sets `EXOP_REPL_OBJ`. 

**How to find it**

Decode DRSUAPI `DRSGetNCChanges` and alert when:

- `dwInVersion = 8`

- `usnHighObjUpdate = 0`

- `usnHighPropUpdate = 0`

- `pUpToDateVecDest = NULL`

- `ulFlags = DRS_INIT_SYNC | DRS_WRIT_REP`

- `cMaxObjects = 1`

- `cMaxBytes = 0`

- `ulExtendedOp = EXOP_REPL_OBJ`

**Relevant code**

`impacket/examples/secretsdump.py:630-648`  

```python
request['dwInVersion'] = 8

request['pmsgIn']['tag'] = 8

request['pmsgIn']['V8']['usnvecFrom']['usnHighObjUpdate'] = 0

request['pmsgIn']['V8']['usnvecFrom']['usnHighPropUpdate'] = 0

request['pmsgIn']['V8']['pUpToDateVecDest'] = NULL

request['pmsgIn']['V8']['ulFlags'] =  drsuapi.DRS_INIT_SYNC | drsuapi.DRS_WRIT_REP

request['pmsgIn']['V8']['cMaxObjects'] = 1

request['pmsgIn']['V8']['cMaxBytes'] = 0

request['pmsgIn']['V8']['ulExtendedOp'] = drsuapi.EXOP_REPL_OBJ
```

<a id="ioc-24"></a>

### IoC 24 - `secretsdump.py` VSS method uses predictable `vssadmin` and temp-copy sequence
**Surface:** Process command line on DCs, service execution telemetry

When using VSS extraction, Impacket runs a predictable `vssadmin` sequence through `%COMSPEC%`, copies `NTDS.dit` from a shadow copy to `%SYSTEMROOT%\Temp\<8 letters>.tmp`, then optionally deletes the shadow.

**How to find it**

Alert on domain controllers for:

- `vssadmin list shadows /for=<drive>`

- `vssadmin create shadow /For=<drive>`

- copy from `GLOBALROOT\Device\HarddiskVolumeShadowCopy*` to `%SYSTEMROOT%\Temp\<A-Za-z>{8}.tmp`

- `vssadmin delete shadows /shadow="{GUID}" /Quiet`

**Relevant code**

`impacket/examples/secretsdump.py:1167-1172`

```python
command = '%COMSPEC% /C vssadmin list shadows /for=' + forDrive

self.__executeRemote(command)
```

`impacket/examples/secretsdump.py:1251-1267`

```python
self.__executeRemote('%%COMSPEC%% /C vssadmin create shadow /For=%s' % ntdsDrive)

tmpFileName = ''.join([random.choice(string.ascii_letters) for _ in range(8)]) + '.tmp'

self.__executeRemote('%%COMSPEC%% /C copy %s%s %%SYSTEMROOT%%\\Temp\\%s' % (shadow, ntdsLocation[2:], tmpFileName))

self.__executeRemote('%%COMSPEC%% /C vssadmin delete shadows /shadow="{%s}" /Quiet' % shadowId)
```

<a id="ioc-36"></a>

### IoC 36 - `keylistattack.py` / `secretsdump.py` sends `KERB-KEY-LIST-REQ [161]` for `krbtgt` with RC4-only requested key list
**Surface:** Kerberos TGS-REQ packet capture, KDC telemetry

The key list attack creates a partial RODC TGT and then sends a TGS-REQ for `krbtgt/<domain>` containing `KERB_KEY_LIST_REQ` padata type `161`. The requested key list is encoded as `[23]`, which is RC4-HMAC, while the normal TGS etype list also includes AES and legacy RC4 variants.

**Expected / proper baseline**

MS-KILE documents that when a KDC receives a TGS-REQ for `krbtgt` with `KERB-KEY-LIST-REQ [161]`, it can return long-term secrets in `KERB-KEY-LIST-REP [162]`. This should be highly unusual outside RODC password replication behavior and controlled testing. Reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/732211ae-4891-40d3-b2b6-85ebd6f5ffff.

Additionally, we would not expect RC4-HMAC to be the only offered value. A recurring Impacket pattern is sparse or monolithic negotiation. For example, when authenticating via SPNEGO with `-k`, Impacket offers only Kerberos in the mechList, whereas normal Windows authentication often includes four or five OID entries, with the fifth being KRB5 User-to-User/PKU2U in some cases. Similarly, without `-k`, Impacket advertises only the NTLMSSP OID.

**How to find it**

Alert on Kerberos TGS-REQ where:

- `padata-type = 161` (`KERB_KEY_LIST_REQ`)

- `sname = krbtgt/<realm>`

- key list value is `[23]` / RC4-HMAC

- request comes from a non-RODC host or unexpected subnet  

**Relevant code**

`examples/keylistattack.py:111-118` and `impacket/examples/secretsdump.py:3570-3632`  

```python
logging.info('Using the KERB-KEY-LIST request method. Tickets everywhere!')

...

tgsReq['padata'][1]['padata-type'] = int(constants.PreAuthenticationDataTypes.KERB_KEY_LIST_REQ.value)

encodedKeyReq = encoder.encode([23], asn1Spec=SequenceOf(componentType=Integer()))

tgsReq['padata'][1]['padata-value'] = encodedKeyReq

...

reqBody['sname']['name-string'][0] = serverName

reqBody['sname']['name-string'][1] = self.__domain
```

<a id="cat-mssql"></a>

## MSSQL

<a id="ioc-30"></a>

### IoC 30 - MSSQL LOGIN7 has constant `ClientID = 01:02:03:04:05:06` and spoofed SSMS metadata
**Surface:** TDS LOGIN7 in packet capture, SQL Server connection telemetry where client app/host is captured
  
The TDS LOGIN7 structure defaults `ClientID` to the constant bytes `01 02 03 04 05 06`. Unless overridden, Impacket also sends a workstation name like `DESKTOP-<8 uppercase hex>` and application/interface name `Microsoft SQL Server Management Studio - Query`. `ClientPID` is not the real process ID; it is a random integer from 0 to 1024.

**Expected / proper baseline**

MS-TDS defines `ClientPID` as the client application's process ID, `HostName` as the client machine name, `AppName` as the client application name, and `ClientID` as the NIC/MAC-based client ID. Reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/773a62b6-ee89-4c02-9e5e-344882630aac.

**How to find it**  

Decode TDS LOGIN7 and detect based on any or a combination of or all of:

- `ClientID == 01:02:03:04:05:06`

- `HostName` matches `DESKTOP-[0-9A-F]{8}`

- `AppName == CltIntName == Microsoft SQL Server Management Studio - Query`

- `ClientPID <= 1024` but not matching any process telemetry from the source host

**Relevant code**

`impacket/tds.py:320-347,1148-1150,1614-1618,1883-1887`

```python
("ClientProgVer", ">L=7"),

("ClientPID", "<L=0"),

...

("ClientID", '6s=b"\x01\x02\x03\x04\x05\x06"'),

...

self._workstation_id = workstation_id or f"DESKTOP-{uuid4().hex[:8].upper()}"

self._application_name = application_name or "Microsoft SQL Server Management Studio - Query"

...

login["ClientPID"] = random.randint(0, 1024)
```

<a id="ioc-31"></a>

### IoC 31 - MSSQL PRELOGIN uses fixed version bytes, `MSSQLServer`, and encryption-off negotiation
**Surface:** TDS PRELOGIN packet capture

The MSSQL client sends a PRELOGIN: `Version = 08 00 01 55 00 00`, `Encryption = ENCRYPT_OFF`, `ThreadID` chosen from only 0-65535, and `Instance = MSSQLServer\0`.

**Expected / proper baseline**  

MS-TDS defines PRELOGIN `VERSION`, `ENCRYPTION`, `INSTOPT`, and `THREADID` as client-provided fields. The encryption value `0x00` means encryption is available but off, and `INSTOPT` should be the target instance name or empty/null. Reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/60f56408-0188-4cd5-8b90-25c6f2423868.

**How to find it**

In TDS PRELOGIN packets, check for:
- `VERSION` bytes exactly `08 00 01 55 00 00`

- `ENCRYPTION = 0x00`

- `INSTOPT = "MSSQLServer\0"`

- `THREADID` always below 65536 across many connections

**Relevant code**

`impacket/tds.py:1194-1212`

```python
prelogin["Version"] = b"\x08\x00\x01\x55\x00\x00"

prelogin["Encryption"] = TDS_ENCRYPT_OFF

prelogin["ThreadID"] = struct.pack("<L", random.randint(0, 65535))

prelogin["Instance"] = b"MSSQLServer\x00"
```

<a id="ioc-32"></a>

### IoC 32 - `mssqlshell.py` upload path echoes base64 chunks to `.b64`, decodes with `certutil`, then validates MD5
**Surface:** SQL audit, SQL Server default trace/Extended Events, process creation from `sqlservr.exe`, EDR command line

The MSSQL shell upload routine uses `xp_cmdshell` to append base64 chunks into `<remote_path>.b64`, checks it with `xp_fileexist`, runs `certutil -decode`, deletes the `.b64`, and runs `certutil -hashfile <file> MD5`.

**Expected / proper baseline**  

Not applicable. This is a hyper-specific TTP observed in Impacket's implementation. Because this backend behavior is usually hidden from the operator, it is easy to miss in the execution chain.

**How to find it**

Alert on SQL Server hosts for this sequence under `sqlservr.exe`:

- repeated `cmd.exe /c echo <base64> >> "<path>.b64"`

- `certutil -decode "<path>.b64" "<path>"`

- `del "<path>.b64"`

- `certutil -hashfile "<path>" MD5`

**Relevant code**

`impacket/examples/mssqlshell.py:180-231`
  
```python
cmd = 'echo ' + b64enc_data[i:i+BUFFER_SIZE] + ' >> "' + remote_path + '.b64"'

self.sql_query("EXEC xp_cmdshell '" + cmd + "'")

...

cmd = 'certutil -decode "' + remote_path + '.b64" "' + remote_path + '"'

...

cmd = 'certutil -hashfile "' + remote_path + '" MD5'

```

<a id="ioc-33"></a>

### IoC 33 - `mssqlshell.py` SQL Agent execution creates self-deleting `IdxDefrag<GUID>` CmdExec jobs
**Surface:** SQL Agent job history, MSDB tables, SQL audit, process creation from SQL Agent service

The `sp_start_job` command path creates a SQL Agent job named `IdxDefrag` plus a GUID, description `INDEXDEFRAG`, step name `Defragmentation`, subsystem `CMDEXEC`, owner `sa`, and `@delete_level=3` so the job deletes itself after execution.

**Expected / proper baseline**

`sp_add_job` creates SQL Agent jobs and `@delete_level = 3` means the job executes once and self-deletes, removing its history. `sp_add_jobstep` documents `CmdExec` as an operating-system command subsystem. References: https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-add-job-transact-sql and https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-add-jobstep-transact-sql.

  You generally don't expect to these, but this isn't the most robust of detections compared to some of the other things present on this list.

**How to find it**  

Hunt SQL telemetry and MSDB remnants for:

- job name starts with `IdxDefrag`

- description `INDEXDEFRAG`

- step name `Defragmentation`

- subsystem `CMDEXEC`

- owner `sa`

- `delete_level = 3` # this and the owner being sa can prolly be axed to be fair as they are to be expected but leaving here to cover the full chain and hopefully inspire more ideas.

**Relevant code**

`impacket/examples/mssqlshell.py:254-265`

```python
"SET @job='IdxDefrag'+CONVERT(NVARCHAR(36),NEWID());"

"EXEC msdb..sp_add_job @job_name=@job,@description='INDEXDEFRAG',"

"@owner_login_name='sa',@delete_level=3;"

"EXEC msdb..sp_add_jobstep @job_name=@job,@step_id=1,@step_name='Defragmentation',"

"@subsystem='CMDEXEC',@command='%s',@on_success_action=1;"
```

<a id="cat-ntlmrelayx-http-webdav-rdp-and-sccm"></a>

## ntlmrelayx HTTP, WebDAV, RDP, and SCCM

<a id="ioc-35"></a>

### IoC 35 - ntlmrelayx HTTP/WinRM local-auth challenge has empty AV pairs and printable challenge material
**Surface:** HTTP/WinRM NTLM challenge in packet capture or proxy logs

When ntlmrelayx handles local authentication rather than relaying a real target challenge, it builds its own NTLM Type 2 challenge. It sets `domain_name` to an empty string, advertises `NTLMSSP_NEGOTIATE_TARGET_INFO`, but sends `TargetInfoFields_len = 0`, sets `Version` to eight `0xff` bytes, and populates the challenge from printable characters.

**Expected / proper baseline**

MS-NLMP defines `ServerChallenge` as an 8-byte nonce and says TargetInfo, when present, is a sequence of AV pairs. It also says domain-joined servers return the domain in TargetName. References: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/801a4681-8809-4be9-ab0d-61dcfe762786 and https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b46d85da-050d-4f18-a2e1-14863f587163.

**How to find it**

Decode HTTP `WWW-Authenticate: NTLM <blob>` or WinRM `WWW-Authenticate: Negotiate <blob>` Type 2 messages and alert on:
  
- `NEGOTIATE_TARGET_INFO` flag set but TargetInfo length is zero

- empty target/domain name

- Version field `ff ff ff ff ff ff ff ff`

- challenge bytes are all printable ASCII

**Relevant code**

`impacket/examples/ntlmrelayx/servers/httprelayserver.py:343-358` and `impacket/examples/ntlmrelayx/servers/winrmrelayserver.py:357-372`

```python
ansFlags |= ntlm.NTLMSSP_NEGOTIATE_VERSION | ntlm.NTLMSSP_NEGOTIATE_TARGET_INFO | \

            ntlm.NTLMSSP_TARGET_TYPE_SERVER | ntlm.NTLMSSP_NEGOTIATE_NTLM

...

challengeMessage['domain_name'] = ""

challengeMessage['challenge'] = ''.join(random.choice(string.printable) for _ in range(64))

challengeMessage['TargetInfoFields'] = ntlm.AV_PAIRS()

challengeMessage['TargetInfoFields_len'] = 0

challengeMessage['Version'] = b'\xff' * 8

```

<a id="ioc-44"></a>

### IoC 44 - ntlmrelayx WPAD serves a fixed PAC body with compact `FindProxyForURL` formatting
**Surface:** HTTP packet capture, proxy/WPAD logs, browser auto-proxy retrieval logs

The ntlmrelayx HTTP and WinRM relay servers generate the same compact PAC JavaScript with no normal formatting, hard-coded localhost bypasses, `dnsDomainIs(host, "<wpad_host>")`, and `return "PROXY <wpad_host>:80; DIRECT";`. The exact function body is stable and very searchable in HTTP responses.

**Expected / proper baseline**
  
Enterprise PAC files are usually longer, and/or more complex. For engineers out there, simply take your PAC and say if a entry doesn't look like mine; detect it. I think a superior detection to this would be to detect anyone standing up a WPAD file that contains a PAC body that doesn't look like the one in your enterprise. This way instead of worrying that someone may break the detection; you are more broadly catching the core attack; rogue WPAD set up for spoofing/capturing and relaying HTTP auth.

**How to find it**

Inspect WPAD/PAC responses for:

- `function FindProxyForURL(url, host){if ((host == "localhost") || shExpMatch(host, "localhost.*") ||(host == "127.0.0.1"))`

- `return "PROXY <host>:80; DIRECT";} `

- `Content-type: application/x-ns-proxy-autoconfig`
- Or following a broader strategy, looking for ones that are different than what the enterprise is running currently. 

For added benefit, we could also potentially correlate the above with repeated 401/407 NTLM challenges from the same listener. This isn't significantly more useful though I believe as I would still rather detect the core issue of someone trying to spoof WPAD.

**Relevant code**

`impacket/examples/ntlmrelayx/servers/httprelayserver.py:62-64,111`
  
```python
self.wpad = 'function FindProxyForURL(url, host){if ((host == "localhost") || shExpMatch(host, "localhost.*") ||' \

            '(host == "127.0.0.1")) return "DIRECT"; if (dnsDomainIs(host, "%s")) return "DIRECT"; ' \

            'return "PROXY %s:80; DIRECT";} '

self.send_header('Content-type', 'application/x-ns-proxy-autoconfig')
```

<a id="ioc-45"></a>

### IoC 45 - ntlmrelayx WebDAV bait returns `webdavrelay` XML with fixed 2016/2017 timestamps
**Surface:** HTTP/WebDAV packet capture, proxy logs, endpoint WebClient/WebDAV telemetry

For WebDAV `PROPFIND`, ntlmrelayx returns synthetic XML containing a fake host/path of `http://webdavrelay/file/`, a display name of either `a` or `image.JPG`, a creation date of `2016-11-12T22:00:22Z`, and a last-modified time of `Mon, 20 Mar 2017 00:00:22 GMT`.

As many of you may have noticed, hardcoded dates, attributes, timestamps, names, and similar values recur throughout the Impacket project. I noticed the same pattern recently while implementing a new Impacket module for MS-NEGOEX.

**Expected / proper baseline**

Obviously, a real WebDAV server would return their actual hostname, resource names, and filesystem or application timestamps as they apply to the specific system. A hard-coded `webdavrelay` URI with identical stale timestamps across clients should not appear normally. This, like the WPAD detection can be made more broadly across the whole AD/Windows infrastructure to detect these anomalies as that in of itself is a sign of tradecraft. 

**How to find it**

Analyze WebDAV XML Responses for the potential following:

- `http://webdavrelay/file/`

- `<D:creationdate>2016-11-12T22:00:22Z</D:creationdate>`

- `<D:getlastmodified>Mon, 20 Mar 2017 00:00:22 GMT</D:getlastmodified>`

- `<D:displayname>image.JPG</D:displayname>` with ETag `4ebabfcee4364434dacb043986abfffe`

**Relevant code**

`impacket/examples/ntlmrelayx/servers/httprelayserver.py:191-193`

```python
content = b"""<?xml version="1.0"?><D:multistatus xmlns:D="DAV:"><D:response><D:href>http://webdavrelay/file/image.JPG/</D:href>...

<D:creationdate>2016-11-12T22:00:22Z</D:creationdate>...

<D:getlastmodified>Mon, 20 Mar 2017 00:00:22 GMT</D:getlastmodified>...

```

<a id="ioc-46"></a>

### IoC 46 - ntlmrelayx multi-relay redirects to `/<10 uppercase letters-or-digits>`
**Surface:** HTTP packet capture, proxy logs, web server logs


When ntlmrelayx wants to keep relaying a client to additional targets, it sends a `307` redirect to a randomly generated root path of exactly ten uppercase letters/digits, while also setting `WWW-Authenticate: NTLM` or `Proxy-Authenticate: NTLM`, `Connection: keep-alive`, and `Content-Length: 0`.

**Expected / proper baseline**

Legitimate NTLM-protected web apps can redirect during authentication, but a bare root path of exactly ten uppercase alphanumeric characters combined with another NTLM challenge and zero-length body is unusual BUTT not definitive. This might've been the only thing where I have *some* evidence to suggest that edge cases may have something similar but I believe that for most medium to large places outside of F500, a detection centered around this could reasonably be deployed with trivial/minimal tuning requirements.

**How to find it**


Look for HTTP responses that contain from below:

- status is `307`

- `Location` matches `^/[A-Z0-9]{10}$`

- `WWW-Authenticate: NTLM` or `Proxy-Authenticate: NTLM` is present

- `Content-Length: 0` and `Connection: keep-alive` are present

**Relevant code**

`impacket/examples/ntlmrelayx/servers/httprelayserver.py:219-228`  

```python
rstr = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10))

self.send_response(307)

self.send_header('WWW-Authenticate', 'NTLM')

self.send_header('Location','/%s' % rstr)

self.send_header('Content-Length','0')
```

<a id="ioc-47"></a>

### IoC 47 - ntlmrelayx RDP relay presents a self-signed certificate with CN `RDP-Server`
**Surface:** RDP TLS handshake, certificate telemetry, Zeek/JA3-adjacent TLS logs

The RDP relay server generates a self-signed certificate that has a default common name is literally `RDP-Server`, with a small random serial number between 0 and 100000 and one-year validity. 

**Expected / proper baseline**  

Windows RDP certificates usually identify the host FQDN or machine name and either come from the clients CA(using AD-CS or smth else) or the local machine certificate store. A generic self-signed `CN=RDP-Server` on an host is usually indication of a relay point/listener. 

My testing has provided no proof that this would/could reasonably occur elsewhere. I had also tried correlating these at work and made no such detection. 

**How to find it**

Inspect RDP TLS server certificates for:

- subject CN exactly `RDP-Server`

- issuer equals subject

- serial number in decimal range `0..100000`

- one-year validity beginning near first observation

**Relevant code**

`impacket/examples/ntlmrelayx/utils/rdp_ssl.py:52,58-64`


```python
def generate_self_signed_cert(common_name="RDP-Server"):

    cert.get_subject().CN = common_name

    cert.set_serial_number(random.randint(0, 100000))

    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)

    cert.set_issuer(cert.get_subject())

    cert.sign(key, "sha256")
```

<a id="ioc-49"></a>

### IoC 49 - ntlmrelayx SCCM policy attack speaks with old ConfigMgr client strings
**Surface:** SCCM management point HTTP logs, packet capture, IIS logs, proxy logs

The SCCM policies attack builds very recognizable client-registration and policy-request XML. It advertises `AgentIdentity="CCMSetup.exe"`, `AgentVersion="5.00.8325.0000"`, `ClientVersion>5.00.8325.0000`, `Locale ID=2057`, `CodePage=850`, `ClientCapabilities=NonSSL`, fixed message IDs, and a self-signed certificate with common name `ConfigMgr Client`.

**Expected / proper baseline**

Current ConfigMgr/SCCM clients should report versions that match the estate and usually have real client state, site codes, locale/codepage values, and certificate material consistent with deployed clients. 

Like the WPAD/PAC detections, a good detection here would be noting/checking for registrations that occur that use inappropriate/mismatched values than what the current misconfiguration man.. I mean Config manager deployment has set up. 

**How to find it**

On SCCM MP/IIS/proxy logs or decrypted HTTP captures, alert on:

- `CCM_POST /ccm_system_windowsauth/request`

- XML containing `AgentIdentity="CCMSetup.exe"` and `AgentVersion="5.00.8325.0000"`

- `ClientVersion>5.00.8325.0000</ClientVersion>`

- `<Property Name="ClientCapabilities">NonSSL</Property>`

- certificate subject CN `ConfigMgr Client`

- fixed IDs `5DD100CD-DF1D-45F5-BA17-A327F43465F8` or `041A35B4-DCEE-4F64-A978-D4D489F47D28`

**Relevant code**

`impacket/examples/ntlmrelayx/attacks/httpattacks/sccmpoliciesattack.py:43-56,90,447`

```python
<AgentInformation AgentIdentity="CCMSetup.exe" AgentVersion="5.00.8325.0000" AgentType="0" />

<Property Name="Locale ID" Value="2057" />

<Property Name="ClientCapabilities">NonSSL</Property>

<ClientVersion>5.00.8325.0000</ClientVersion><CodePage>850</CodePage><SystemDefaultLCID>2057</SystemDefaultLCID>

x509.NameAttribute(NameOID.COMMON_NAME, "ConfigMgr Client")

self.client.request("CCM_POST", f"{management_point}/ccm_system_windowsauth/request", registration_request_payload, headers=headers)
```

<a id="conclusion"></a>

## Conclusion

While a lot of these quirks can be easily changed and modified such as the file names used to redirect execution outputs, new computer registration naming conventions etc, others exist deep within the protocol layers. That's where I believe detection best lives. A lot of the quirks in krb5/ntlmrelayx/spnego/ntlm etc are not accessible to the operator and so when using them to write tools; you often may fail to notice that they may be giving something sneaky away.
