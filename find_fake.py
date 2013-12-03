#!/usr/bin/python
# -*- encoding: utf-8 -*-
"""
 Find Fake (File Path, Filename fake)
 @author: Dong-ha, Lee (ldh0227)
 @contact: ldh0227@kaist.ac.kr
 @copyright: All information in this Code belong to the Cyber ​​Security Research Center, Korea Advanced Institute of Science and Technology.
 @license: LGPL
 @summary:
    Some malawre using fake path and name when Create or Execute.
    This module give some match. 
"""

import os
import time
import sys

lstSysdirDllName = [
                    "6to4svc", "aaaamon", "aaclient", "acctres", "acledit", "aclui",
                    "activeds", "actxprxy", "admparse", "adptif", "adsldp", "adsldpc",
                    "adsmsext", "adsnds", "adsnt", "adsnw", "advapi32", "advpack",
                    "alrsvc", "amstream", "apcups", "apphelp", "appmgmts", "appmgr",
                    "asferror", "asycfilt", "atkctrs", "atl", "atmfd", "atmlib", "atmpvcno",
                    "atrace", "audiodev", "audiosrv", "authz", "autodisc", "avicap", "avicap32",
                    "avifil32", "avifile", "avmeter", "avtapi", "avwav", "azroles", "basesrv",
                    "batmeter", "batt", "bidispl", "bitsprx2", "bitsprx3", "bitsprx4", "blackbox",
                    "bootvid", "browselc", "browser", "browseui", "browsewm", "bthci", "bthserv",
                    "btpanui", "cabinet", "cabview", "camocx", "capesnpn", "cards", "catsrv",
                    "catsrvps", "catsrvut", "ccfgnt", "cdfview", "cdm", "cdmodem", "cdosys",
                    "certcli", "certmgr", "cewmdm", "cfgbkend", "cfgmgr32", "chsbrkr", "chtbrkr",
                    "ciadmin", "cic", "ciodm", "clb", "clbcatex", "clbcatq", "cliconfg", "clusapi",
                    "cmcfg32", "cmdial32", "cmpbk32", "cmprops", "cmsetacl", "cmutil", "cnbjmon",
                    "cnetcfg", "cnvfat", "colbact", "comaddin", "comcat", "comctl32", "comdlg32",
                    "commdlg", "compatui", "compobj", "compstui", "comrepl", "comres", "comsnap",
                    "comsvcs", "comuid", "confmsp", "console", "corpol", "credssp", "credui",
                    "crtdll", "crypt32", "cryptdlg", "cryptdll", "cryptext", "cryptnet", "cryptsvc",
                    "cryptui", "cscdll", "cscui", "csrsrv", "csseqchk", "ctl3d32", "ctl3dv2",
                    "c_g18030", "c_is2022", "d3d8", "d3d8thk", "d3d9", "d3dcompiler_33",
                    "d3dcompiler_34", "d3dcompiler_35", "d3dcompiler_36", "d3dcompiler_37",
                    "d3dcompiler_38", "d3dim", "d3dim700", "d3dpmesh", "d3dramp", "d3drm", "d3dx10_33",
                    "d3dx10_34", "d3dx10_35", "d3dx10_36", "d3dx10_37", "d3dx10_38", "d3dx9_24",
                    "d3dx9_25", "d3dx9_26", "d3dx9_27", "d3dx9_28", "d3dx9_29", "d3dx9_30", "d3dx9_31",
                    "d3dx9_32", "d3dx9_33", "d3dx9_34", "d3dx9_35", "d3dx9_36", "d3dx9_37", "d3dx9_38",
                    "d3dxof", "danim", "dataclen", "datime", "davclnt", "dbgeng", "dbghelp", "dbmsrpcn",
                    "dbnetlib", "dbnmpntw", "dciman32", "ddeml", "ddraw", "ddrawex", "deployjava1",
                    "deskadp", "deskmon", "deskperf", "devenum", "devmgr", "dfrgres", "dfrgsnap",
                    "dfrgui", "dfshim", "dfsshlex", "dgnet", "dgrpsetu", "dgsetup", "dhcpcsvc",
                    "dhcpmon", "dhcpqec", "dhcpsapi", "diactfrm", "digest", "dimap", "dimsntfy",
                    "dimsroam", "dinput", "dinput8", "diskcopy", "dispex", "dmband", "dmcompos",
                    "dmconfig", "dmdlgs", "dmdskmgr", "dmdskres", "dmime", "dmintf", "dmloader",
                    "dmocx", "dmscript", "dmserver", "dmstyle", "dmsynth", "dmusic", "dmutil",
                    "dnsapi", "dnsrslvr", "docprop", "docprop2", "dot3api", "dot3cfg", "dot3dlg",
                    "dot3gpclnt", "dot3msm", "dot3svc", "dot3ui", "dpcdll", "dplay", "dplayx",
                    "dpmodemx", "dpnaddr", "dpnet", "dpnhpast", "dpnhupnp", "dpnlobby", "dpnmodem",
                    "dpnwsock", "dpserial", "dpvacm", "dpvoice", "dpvvox", "dpwsock", "dpwsockx",
                    "drmclien", "drmstor", "drmv2clt", "drprov", "ds16gt", "ds32gt", "dsauth",
                    "dsdmo", "dsdmoprp", "dskquota", "dskquoui", "dsound", "dsound3d", "dsprop",
                    "dsprpres", "dsquery", "dssec", "dssenh", "dsuiext", "dswave", "duser", "dx7vb",
                    "dx8vb", "dxdiagn", "dxmasf", "dxtmsft", "dxtrans", "eapolqec", "eapp3hst",
                    "eappcfg", "eappgnui", "eapphost", "eappprxy", "eapqec", "eapsvc", "efsadu",
                    "els", "encapi", "encdec", "eqnclass", "ersvc", "es", "esent", "esent97", "esentprf",
                    "eventcls", "eventlog", "expsrv", "extmgr", "exts", "f3ahvoas", "faultrep", "fde",
                    "fdeploy", "feclient", "filemgmt", "fldrclnr", "fltlib", "fmifs", "fontext",
                    "fontsub", "framebuf", "fsusd", "ftsrch", "fwcfg", "gcdef", "gdi32", "getuname",
                    "glmf32", "glu32", "gpedit", "gpkcsp", "gpkrsrc", "gptext", "h323msp", "hal",
                    "hccoin", "hhsetup", "hid", "hlink", "hnetcfg", "hnetmon", "hnetwiz", "hotplug",
                    "hticons", "httpapi", "htui", "hypertrm", "iasacct", "iasads", "iashlpr", "iasnap",
                    "iaspolcy", "iasrad", "iasrecst", "iassam", "iassdo", "iassvcs", "icaapi", "icardie",
                    "iccvid", "icfgnt5", "icm32", "icmp", "icmui", "icwdial", "icwphbk", "idndl", "idq",
                    "ieakeng", "ieaksie", "ieakui", "ieapfltr", "iedkcs32", "ieencode", "ieframe",
                    "iepeers", "iernonce", "iertutil", "iesetup", "ieui", "ifmon", "ifsutil", "igmpagnt",
                    "iissuba", "ils", "imagehlp", "imeshare", "imgutil", "imjp81k", "imm32", "inetcfg",
                    "inetcomm", "inetcplc", "inetmib1", "inetpp", "inetppui", "inetres", "infosoft",
                    "initpki", "input", "inseng", "iologmsg", "iphlpapi", "ipmontr", "ipnathlp", 
                    "ippromon", "iprop", "iprtprio", "iprtrmgr", "ipsecsnp", "ipsecsvc", "ipsmsnap", 
                    "ipv6mon", "ipxmontr", "ipxpromn", "ipxrip", "ipxrtmgr", "ipxsap", "ipxwan", 
                    "ir32_32", "ir41_qc", "ir41_qcx", "ir50_32", "ir50_qc", "ir50_qcx", "irclass", 
                    "isign32", "isrdbg32", "itircl", "itss", "iuengine", "ixsso", "iyuv_32", "jet500", 
                    "jgaw400", "jgdw400", "jgmd400", "jgpl400", "jgsd400", "jgsh400", "jobexec", 
                    "jscript", "jsko", "jsproxy", "kbd101", "kbd101a", "kbd101b", "kbd101c", "kbd103", 
                    "kbd106", "kbd106n", "kbdal", "kbdax2", "kbdaze", "kbdazel", "kbdbe", "kbdbene", 
                    "kbdbhc", "kbdblr", "kbdbr", "kbdbu", "kbdca", "kbdcan", "kbdcr", "kbdcz", "kbdcz1", 
                    "kbdcz2", "kbdda", "kbddv", "kbdes", "kbdest", "kbdfc", "kbdfi", "kbdfi1", "kbdfo", 
                    "kbdfr", "kbdgae", "kbdgkl", "kbdgr", "kbdgr1", "kbdhe", "kbdhe220", "kbdhe319", 
                    "kbdhela2", "kbdhela3", "kbdhept", "kbdhu", "kbdhu1", "kbdibm02", "kbdic", "kbdinbe1", 
                    "kbdinben", "kbdinmal", "kbdir", "kbdit", "kbdit142", "kbdiultn", "kbdjpn", "kbdkaz", 
                    "kbdkor", "kbdkyr", "kbdla", "kbdlk41a", "kbdlk41j", "kbdlt", "kbdlt1", "kbdlv", 
                    "kbdlv1", "kbdmac", "kbdmaori", "kbdmlt47", "kbdmlt48", "kbdmon", "kbdne", "kbdnec", 
                    "kbdnec95", "kbdnecat", "kbdnecnt", "kbdnepr", "kbdno", "kbdno1", "kbdpash", "kbdpl", 
                    "kbdpl1", "kbdpo", "kbdro", "kbdru", "kbdru1", "kbdsf", "kbdsg", "kbdsl", "kbdsl1", 
                    "kbdsmsfi", "kbdsmsno", "kbdsp", "kbdsw", "kbdtat", "kbdtuf", "kbdtuq", "kbduk", 
                    "kbdukx", "kbdur", "kbdus", "kbdusl", "kbdusr", "kbdusx", "kbduzb", "kbdycc", "kbdycl", 
                    "kd1394", "kdcom", "kerberos", "kernel32", "keymgr", "kmsvc", "korwbrkr", "ksuser", 
                    "l2gpstore", "langwrbk", "laprxy", "legitcheckcontrol", "licdll", "licmgr10", "licwmi", 
                    "linkinfo", "lmhsvc", "lmrt", "loadperf", "localsec", "localspl", "localui", "loghours", 
                    "lpk", "lprhelp", "lprmonui", "lsasrv", "lz32", "lzexpand", "mag_hook", "mapi32", 
                    "mapistub", "mcastmib", "mcd32", "mcdsrv32", "mchgrcoi", "mciavi32", "mcicda", "mciole16", 
                    "mciole32", "mciqtz32", "mciseq", "mciwave", "mdhcp", "mdminst", "mdwmdmsp", "mf3216", 
                    "mfc40", "mfc40loc", "mfc40u", "mfc42", "mfc42loc", "mfc42u", "mfc71", "mfc71u", "mfcsubs", 
                    "mfplat", "mgmtapi", "microsoft.managementconsole", "midimap", "mimefilt", "mlang", 
                    "mll_hp", "mll_mtf", "mll_qic", "mmcbase", "mmcex", "mmcfxcommon", "mmcndmgr", 
                    "mmcshext", "mmdrv", "mmfutil", "mmsystem", "mmutilse", "mnmdd", "mobsync", "modemui", 
                    "modex", "moricons", "mp43decd", "mp43dmod", "mp4sdecd", "mp4sdmod", "mpg4decd", 
                    "mpg4dmod", "mpr", "mprapi", "mprddm", "mprdim", "mprmsg", "mprui", "mqad", 
                    "mqcertui", "mqdscli", "mqgentr", "mqise", "mqlogmgr", "mqoa", "mqperf", "mqqm", 
                    "mqrt", "mqrtdep", "mqsec", "mqsnap", "mqtrig", "mqupgrd", "mqutil", "msaatext", 
                    "msacm", "msacm32", "msafd", "msapsspc", "msasn1", "msaudite", "mscat32", "mscms", 
                    "msconf", "mscoree", "mscorier", "mscories", "mscpx32r", "mscpxl32", "msctf", 
                    "msctfp", "msdadiag", "msdart", "msdelta", "msdmo", "msdtclog", "msdtcprx", "msdtctm", 
                    "msdtcuiu", "msdxmlc", "msencode", "msexch40", "msexcl40", "msfeeds", "msfeedsbs", 
                    "msftedit", "msgina", "msgsvc", "mshtml", "mshtmled", "mshtmler", "msi", "msident", 
                    "msidle", "msidntld", "msieftp", "msihnd", "msimg32", "msimsg", "msimtf", "msir3jp", 
                    "msisip", "msjet40", "msjetoledb40", "msjint40", "msjter40", "msjtes40", "msls31", 
                    "msltus40", "msnetobj", "msnsspc", "msobjs", "msoeacct", "msoert2", "msorc32r", 
                    "msorcl32", "mspatcha", "mspbde40", "mspmsnsv", "mspmsp", "msports", "msprivs", 
                    "msr2c", "msr2cenu", "msratelc", "msrating", "msrclr40", "msrd2x40", "msrd3x40", 
                    "msrecr40", "msrepl40", "msrle32", "mssap", "msscp", "mssha", "msshavmsg", "mssign32", 
                    "mssip32", "msswch", "mstask", "mstext40", "mstime", "mstlsapi", "mstscax", "msutb", 
                    "msv1_0", "msvbvm50", "msvbvm60", "msvcirt", "msvcp50", "msvcp60", "msvcr71", 
                    "msvcrt", "msvcrt20", "msvcrt40", "msvfw32", "msvidc32", "msvidctl", "msvideo", 
                    "msw3prt", "mswdat10", "mswebdvd", "mswmdm", "mswsock", "mswstr10", "msxbde40", 
                    "msxml", "msxml2", "msxml2r", "msxml3", "msxml3r", "msxml6", "msxml6r", "msxmlr", 
                    "msyuv", "mtxclu", "mtxdm", "mtxex", "mtxlegih", "mtxoci", "mycomput", "mydocs", 
                    "napipsec", "napmontr", "narrhook", "ncobjapi", "ncxpnt", "nddeapi", "nddenb32", 
                    "netapi", "netapi32", "netcfgx", "netevent", "netfxperf", "neth", "netid", "netlogon", 
                    "netman", "netmsg", "netplwiz", "netrap", "netshell", "netui0", "netui1", "netui2", 
                    "newdev", "nlhtml", "nlsdl", "nmapi", "nmevtmsg", "nmevtrpt", "nmmkcert", "normaliz", 
                    "npptools", "ntdll", "ntdsapi", "ntdsbcli", "ntlanman", "ntlanui", "ntlanui2", 
                    "ntlsapi", "ntmarta", "ntmsapi", "ntmsdba", "ntmsevt", "ntmsmgr", "ntmssvc", 
                    "ntprint", "ntsdexts", "ntshrui", "ntvdmd", "nwapi16", "nwapi32", "nwcfg", "nwevent", 
                    "nwprovau", "nwwks", "oakley", "objsel", "occache", "ocmanage", "odbc16gt", "odbc32", 
                    "odbc32gt", "odbcbcp", "odbcconf", "odbccp32", "odbccr32", "odbccu32", "odbcint", 
                    "odbcji32", "odbcjt32", "odbcp32r", "odbctrac", "oddbse32", "odexl32", "odfox32", 
                    "odpdx32", "odtext32", "offfilt", "ole2", "ole2disp", "ole2nls", "ole32", "oleacc", 
                    "oleaccrc", "oleaut32", "olecli", "olecli32", "olecnv32", "oledlg", "oleprn", 
                    "olepro32", "olesvr", "olesvr32", "olethk32", "onex", "opengl32", "osuninst", "p2p", 
                    "p2pgasvc", "p2pgraph", "p2pnetsh", "p2psvc", "packet", "panmap", "paqsp", "pautoenr", 
                    "pdh", "perfctrs", "perfdisk", "perfnet", "perfnw", "perfos", "perfproc", "perfts", 
                    "photometadatahandler", "photowiz", "pid", "pidgen", "pifmgr", "pjlmon", "plustab", 
                    "pmspl", "pngfilt", "pnrpnsp", "polstore", "portabledeviceapi", 
                    "portabledeviceclassextension", "portabledevicetypes", "portabledevicewiacompat", 
                    "portabledevicewmdrm", "powrprof", "prflbmsg", "printui", "profmap", "psapi", 
                    "psbase", "pschdprf", "psnppagn", "pstorec", "pstorsvc", "pthreadvc", "ptpusb", 
                    "ptpusd", "python26", "python27", "qagent", "qagentrt", "qasf", "qcap", "qcliprov", 
                    "qdv", "qdvd", "qedit", "qedwipes", "qmgr", "qmgrprxy", "qosname", "quartz", 
                    "query", "qutil", "racpldlg", "rasadhlp", "rasapi32", "rasauto", "raschap", 
                    "rasctrs", "rasdlg", "rasman", "rasmans", "rasmontr", "rasmxs", "rasppp", "rasqec", 
                    "rasrad", "rassapi", "rasser", "rastapi", "rastls", "rcbdyctl", "rdchost", "rdpcfgex", 
                    "rdpdd", "rdpsnd", "rdpwsx", "regapi", "regsvc", "regwizc", "remotepg", "rend", 
                    "resutils", "rhttpaa", "riched20", "riched32", "rnr20", "routetab", "rpcns4", 
                    "rpcrt4", "rpcss", "rsaenh", "rsfsaps", "rshx32", "rsmps", "rsvpmsg", "rsvpperf", 
                    "rsvpsp", "rtipxmib", "rtm", "rtutils", "safrcdlg", "safrdm", "safrslv", "samlib", 
                    "samsrv", "sbe", "sbeio", "scarddlg", "scardssp", "sccbase", "sccsccp", "scecli", 
                    "scesrv", "schannel", "schedsvc", "schkcore", "sclgntfy", "scoko", "scredir", 
                    "scriptpw", "scrobj", "scrrnko", "scrrun", "sdhcinst", "sdpblb", "seclogon", 
                    "secur32", "security", "sendcmsg", "sendmail", "sens", "sensapi", "senscfg", 
                    "serialui", "servdeps", "serwvdrv", "setupapi", "setupdll", "sfc", "sfcfiles", 
                    "sfc_os", "sfmapi", "shdoclc", "shdocvw", "shell", "shell32", "shellstyle", 
                    "shfolder", "shgina", "shimeng", "shimgvw", "shlwapi", "shmedia", "shscrap", 
                    "shsvcs", "sigtab", "sisbkup", "skdll", "slayerxp", "slbcsp", "slbiop", "slbrccsp", 
                    "smlogcfg", "snmpapi", "snmpsnap", "softpub", "spmsg", "spmsgxp_2k3", "spnike", 
                    "spoolss", "sprio600", "sprio800", "spxcoins", "sqlsrv32", "sqlunirl", "sqlwid", 
                    "sqlwoa", "srclient", "srrstr", "srsvc", "srvsvc", "ssdpapi", "ssdpsrv", "stclient", 
                    "sti", "sti_ci", "stobject", "storage", "storprop", "streamci", "strmdll", "strmfilt", 
                    "svcpack", "swprv", "sxs", "synceng", "syncui", "sysinv", "syssetup", "t2embed", 
                    "tapi", "tapi3", "tapi32", "tapiperf", "tapisrv", "tapiui", "tcpmib", "tcpmon", 
                    "tcpmonui", "termmgr", "termsrv", "themeui", "tlntsvrp", "toolhelp", "tprdpw32", 
                    "tpsvc", "tpvmmon", "tpvmmondeu", "tpvmmonjpn", "tpvmmonui", "tpvmmonuideu", 
                    "tpvmmonuijpn", "tpvmw32", "traffic", "trkwks", "tsappcmp", "tsbyuv", "tscfgwmi", 
                    "tsd32", "tsddd", "tsgqec", "tspkg", "twext", "txflog", "typelib", "udhisapi", 
                    "ufat", "ulib", "umandlg", "umdmxfrm", "umpnpmgr", "uniime", "unimdmat", "uniplat", 
                    "untfs", "upnp", "upnphost", "upnpui", "ureg", "url", "urlmon", "usbmon", "usbui", 
                    "user32", "userenv", "usp10", "utildll", "uxtheme", "vbajet32", "vbscript", "vbsko", 
                    "vcdex", "vdmdbg", "vdmredir", "ver", "verifier", "version", "vfpodbc", "vga", 
                    "vga256", "vga64k", "vjoy", "vmguestlib", "vmguestlibjava", "vmhgfs", 
                    "vmupgradeatshutdownwxp", "vmwogl32", "vmx_fb", "vmx_mode", "vsocklib", "vssapi", 
                    "vss_ps", "vwipxspx", "w32time", "w32topl", "w3ssl", "wavemsp", "wdfapi", 
                    "wdfcoinstaller01007", "wdigest", "webcheck", "webclnt", "webhits", "webvw", 
                    "wiadefui", "wiadss", "wiascr", "wiaservc", "wiashext", "wiavideo", "wiavusd", 
                    "wifeman", "win32spl", "win87em", "winbrand", "windowscodecs", "windowscodecsext", 
                    "winfax", "winhttp", "wininet", "winipsec", "winmm", "winnls", "winntbbu", "winrnr", 
                    "winscard", "winshfhc", "winsock", "winsrv", "winsta", "winstrm", "wintrust", 
                    "winusb", "winusbcoinstaller", "wkssvc", "wlanapi", "wldap32", "wlnotify", "wmadmod", 
                    "wmadmoe", "wmasf", "wmdmlog", "wmdmps", "wmdrmdev", "wmdrmnet", "wmdrmsdk", 
                    "wmerrkor", "wmerror", "wmi", "wmidx", "wmiprop", "wmiscmgr", "wmnetmgr", "wmp", 
                    "wmpasf", "wmpcd", "wmpcore", "wmpdxm", "wmpeffects", "wmpencen", "wmphoto", "wmploc", 
                    "wmpmde", "wmpps", "wmpshell", "wmpsrcwp", "wmpui", "wmsdmod", "wmsdmoe", "wmsdmoe2", 
                    "wmspdmod", "wmspdmoe", "wmstream", "wmvadvd", "wmvadve", "wmvcore", "wmvdecod", 
                    "wmvdmod", "wmvdmoe2", "wmvencod", "wmvsdecd", "wmvsencd", "wmvxencd", "wow32", 
                    "wowfax", "wowfaxui", "wpcap", "wpdconns", "wpdmtp", "wpdmtpus", "wpdshext", 
                    "wpdshextres", "wpdshserviceobj", "wpdsp", "wpd_ci", "ws2help", "ws2_32", "wscsvc", 
                    "wsecedit", "wshatm", "wshbth", "wshcon", "wshext", "wship6", "wshisn", "wshko", 
                    "wshnetbs", "wshrm", "wshtcpip", "wsnmp32", "wsock32", "wstdecod", "wtsapi32", 
                    "wuapi", "wuaueng", "wuaueng1", "wuauserv", "wucltui", "wudfcoinstaller", 
                    "wudfplatform", "wudfsvc", "wudfx", "wups", "wuweb", "wzcdlg", "wzcsapi", "wzcsvc", 
                    "x3daudio1_0", "x3daudio1_1", "x3daudio1_2", "x3daudio1_3", "x3daudio1_4", 
                    "xactengine2_0", "xactengine2_1", "xactengine2_10", "xactengine2_2", 
                    "xactengine2_3", "xactengine2_4", "xactengine2_5", "xactengine2_6", 
                    "xactengine2_7", "xactengine2_8", "xactengine2_9", "xactengine3_0", 
                    "xactengine3_1", "xactsrv", "xapofx1_0", "xaudio2_0", "xaudio2_1", "xenroll", 
                    "xinput1_1", "xinput1_2", "xinput1_3", "xinput9_1_0", "xmllite", "xmlprov", 
                    "xmlprovi", "xolehlp", "xpob2res", "xpsp1res", "xpsp2res", "xpsp3res", "zipfldr"
                    ]

lstWindirDllName = ["spsubclass", "tl32v20", "twain", "twain_32", "vbdevkit", "vmmreg32"]

lstSysdirExeName = [
                    "accwiz", "actmovie", "ahui", "alg", "append", "arp", "asr_fmt", "asr_ldm", 
                    "asr_pfu", "at", "atmadm", "attrib", "auditusr", "autochk", "autoconv", "autofmt", 
                    "autolfn", "blastcln", "bootcfg", "bootok", "bootvrfy", "cacls", "calc", "charmap", 
                    "chkdsk", "chkntfs", "cidaemon", "cipher", "cisvc", "ckcnv", "cleanmgr", "cliconfg", 
                    "clipbrd", "clipsrv", "cmd", "cmdl32", "cmmon32", "cmstp", "comp", "compact", 
                    "conime", "control", "convert", "cscript", "csrss", "ctfmon", "dcomcnfg", 
                    "ddeshare", "debug", "defrag", "dfrgfat", "dfrgntfs", "diantz", "diskpart", 
                    "diskperf", "dllhost", "dllhst3g", "dmadmin", "dmremote", "doskey", "dosx", 
                    "dplaysvr", "dpnsvr", "dpvsetup", "driverquery", "drmupgds", "drwatson", "drwtsn32", 
                    "dumprep", "dvdplay", "dvdupgrd", "dwwin", "dxdiag", "edlin", "esentutl", "eudcedit", 
                    "eventcreate", "eventtriggers", "eventvwr", "exe2bin", "expand", "extrac32", 
                    "fastopen", "fc", "femgrate", "find", "findstr", "finger", "fixmapi", 
                    "flashplayerapp", "fltmc", "fontview", "forcedos", "freecell", "fsquirt", "fsutil", 
                    "ftp", "gdi", "getmac", "gpresult", "gpupdate", "grpconv", "help", "hostname", 
                    "ie4uinit", "ieudinit", "iexpress", "imapi", "ipconfig", "ipsec6", "ipv6", 
                    "ipxroute", "java", "javaw", "javaws", "krnl386", "label", "lights", "locator", 
                    "lodctr", "logagent", "logman", "logoff", "logonui", "lpq", "lpr", "lsass", 
                    "magnify", "makecab", "mem", "mmc", "mmcperf", "mnmsrvc", "mobsync", "mountvol", 
                    "mplay32", "mpnotify", "mqbkup", "mqsvc", "mqtgsvc", "mrinfo", "mscdexnt", 
                    "msdtc", "msfeedssync", "msg", "mshearts", "mshta", "msc", "mspaint", "msswchx", 
                    "mstinit", "mstsc", "napstat", "narrator", "nbtstat", "nddeapir", "net", "net1", 
                    "netdde", "netsetup", "netsh", "netstat", "nlsfunc", "notepad", "nslookup", 
                    "ntbackup", "ntkrnlpa", "ntoskrnl", "ntsd", "ntvdm", "nw16", "nwscript", "odbcad32", 
                    "odbcconf", "openfiles", "osk", "osuninst", "packager", "pathping", "pentnt", 
                    "perfmon", "ping", "ping6", "powercfg", "print", "progman", "proquota", "proxycfg", 
                    "qappsrv", "qbasic", "qbasic2", "qprocess", "qwinsta", "rasautou", "rasdial", 
                    "rasphone", "rcimlby", "rcp", "rdpclip", "rdsaddin", "rdshost", "recover", 
                    "redir", "reg", "regedt32", "regini", "regsvr32", "regwiz", "relog", "replace", 
                    "reset", "c", "route", "routemon", "rsh", "rsm", "rsmsink", "rsmui", "rsnotify", 
                    "rsopprov", "rsvp", "rtcshare", "runas", "rundll32", "runonce", "rwinsta", 
                    "savedump", "sc", "scardsvr", "schtasks", "sdbinst", "secedit", "services", 
                    "sessmgr", "sethc", "setup", "setupn", "setupold", "setver", "sfc", "shadow", 
                    "share", "shmgrate", "shrpubw", "shutdown", "sigverif", "skeys", "smbinst", 
                    "smlogsvc", "smss", "sndrec32", "sndvol32", "sol", "sort", "spider", "spiisupd", 
                    "spnpinst", "spoolsv", "sprestrt", "spupdsvc", "stimon", "subst", "svchost", 
                    "syncapp", "sysedit", "syskey", "sysocmgr", "systeminfo", "systray", "taskkill", 
                    "tasklist", "taskman", "taskmgr", "tcmsetup", "tcpsvcs", "telnet", "tftp", 
                    "tlntadmn", "tlntsess", "tlntsvr", "tracerpt", "tracert", "tracert6", "tscon", 
                    "tsdiscon", "tskill", "tsshutdn", "typeperf", "tzchange", "unlodctr", "upnpcont", 
                    "ups", "user", "userinit", "utilman", "uwdf", "verclsid", "verifier", "vssadmin", 
                    "vssvc", "vwipxspx", "w32tm", "wdfmgr", "wextract", "wiaacmgr", "winchat", 
                    "winfxdocobj", "winhlp32", "winlogon", "winmine", "winmsd", "winspool", "winver", 
                    "wowdeb", "woc", "wpdshextautoplay", "wpnpinst", "write", "wscntfy", "wscript", 
                    "wuauclt", "wuauclt1", "wudfhost", "wupdmgr", "xcopy"
                    ]

lstWindirExeName = ["explorer", "hh", "isuninst", "notepad", "regedit", "taskman", "twunk_16", "twunk_32", "winhelp", "winhlp32"]

def findFakePath(strDirname):
    """
        @param strDirname: Only Path except.
                           Use like findFakePath(os.path.dirname(your varibale)) 
    """
    
    bRet = False
    
    
    return bRet

def findFakeFilename(strFilename):
    """
        @param strFilename: Only Filename except.
                           Use like findFakeFilename(os.path.basename(your varibale))
                           
        @return: Original Filename.
                 If you want strFilename is Original. Compare return value and your variable. 
    """
    
    strOriname = ""
    
    
    return strOriname

def findFakeExeName(strFilename):
    """
        @param strFilename: Only Filename except.
                           Use like findFakeFilename(os.path.basename(your varibale))
                           
        @return: Original Filename.
                 Currently Original File name include support 
    """
    bRet = False
    
    tmpFilename = os.path.splitext(strFilename)[0].lower()
    
    for curName in lstWindirExeName:
        if tmpFilename.find(curName) != -1:
            bRet = True    
        if tmpFilename == curName:
            bRet = False
            break
        else:
            break
        
    if bRet == False:
        for curName in lstSysdirExeName:
            if tmpFilename.find(curName) != -1:
                bRet = True    
            if tmpFilename == curName:
                bRet = False
                break
            else:
                break
    return bRet

def findFakeDllName(strFilename):
    """
        @param strFilename: Only Filename except.
                           Use like findFakeFilename(os.path.basename(your varibale))
                           
        @return: Original Filename.
                 Currently Original File name include support 
    """
    bRet = False
    
    tmpFilename = os.path.splitext(strFilename)[0].lower()
        
    for curName in lstWindirDllName:
        if tmpFilename.find(curName) != -1:            
            bRet = True
        if tmpFilename == curName:
            bRet = False
            break
        else:
            break
    
    if bRet == False:
        for curName in lstSysdirDllName:
            if tmpFilename.find(curName) != -1:
                bRet = True
            if tmpFilename == curName:
                bRet = False
                break
            else:
                break
    return bRet

def isSysdirExe(strFilename):
    """
        @param strFilename: Only Filename except
        
        @return: Filename is in %SYSDIR%\\*.exe will return True. or return False
    """
    
    bRet = False
    
    tmpFilename = os.path.splitext(strFilename)[0].lower()
    try:
        tmpIndex = lstSysdirExeName.index(tmpFilename)
        bRet = True
    except ValueError:
        bRet = False    
    
    return bRet

def isWindirExe(strFilename):
    """
        @param strFilename: Only Filename except
        
        @return: Filename is in %WINDIR%\\*.exe will return True. or return False
    """
    
    bRet = False
    
    tmpFilename = os.path.splitext(strFilename)[0].lower()
    try:
        tmpIndex = lstWindirExeName.index(tmpFilename)
        bRet = True
    except ValueError:
        bRet = False  
    
    return bRet

def isSysdirDll(strFilename):
    """
        @param strFilename: Only Filename except
        
        @return: Filename is in %SYSDIR%\\*.dll will return True. or return False
    """
    
    bRet = False
    
    tmpFilename = os.path.splitext(strFilename)[0].lower()
    try:
        tmpIndex = lstSysdirDllName.index(tmpFilename)
        bRet = True
    except ValueError:
        bRet = False  
    
    return bRet

def isWindirDll(strFilename):
    """
        @param strFilename: Only Filename except
        
        @return: Filename is in %WINDIR%\\*.dll will return True. or return False
    """
    
    bRet = False
    
    tmpFilename = os.path.splitext(strFilename)[0].lower()
    try:
        tmpIndex = lstWindirDllName.index(tmpFilename)
        bRet = True
    except ValueError:
        bRet = False  
    
    return bRet