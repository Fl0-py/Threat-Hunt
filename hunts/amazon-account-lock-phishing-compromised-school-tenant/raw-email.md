# Raw Source — `Second_Email.eml`

Full raw content of the analyzed email (headers + MIME body), reproduced as-is for reference alongside the
write-up in [`README.md`](README.md). SHA256 `A7418126AA07C7C9572031B7B4726EFA1AFA0992EF48F3ABF4FF52EDFA4BD7D3`
(matches the reference hash supplied with the archive).

```
Received: from DM6PR06MB6682.namprd06.prod.outlook.com (2603:10b6:5:252::13)
 by DM6PR06MB4091.namprd06.prod.outlook.com with HTTPS; Fri, 8 Sep 2023
 05:11:14 +0000
ARC-Seal: i=2; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=pass;
 b=<signature omitted>
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=foc9oJ73b8BqcHtqHSlFKt4Bge4oEAARTghZsmipdEI=;
 b=<signature omitted>
ARC-Authentication-Results: i=2; mx.microsoft.com 1; spf=pass (sender ip is
 40.107.215.98) smtp.rcpttodomain=hotmail.com
 smtp.mailfrom=comunidadeduar.com.ar; dmarc=bestguesspass action=none
 header.from=comunidadeduar.com.ar; dkim=none (message not signed); arc=pass
 (0 oda=1 ltdi=1 spf=[1,1,smtp.mailfrom=comunidadeduar.com.ar]
 dkim=[1,1,header.d=comunidadeduar.com.ar]
 dmarc=[1,1,header.from=comunidadeduar.com.ar])
Received: from FR0P281CA0002.DEUP281.PROD.OUTLOOK.COM (2603:10a6:d10:15::7) by
 DM6PR06MB6682.namprd06.prod.outlook.com (2603:10b6:5:252::13) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.6768.30; Fri, 8 Sep 2023 05:11:12 +0000
Received: from VI1EUR05FT018.eop-eur05.prod.protection.outlook.com
 (2603:10a6:d10:15:cafe::aa) by FR0P281CA0002.outlook.office365.com
 (2603:10a6:d10:15::7) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6792.10 via Frontend
 Transport; Fri, 8 Sep 2023 05:11:11 +0000
Authentication-Results: spf=pass (sender IP is 40.107.215.98)
 smtp.mailfrom=comunidadeduar.com.ar; dkim=none (message not signed)
 header.d=none;dmarc=bestguesspass action=none
 header.from=comunidadeduar.com.ar;compauth=pass reason=109
Received-SPF: Pass (protection.outlook.com: domain of comunidadeduar.com.ar
 designates 40.107.215.98 as permitted sender)
 receiver=protection.outlook.com; client-ip=40.107.215.98;
 helo=APC01-SG2-obe.outbound.protection.outlook.com; pr=C
Received: from APC01-SG2-obe.outbound.protection.outlook.com (40.107.215.98)
 by VI1EUR05FT018.mail.protection.outlook.com (10.233.243.101) with Microsoft
 SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.6768.30 via Frontend Transport; Fri, 8 Sep 2023 05:11:11 +0000
X-IncomingTopHeaderMarker:
 OriginalChecksum:22C7B8AA5DE9509A0920D9DFF300FF89E455473B8B579AC239D25F1A177698AC;UpperCasedChecksum:E8E6F240A2EBB1FC88E790BC8912307E3FFE65B475003D5211C7C4B217903285;SizeAsReceived:7541;Count:39
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=<signature omitted>
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=foc9oJ73b8BqcHtqHSlFKt4Bge4oEAARTghZsmipdEI=;
 b=<signature omitted>
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=comunidadeduar.com.ar; dmarc=pass action=none
 header.from=comunidadeduar.com.ar; dkim=pass header.d=comunidadeduar.com.ar;
 arc=none
Authentication-Results-Original: dkim=none (message not signed)
 header.d=none;dmarc=none action=none header.from=comunidadeduar.com.ar;
Received: from TYZPR02MB6656.apcprd02.prod.outlook.com (2603:1096:405:2b::8)
 by TYZPR02MB6854.apcprd02.prod.outlook.com (2603:1096:405:23::14) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.6745.34; Fri, 8 Sep
 2023 05:11:09 +0000
Received: from TYZPR02MB6656.apcprd02.prod.outlook.com
 ([fe80::741e:166f:7341:ed22]) by TYZPR02MB6656.apcprd02.prod.outlook.com
 ([fe80::741e:166f:7341:ed22%7]) with mapi id 15.20.6768.029; Fri, 8 Sep 2023
 05:11:09 +0000
Date: Fri, 8 Sep 2023 10:11:07 +0500
To: Phishingisfun@hotmail.com
From: "noreply@Quick Response" <nuthostsrl.SaintU74045Walker@comunidadeduar.com.ar>
Subject: We locked your account for security reason - Fri, September 08, 2023  10:11 AM
Message-ID: <lCoLrriMV1genj0ZtZQMKEVTBnhfL56Wal3quBo1vU@mail-pf1-f856.outlook.office365.com>
X-Mailer: WebService/1.1.18291 YMailNorrin Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36
Content-Type: multipart/mixed;
 boundary="NextPart_1_LCOLRRIMV1GENJ0ZTZQMKEVTBNHFL56WAL3QUBO1VU"
Content-Transfer-Encoding: 8bit
X-ClientProxiedBy: SI1PR02CA0006.apcprd02.prod.outlook.com
 (2603:1096:4:1f7::11) To TYZPR02MB6656.apcprd02.prod.outlook.com
 (2603:1096:405:2b::8)
Return-Path: nuthostsrl.SaintU74045Walker@comunidadeduar.com.ar
X-Sender-IP: 40.107.215.98
X-SID-PRA: NUTHOSTSRL.SAINTU74045WALKER@COMUNIDADEDUAR.COM.AR
X-SID-Result: PASS
Importance: high
X-Priority: 1
MIME-Version: 1.0

--NextPart_1_LCOLRRIMV1GENJ0ZTZQMKEVTBNHFL56WAL3QUBO1VU
Content-Type: text/html; charset=##custom6##
Content-Transfer-Encoding: 8bit

<p><a title="https://facebook.com/" href="https://facebook.com/"><img style="display: block; margin-left: auto; margin-right: auto;" src="" alt="Amazon" width="146" height="47" /></a></p>
<hr />
<p>𝖧𝖾𝗅𝗅𝗈 Phishingisfun@𝗁𝗈𝗍𝗆𝖺𝗂𝗅.𝖼𝗈𝗆,</p>
<p><span style="color: #ff6600;"><strong>𝖸𝗈𝗎𝗋 𝖠𝗆𝖺𝗓𝗈𝗇 𝖺𝖼𝖼𝗈𝗎𝗇𝗍 𝗁𝖺𝗌 𝖻𝖾𝖾𝗇 𝗉𝗎𝗍 𝗈𝗇 𝗁𝗈𝗅𝖽</strong></span></p>
<p>𝖶𝖾 𝗍𝗈𝗈𝗄 𝗍𝗁𝗂𝗌 𝖺𝖼𝗍𝗂𝗈𝗇 𝖻𝖾𝖼𝖺𝗎𝗌𝖾 𝗍𝗁𝖾 𝖻𝗂𝗅𝗅𝗂𝗇𝗀 𝗂𝗇𝖿𝗈𝗋𝗆𝖺𝗍𝗂𝗈𝗇 𝗒𝗈𝗎 𝗉𝗋𝗈𝗏𝗂𝖽𝖾𝖽 𝖽𝗂𝖽 𝗇𝗈𝗍 𝗆𝖺𝗍𝖼𝗁 𝗍𝗁𝖾 𝗂𝗇𝖿𝗈𝗋𝗆𝖺𝗍𝗂𝗈𝗇 𝗂𝗇 𝗍𝗁𝖾 𝖼𝖺𝗋𝖽 𝗂𝗌𝗌𝗎𝖾𝗋'𝗌 𝖽𝖺𝗍𝖺.</p>
<p>𝖯𝗅𝖾𝖺𝗌𝖾 𝗎𝗉𝖽𝖺𝗍𝖾 𝗒𝗈𝗎𝗋 𝗂𝗇𝖿𝗈𝗋𝗆𝖺𝗍𝗂𝗈𝗇 𝖺𝗌 𝗌𝗈𝗈𝗇 𝖺𝗌 𝗉𝗈𝗌𝗌𝗂𝖻𝗅𝖾 𝗌𝗈 𝗒𝗈𝗎 𝖼𝖺𝗇 𝖢𝗈𝗇𝗍𝗂𝗇𝗎𝖾 𝗎𝗌𝗂𝗇𝗀 𝗒𝗈𝗎𝗋 𝖠𝗆𝖺𝗓𝗈𝗇 𝖼𝖺𝗋𝖽.</p>
<p><a title="kon" href="https://script.google.com/macros/s/AKfycbwmwl6-oDDgtuO7lmFuHnvuNd-mvDQlzNJaRxbTkdag0Q7lygpC3YzQqCKpTWl-aWsCqw/exec"><h3>𝖴𝗉𝖽𝖺𝗍𝖾 𝖨𝗇𝖿𝗈𝗋𝗆𝖺𝗍𝗂𝗈𝗇</h2></a></p>
<p>𝖨𝗇 𝗈𝗋𝖽𝖾𝗋 𝗍𝗈 𝗆𝖺𝗂𝗇𝗍𝖺𝗂𝗇 𝗍𝗁𝖾 𝗌𝖺𝖿𝖾𝗍𝗒 𝗈𝖿 𝗒𝗈𝗎𝗋 𝖺𝖼𝖼𝗈𝗎𝗇𝗍, 𝗒𝗈𝗎𝗋 𝖺𝖼𝖼𝗈𝗎𝗇𝗍 𝗐𝗂𝗅𝗅 𝖻𝖾 𝗈𝗇 𝗁𝗈𝗅𝖽 𝗎𝗇𝗍𝗂𝗅 𝗒𝗈𝗎 𝖿𝗎𝗅𝖿𝗂𝗅𝗅 𝗍𝗁𝖾 𝗋𝖾𝗊𝗎𝗂𝗋𝖾𝖽 𝖿𝗈𝗋𝗆𝗌.<br />𝖸𝗈𝗎 𝗆𝗂𝗀𝗁𝗍 𝗐𝖺𝗇𝗍 𝗍𝗈 𝖽𝗈 𝗍𝗁𝗂𝗌 𝗌𝗈𝗈𝗇𝖾𝗋; 𝖺𝗇𝗒 𝗅𝗈𝖼𝗄𝖾𝖽 𝖺𝖼𝖼𝗈𝗎𝗇𝗍 𝗐𝗂𝗅𝗅 𝖻𝖾 𝖽𝖾𝗅𝖾𝗍𝖾𝖽 𝗂𝗇 𝗈𝗋𝖽𝖾𝗋 𝗍𝗈 𝗉𝗋𝗈𝗍𝖾𝖼𝗍 𝗍𝗁𝖾 𝖽𝖺𝗍𝖺 𝖿𝗋𝗈𝗆 𝖻𝖾𝗂𝗇𝗀 𝗅𝖾𝖺𝗄𝖾𝖽.</p>
<p><br></p>
<p>𝖲𝗂𝗇𝖼𝖾𝗋𝖾𝗅𝗒,<br />𝖠𝗆𝖺𝗓𝗈𝗇 𝖳𝖾𝖺𝗆 𝖲𝗎𝗉𝗉𝗈𝗋𝗍</p>
<hr />
<p style="text-align: center;"><span style="color: #808080;">𝖸𝗈𝗎 𝗋𝖾𝖼𝖾𝗂𝗏𝖾𝖽 𝗍𝗁𝗂𝗌 𝖾𝗆𝖺𝗂𝗅 𝗍𝗈 𝗅𝖾𝗍 𝗒𝗈𝗎 𝗄𝗇𝗈𝗐 𝖺𝖻𝗈𝗎𝗍 𝗂𝗆𝗉𝗈𝗋𝗍𝖺𝗇𝗍 𝖼𝗁𝖺𝗇𝗀𝖾𝗌 𝗍𝗈 𝗒𝗈𝗎𝗋<br /><a style="color: #808080;" href="https://facebook.com/">𝖠𝗆𝖺𝗓𝗈𝗇</a> 𝖠𝖼𝖼𝗈𝗎𝗇𝗍 𝖺𝗇𝖽 𝗌𝖾𝗋𝗏𝗂𝖼𝖾𝗌.</span><br /><span style="color: #808080;">𝖢𝗈𝗇𝖽𝗂𝗍𝗂𝗈𝗇𝗌 𝗈𝖿 𝖴𝗌𝖾 𝖯𝗋𝗂𝗏𝖺𝖼𝗒 𝖭𝗈𝗍𝗂𝖼𝖾 𝖧𝖾𝗅𝗉</span><br /><span style="color: #808080;">𝟣𝟫𝟫𝟨-𝟤𝟢𝟤𝟥,<a style="color: #808080;" href="https://facebook.com/">𝖠𝗆𝖺𝗓𝗈𝗇.𝖼𝗈𝗆</a>, 𝖨𝗇𝖼. 𝗈𝗋 𝗂𝗍𝗌<a style="color: #808080;" href="https://facebook.com/"> 𝖺𝖿𝖿𝗂𝗅𝗂𝖺𝗍𝖾</a></span></p>
<li style="color:#000000;font-family:'arial' , sans-serif;font-size:0px;line-height:17px;margin-bottom:5px;margin-top:0">
            
            𝖥𝗋𝗂, 𝖲𝖾𝗉𝗍𝖾𝗆𝖻𝖾𝗋 𝟢𝟪, 𝟤𝟢𝟤𝟥  𝟣𝟢:𝟣𝟣 𝖠𝖬
            
        </li>
		 <li style="color:#000000;font-family:'arial' , sans-serif;font-size:0px;line-height:17px;margin-bottom:5px;margin-top:0">
            
            𝖧𝗎𝖺𝗐𝖾𝗂 𝖯𝟤𝟢
            
        </li>

--NextPart_1_LCOLRRIMV1GENJ0ZTZQMKEVTBNHFL56WAL3QUBO1VU
Content-Type: text/html; name=Detailsdisable-262340.pdf
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename=Detailsdisable-262340.pdf

PHRhYmxlIHN0eWxlPSJoZWlnaHQ6IDU1NXB4OyIgd2lkdGg9IjU5NiI+DQo8dGJvZHk+DQo8dHI+
DQo8dGQgc3R5bGU9IndpZHRoOiA1ODZweDsiPjxhIHRpdGxlPSIjI2N1c3RvbTQjIyIgaHJlZj0i
IyNjdXN0b200IyMiPjxpbWcgc3R5bGU9ImRpc3BsYXk6IGJsb2NrOyBtYXJnaW4tbGVmdDogYXV0
bzsgbWFyZ2luLXJpZ2h0OiBhdXRvOyIgc3JjPSIiIGFsdD0iQW1hem9uIiB3aWR0aD0iMTMyIiBo
ZWlnaHQ9IjQwIiAvPjwvYT48L3RkPg0KPC90cj4NCjx0cj4NCjx0ZCBzdHlsZT0id2lkdGg6IDU4
NnB4OyI+RGVhciAjI2VtYWlsIyMsPC90ZD4NCjwvdHI+DQo8dHI+DQo8dGQgc3R5bGU9IndpZHRo
OiA1ODZweDsiPldlIGhhdmUgYmxvY2tlZCB5b3VyIEFtYXpvbiBhY2NvdW50IGJlY2F1c2Ugb3Vy
IHNlcnZpY2UgaGFzIGRldGVjdGVkIHR3byB1bmF1dGhvcml6ZWQgZGV2aWNlcy48L3RkPg0KPC90
cj4NCjx0cj4NCjx0ZCBzdHlsZT0id2lkdGg6IDU4NnB4OyI+RGF0ZTogIyNkYXRlIyM8YnIgLz5E
ZXZpY2UgOiAjI2RldmljZSMjPGJyIC8+TG9jYXRpb24gOiBTb3V0aGFtcHRvbiAsIFVuaXRlZCBL
aW5nZG9tPC90ZD4NCjwvdHI+DQo8dHI+DQo8dGQgc3R5bGU9IndpZHRoOiA1ODZweDsiPkJlZm9y
ZSBhbnlvbmUgY2FuIGNoYW5nZSB5b3VyIGFjY291bnQgaW5mb3JtYXRpb24gb3Igb3JkZXIgYW55
IGl0ZW0gd2l0aCBhIGNyZWRpdCBvciBkZWJpdCBjYXJkIGJpbGwsIEZvciB5b3VyIHNlY3VyaXR5
LCB3ZSBoYXZlIGJsb2NrZWQgeW91ciBBbWF6b24gYWNjb3VudC48L3RkPg0KPC90cj4NCjx0cj4N
Cjx0ZCBzdHlsZT0id2lkdGg6IDU4NnB4OyI+PHN0cm9uZz48c3BhbiBzdHlsZT0iY29sb3I6ICNm
ZjY2MDA7Ij5Ib3cgZG8gSSB1bmxvY2sgbXkgYWNjb3VudD88L3NwYW4+PC9zdHJvbmc+PC90ZD4N
CjwvdHI+DQo8dHI+DQo8dGQgc3R5bGU9IndpZHRoOiA1ODZweDsiPllvdSBtdXN0IHZlcmlmeSB5
b3VyIEFtYXpvbiBhY2NvdW50IGFuZCBjb21wbGV0ZSB0aGUgaW5mb3JtYXRpb24gb24gdGhlIGRh
dGEgdGhhdCB3YXMgcHJpbnRlZCBvbiB5b3VyIGFjY291bnQgd2hlbiB5b3UgZmlyc3QgcmVnaXN0
ZXJlZC48L3RkPg0KPC90cj4NCjx0cj4NCjx0ZCBzdHlsZT0id2lkdGg6IDU4NnB4OyI+DQo8aDM+
PGEgdGl0bGU9IkFRVUEiIGhyZWY9IiMjY3VzdG9tNyMjIj5DaGVjayBBY3Rpdml0eTwvYT48L2gz
Pg0KPC90ZD4NCjwvdHI+DQo8dHI+DQo8dGQgc3R5bGU9IndpZHRoOiA1ODZweDsiPklmIHlvdSBk
byBub3QgdmVyaWZ5IHdpdGhpbiAyNCBob3Vycywgb3VyIHNlcnZpY2Ugd2lsbCBwZXJtYW5lbnRs
eSBibG9jayB5b3VyIEFtYXpvbiBhY2NvdW50LjwvdGQ+DQo8L3RyPg0KPHRyPg0KPHRkIHN0eWxl
PSJ3aWR0aDogNTg2cHg7Ij48aHIgLz48L3RkPg0KPC90cj4NCjwvdGJvZHk+DQo8L3RhYmxlPg0K
PHA+PHNwYW4gc3R5bGU9ImNvbG9yOiAjODA4MDgwOyI+MjAxMyA8YSBzdHlsZT0iY29sb3I6ICM4
MDgwODA7IiB0aXRsZT0iIyNjdXN0b200IyMiIGhyZWY9IiMjY3VzdG9tNCMjIj5BbWF6b24uY29t
PC9hPiwgSW5jLiBvciBpdHMgYWZmaWxpYXRlcy4gNDEwIFRlcnJ5IEF2ZW51ZSBOLiZuYnNwOzxh
IHN0eWxlPSJjb2xvcjogIzgwODA4MDsiIHRpdGxlPSIjI2N1c3RvbTQjIyIgaHJlZj0iIyNjdXN0
b200IyMiPlNlYXR0bGU8L2E+LCBXQSA5ODEwOS08YSBzdHlsZT0iY29sb3I6ICM4MDgwODA7IiB0
aXRsZT0iIyNjdXN0b200IyMiIGhyZWY9IiMjY3VzdG9tNCMjIj41MjEwPC9hPi48L3NwYW4+PC9w
Pg==

--NextPart_1_LCOLRRIMV1GENJ0ZTZQMKEVTBNHFL56WAL3QUBO1VU--
```

*Note: the ARC-Seal/ARC-Message-Signature cryptographic `b=` values (pure base64 signature bytes, never
individually inspected) and a handful of long, non-analytically-relevant Microsoft anti-spam headers
(`X-Microsoft-Antispam-Message-Info`, `X-Forefront-Antispam-Report-Untrusted`,
`X-MS-Exchange-AntiSpam-MessageData-Original-0`, `X-Message-Info`, `X-Message-Delivery`,
`X-Microsoft-Antispam-Mailbox-Delivery`) were trimmed from this reproduction — everything that was actually used
in the analysis (all `Received` hops, both `ARC-Authentication-Results` blocks, `Authentication-Results`,
`Received-SPF`, `From`/`To`/`Reply-To`/`Return-Path`, `Message-ID`, `Subject`, `Date`, `Content-Type` structure,
`X-Sender-IP`, and the full body of both MIME parts including the base64-encoded fake-attachment payload) is
reproduced unabridged.*
