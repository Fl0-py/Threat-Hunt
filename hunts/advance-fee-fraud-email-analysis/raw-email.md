# Raw Source — `First_Email.eml`

Full raw content of the analyzed email (headers + HTML body), reproduced as-is for reference alongside the
write-up in [`README.md`](README.md). SHA256 `D7942B86529946BFF77914A0569C1C8EE31F6DC3AA647289747CDAE21638DDB0`
(matches the MyDFIR "First Email Analysis" lab statement).

```
Received: from SJ0PR06MB6767.namprd06.prod.outlook.com (2603:10b6:a03:286::13)
 by DM6PR06MB4091.namprd06.prod.outlook.com with HTTPS; Wed, 6 Dec 2023
 17:07:20 +0000
Received: from TY2PR0101CA0005.apcprd01.prod.exchangelabs.com
 (2603:1096:404:92::17) by SJ0PR06MB6767.namprd06.prod.outlook.com
 (2603:10b6:a03:286::13) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7046.34; Wed, 6 Dec
 2023 17:07:19 +0000
Received: from TYZPR01MB4137.apcprd01.prod.exchangelabs.com
 (2603:1096:404:92:cafe::5f) by TY2PR0101CA0005.outlook.office365.com
 (2603:1096:404:92::17) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7046.34 via Frontend
 Transport; Wed, 6 Dec 2023 17:07:18 +0000
Received: from DS7PR03CA0035.namprd03.prod.outlook.com (2603:10b6:5:3b5::10)
 by TYZPR01MB4137.apcprd01.prod.exchangelabs.com (2603:1096:400:1cb::10) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7046.34; Wed, 6 Dec
 2023 17:07:16 +0000
Received: from DM6NAM04FT068.eop-NAM04.prod.protection.outlook.com
 (2603:10b6:5:3b5:cafe::d5) by DS7PR03CA0035.outlook.office365.com
 (2603:10b6:5:3b5::10) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.7046.34 via Frontend
 Transport; Wed, 6 Dec 2023 17:07:15 +0000
Authentication-Results: spf=softfail (sender IP is 183.56.179.169)
 smtp.mailfrom=sasktel.net; dkim=none (message not signed)
 header.d=none;dmarc=none action=none header.from=sasktel.net;compauth=fail
 reason=001
Received-SPF: SoftFail (protection.outlook.com: domain of transitioning
 sasktel.net discourages use of 183.56.179.169 as permitted sender)
Received: from mail.yobow.cn (183.56.179.169) by
 DM6NAM04FT068.mail.protection.outlook.com (10.13.158.249) with Microsoft SMTP
 Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.20.7068.26 via Frontend Transport; Wed, 6 Dec 2023 17:07:14 +0000
X-IncomingTopHeaderMarker:
 OriginalChecksum:67032896AC09AA02CFCBC006CBDCE192AEA8187508AAB8571938B34AC5550621;UpperCasedChecksum:DEC09567BEA0ED87154761EE71FCC7815AD3FB3099EA3C019EDAA4ECAF7E069C;SizeAsReceived:2305;Count:17
Received: from User (localhost [127.0.0.1])
	by mail.yobow.cn (Postfix) with SMTP id 6414E20EB5FD;
	Wed,  6 Dec 2023 20:59:57 +0800 (CST)
Reply-To: <agentcynthiajamescontact01@gmail.com>
From: "Mrs  Janet Yellen"<p.chambers@sasktel.net>
Subject: Attention Dear Beneficiary  
Date: Wed, 6 Dec 2023 05:00:12 -0800
Content-Type: text/html;
	charset="Windows-1251"
Content-Transfer-Encoding: 7bit
X-Mailer: Microsoft Outlook Express 6.00.2600.0000
X-MimeOLE: Produced By Microsoft MimeOLE V6.00.2600.0000
Message-Id: <20231206125957.6414E20EB5FD@mail.yobow.cn>
X-Synology-Virus-Status: no
X-Synology-Spam-Status: score=38.393, required 5, HAS_REPLYTO 0, T_SCC_BODY_TEXT_LINE 0, FORGED_OUTLOOK_HTML 0.001, __FROM_MISSP_FREEMAIL 0, MONEY_FROM_MISSP 0.001, __ADVANCE_FEE_3_NEW_MONEY 0, XPRIO 0.5, __NOT_A_PERSON 0, MSBL_EBL 0, HAS_X_PRIO_THREE 0, MISSING_TO 0, LOTS_OF_MONEY 0.001, __FORGED_OE 0, FROM_EQ_ENVFROM 0, __TO_NO_BRKTS_FROM_MSSP 0, MONEY_FREEMAIL_REPTO 2.824, __XPRIO_MINFP 0, RCVD_COUNT_ZERO 0, NO_RECEIVED -0.001, ADVANCE_FEE_4_NEW_MONEY 0.131, SUBJECT_ENDS_SPACES 0.5, AXB_XMAILER_MIMEOLE_OL_024C2 0.001, OLD_X_MAILER 0.667, FROM_HAS_DN 0, FREEMAIL_ENVRCPT 0, FREEMAIL_REPLYTO 2, HK_NAME_MR_MRS 0.999, HTML_MISSING_CTYPE 0, __TO_NO_BRKTS_MSFT 0, FROM_NAME_HAS_TITLE 1, __TO_NO_BRKTS_FROM_RUNON 0, FROM_MISSP_MSFT 0.526, MSOE_MID_WRONG_CASE 3.373, __ADVANCE_FEE_2_NEW_MONEY 0, FROM_MISSPACED 1.711, FROM_MISSP_XPRIO 2.499, __ADVANCE_FEE_4_NEW_MONEY 0, FORGED_MUA_OUTLOOK 2.785, RCVD_HELO_USER 1, HTML_MESSAGE 0.001, REPLYTO_WITHOUT_TO_CC 1.946, FSL_CTYPE_WIN1251 0.001, MIME_TR
 ACE 0, __NOT_SPOOFED 0, __XFER_MONEY 0, __ADVANCE_FEE_2_NEW 0, __ADVANCE_FEE_3_NEW 0, ARC_NA 0, __TO_NO_BRKTS_FREEMAIL 0, FROM_MISSP_FREEMAIL 4.998, __FROM_MISSP_REPLYTO 0, __XFER_LOTSA_MONEY 0, REPLYTO_DOM_NEQ_FROM_DOM 0, __NO_INR_YES_REF 0, MISSING_HEADERS 1.207, FORGED_OUTLOOK_TAGS 0.565, FREEMAIL_REPLYTO_END_DIGIT 0.25, __ADVANCE_FEE_4_NEW 0, MIME_HTML_ONLY 0, DEAR_BENEFICIARY 0.401, TO_NO_BRKTS_FROM_MSSP 2.499, R_NO_SPACE_IN_FROM 0, FROM_NAME_EXCESS_SPACE 1, __MONEY_FRAUD_3 0, XFER_LOTSA_MONEY 0.001, __MONEY_FREEMAIL_REPTO 0, FREEMAIL_FORGED_REPLYTO 5.006
X-Synology-Spam-Flag: yes
Authentication-Results-Original: mail.yobow.cn;	none
X-IncomingHeaderCount: 17
To: Undisclosed recipients:;
Return-Path: p.chambers@sasktel.net
X-MS-Exchange-Organization-ExpirationStartTime: 06 Dec 2023 17:07:15.4936
 (UTC)
X-MS-Exchange-Organization-ExpirationStartTimeReason: OriginalSubmit
X-MS-Exchange-Organization-ExpirationInterval: 1:00:00:00.0000000
X-MS-Exchange-Organization-ExpirationIntervalReason: OriginalSubmit
X-MS-Exchange-Organization-Network-Message-Id:
 79f1129b-6288-42e6-382c-08dbf67dcbe1
X-EOPAttributedMessage: 0
X-EOPTenantAttributedMessage: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa:0
X-MS-Exchange-Organization-MessageDirectionality: Incoming
X-MS-PublicTrafficType: Email
X-MS-TrafficTypeDiagnostic:
 DM6NAM04FT068:EE_|TYZPR01MB4137:EE_|SJ0PR06MB6767:EE_|DM6PR06MB4091:EE_
X-MS-Office365-Filtering-Correlation-Id: 79f1129b-6288-42e6-382c-08dbf67dcbe1
X-MS-Exchange-EOPDirect: true
X-Sender-IP: 183.56.179.169
X-SID-PRA: P.CHAMBERS@SASKTEL.NET
X-SID-Result: FAIL
X-MS-Exchange-Organization-PCL: 2
X-MS-Exchange-Organization-SCL: 5
X-Microsoft-Antispam: BCL:0;
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 06 Dec 2023 17:07:14.9155
 (UTC)
X-MS-Exchange-CrossTenant-Network-Message-Id: 79f1129b-6288-42e6-382c-08dbf67dcbe1
X-MS-Exchange-CrossTenant-Id: 84df9e7f-e9f6-40af-b435-aaaaaaaaaaaa
X-MS-Exchange-CrossTenant-AuthSource: DM6NAM04FT068.eop-NAM04.prod.protection.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Anonymous
X-MS-Exchange-CrossTenant-FromEntityHeader: Internet
X-MS-Exchange-CrossTenant-RMS-PersistedConsumerOrg: 00000000-0000-0000-0000-000000000000
X-MS-Exchange-Transport-CrossTenantHeadersStamped: TYZPR01MB4137
X-MS-Exchange-Organization-AuthSource:
 DM6NAM04FT068.eop-NAM04.prod.protection.outlook.com
X-MS-Exchange-Organization-AuthAs: Anonymous
X-MS-Exchange-Transport-EndToEndLatency: 00:00:05.7290959
X-MS-Exchange-Processed-By-BccFoldering: 15.20.7046.032
MIME-Version: 1.0

<html><head>
<meta http-equiv="Content-Type" content="text/html; charset=windows-1251"><title></title>
</head>
<body bgcolor="#FFFFFF" leftmargin="5" topmargin="5" rightmargin="5" bottommargin="5">
<font size="2" color="#000000" face="Arial">
<div>
United States Funds Authority,</div>
<div>
USA Funds P.O. Box 6028. Indianapolis</div>
<div>
Finance Director: Janet Yellen</div>
<div>
Head Office Brooklyn, New York, United States</div>
<div>
Email    usanewjamesfingerprint@gmail.com</div>
<div>
Attention:Email Owner,</div>
<div>
We are very sorry for our responding late, and we are here to inform</div>
<div>
you that your long awaiting (COVID-19) funds arrive in our office on</div>
<div>
 22 Nov 2023, your email are among the 15</div>
<div>
peoples to receive this funds in your Great Country .</div>
<div>
The funds was package through luggage by the Wells Fargo Bank United</div>
<div>
States, The PIN CODE to open the luggage will be send by Wells Fargo</div>
<div>
Bank, once you confirm that the luggage have arrive your place.</div>
<div>
Total funds in the luggage according to Wells Fargo Bank report is</div>
<div>
$16,000,000.00, ( Sixteen Millions USD ).</div>
<div>
Please there is two available diplomatic agent well train and</div>
<div>
educated, we will list there name and there working ID, then you will</div>
<div>
now choose the one who you will like to deliver this luggage in your</div>
<div>
Country.</div>
<div>
1, Diplomatic Agent Miss. Cynthia R. James</div>
<div>
Email: agentcynthiajamescontact01@gmail.com</div>
<div>
2, Diplomatic Agent: Mr. John Williams</div>
<div>
Email: dr.philipmaxwell303@gmail.com</div>
<div>
And for your information never discuss the content of this delivery to</div>
<div>
any third party , even the two diplomatic agent did not know the</div>
<div>
content of this delivery as Bank instructed.</div>
<div>
Receiving this funds did not mean that you can use it by your self</div>
<div>
only, but use it to help some needy in your country because that is</div>
<div>
why your name and email is chosen among the leader.</div>
<div>
So download there working ID CARD and choose your diplomatic choice of</div>
<div>
delivery, two of them are very nice and well trusted.</div>
<div>
Thank you and God bless Americans.</div>
<div>
United States Funds Authority,</div>
<div>
USA Funds P.O. Box 6028. Indianapolis</div>
<div>
Finance Director: Janet Yellen</div>
<div>
Head Office Brooklyn, New York, United States</div>
<div>
Treasurer of the United States: Lynn Malerba</div>
</font>
</body></html>
```

*Note: a handful of long, non-analytically-relevant Microsoft anti-spam headers (`X-Message-Info`,
`X-Microsoft-Antispam-Message-Info`, base64/quoted-printable blobs) were trimmed from this reproduction —
everything that was actually used in the analysis (all `Received` hops, `Authentication-Results`,
`Received-SPF`, `From`/`Reply-To`/`Return-Path`/`To`, `Message-Id`, `Content-Type`, `X-Sender-IP`, and the full
body) is reproduced unabridged.*
