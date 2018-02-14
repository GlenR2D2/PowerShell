$SvcEnum = @'
	namespace Services
	{
		[System.FlagsAttribute]
		public enum ServiceAccessFlags : uint
		{
			QueryConfig = 1,
			ChangeConfig = 2,
			QueryStatus = 4,
			EnumerateDependents = 8,
			Start = 16,
			Stop = 32,
			PauseContinue = 64,
			Interrogate = 128,
			UserDefinedControl = 256,
			Delete = 65536,
			ReadControl = 131072,
			WriteDac = 262144,
			WriteOwner = 524288,
			Synchronize = 1048576,
			AccessSystemSecurity = 16777216,
			GenericAll = 268435456,
			GenericExecute = 536870912,
			GenericWrite = 1073741824,
			GenericRead = 2147483648
		}
	}
'@

Add-Type $SvcEnum -ErrorAction 'Stop'

Function Add-UserRightsOnService {
	Param(
		[Parameter(Mandatory=$True)]
		[String]$ServiceName,
		[Parameter(Mandatory=$True,ParameterSetName='UserName')]
		[String]$UserName,
		[Parameter(Mandatory=$True,ParameterSetName='SID')]
		[System.Security.Principal.SecurityIdentifier]$SID,
		[Parameter(Mandatory=$True)]
		[Services.ServiceAccessFlags[]]$AccessMask
	)

	Process {
	
		Try {
	
			$Service = Get-WmiObject Win32_Service -Filter "Name='$($ServiceName)'" -EnableAllPrivileges -ErrorAction 'Stop'
			
			If ($Service) {
			
				$ResultGetDescriptor = $Service.GetSecurityDescriptor()
				If (($ResultGetDescriptor.ReturnValue) -ne '0') { 
					Throw 'Unable to retrieve Security Descriptor' 
				}

				$SvcDescriptor = $ResultGetDescriptor.Descriptor

				If ($($PsCmdlet.ParameterSetName) -eq 'UserName') {
					$UserSID = $(((New-Object System.Security.Principal.NTAccount($UserName)).Translate([System.Security.Principal.SecurityIdentifier])).Value)
				}
				Else {
					$UserSID = $($SID.Value)
				}
				
				# Build AccessMask UINT32 Value
				ForEach ($AM in $AccessMask) {
					[UInt32]$AccessMaskValue = $($AccessMaskValue + $AM.value__)
				}
				
				$TmpDACL = New-Object System.Collections.ArrayList -ErrorAction 'Stop'
				
				ForEach ($DACL in $SvcDescriptor.DACL) {
					If ($DACL.Trustee.SIDString -eq $UserSID) {
						$DACL.AccessMask = $AccessMaskValue
						[void]$TmpDACL.Add($DACL)
						[Boolean]$AccessMaskFound = $True
					}
					Else {
						[void]$TmpDACL.Add($DACL)
					}
				}
				
				If (!$AccessMaskFound) {
					$Trustee = ([WMIClass]"Win32_Trustee").CreateInstance()
					$Trustee.SIDString = $UserSID
					$Ace = ([WMIClass]"Win32_ACE").CreateInstance()
					$Ace.AccessMask = $AccessMaskValue
					$Ace.Trustee = $Trustee
					[void]$TmpDACL.Add($Ace)
				}
				
				$SvcDescriptor.DACL = $TmpDACL
				
				$ResultSetDescriptor = $Service.SetSecurityDescriptor($SvcDescriptor)
				If ($ResultSetDescriptor.ReturnValue -ne '0') { 
					Throw "Unable to Write DACL on $ServiceName" 
				}
				
			}
			Else {
			
				Throw "$ServiceName not found"
				
			}
			
		}
		Catch {
		
			Throw "Line Error : $($_.InvocationInfo.ScriptLineNumber)`nErrorMessage : $($_.Exception.Message)`nErrorRecord : $($_.Exception.ErrorRecord)"
		
		}
		
	}
	
}

Function Remove-UserRightsOnService {
	Param(
		[Parameter(Mandatory=$True)]
		[String]$ServiceName,
		[Parameter(Mandatory=$True,ParameterSetName='UserName')]
		[String]$UserName,
		[Parameter(Mandatory=$True,ParameterSetName='SID')]
		[System.Security.Principal.SecurityIdentifier]$SID
	)
	
	Process {
	
		Try {
		
			$Service = Get-WmiObject Win32_Service -Filter "Name='$($ServiceName)'" -EnableAllPrivileges -ErrorAction 'Stop'
			
			If ($Service) {
			
				$ResultGetDescriptor = $Service.GetSecurityDescriptor()
				If (($ResultGetDescriptor.ReturnValue) -ne '0') { Throw 'Unable to retrieve Security Descriptor' }

				$SvcDescriptor = $ResultGetDescriptor.Descriptor

				If ($($PsCmdlet.ParameterSetName) -eq 'UserName') {
					$UserSID = $(((New-Object System.Security.Principal.NTAccount($UserName)).Translate([System.Security.Principal.SecurityIdentifier])).Value)
				}
				Else {
					$UserSID = $($SID.Value)
				}
				
				# Rebuild DACL Object Array
				$TmpDACL = New-Object System.Collections.ArrayList -ErrorAction 'Stop'
				ForEach ($DACL in $SvcDescriptor.DACL) {
					If ($DACL.Trustee.SIDString -ne $UserSID) {
						[void]$TmpDACL.Add($DACL)
					}
				}

				$SvcDescriptor.DACL = $TmpDACL
				
				$ResultSetDescriptor = $Service.SetSecurityDescriptor($SvcDescriptor)
				If ($ResultSetDescriptor.ReturnValue -ne '0') { Throw "Unable to Write DACL on $ServiceName" }
				
			}
			Else {
				Throw "$ServiceName not found"
			}
			
		}
		Catch {
		
			Throw "Line Error : $($_.InvocationInfo.ScriptLineNumber)`nErrorMessage : $($_.Exception.Message)`nErrorRecord : $($_.Exception.ErrorRecord)"
		}
		
	}

}

Function Show-RightsOnService {
	Param(
		[Parameter(Mandatory=$True)]
		[String[]]$ServiceName
	)

	Process {
	
		Try {
		
			$TmpSvcs = New-Object System.Collections.ArrayList -ErrorAction 'Stop'
			
			ForEach ($Service in $ServiceName) {
			
				$Svc = Get-WmiObject Win32_Service -Filter "Name='$($Service)'" -EnableAllPrivileges -ErrorAction 'Stop'
				
				If ($Svc) {
				
					$ResultGetDescriptor = $Svc.GetSecurityDescriptor()
					If (($ResultGetDescriptor.ReturnValue) -ne '0') { Throw 'Unable to retrieve Security Descriptor' }

					$SvcDescriptor = $ResultGetDescriptor.Descriptor
			
					#
					$TmpDACL = New-Object System.Collections.ArrayList -ErrorAction 'Stop'
					ForEach ($DACL in $SvcDescriptor.DACL) {
						$UserRights = New-Object -TypeName 'PSObject' -Property @{
							Service=$Service;
							AccessMask=[ServiceAccessFlags]$($DACL.AccessMask);
							Domain=$DACL.Trustee.Domain;
							Name=$DACL.Trustee.Name;
							SID=$DACL.Trustee.SIDString;
						}
						[void]$TmpDACL.Add($UserRights)
					}
					
				}
				$SvcRights = New-Object -TypeName 'PSObject' -Property @{
					Name=$Service;
					Rights=$TmpDACL;
				}
				[void]$TmpSvcs.Add($SvcRights)
				
			}
			
			Return $TmpSvcs
			
		}
		Catch {
		
			Throw "Line Error : $($_.InvocationInfo.ScriptLineNumber)`nErrorMessage : $($_.Exception.Message)`nErrorRecord : $($_.Exception.ErrorRecord)"
			
		}
		
	}

}
