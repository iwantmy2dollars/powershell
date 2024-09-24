<#PSScriptInfo

.VERSION 0.0.2

.GUID xxxyyyzzzz

.AUTHOR -iwantmy2dollars-

.COMPANYNAME

.COPYRIGHT

.TAGS

.LICENSEURI

.PROJECTURI

.ICONURI

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES


.PRIVATEDATA

#>

<# 

.DESCRIPTION 
 Set the local security policy to include a specified serivde account as a batch user.  This action is required to allow scheduled tasks to run scripts while no users are logged on. 

#> 
[CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $false)] [switch] $LIVE,
        [Parameter(Mandatory = $false)] [string] $IDENTITY
    )

function SetSeBatchLogon {

    #Export the USER_RIGHTS area of the local security policy
    #https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh875542(v=ws.11)
    $u_secpolitem = "SeBatchLogonRight"
    secedit.exe /export /cfg $ENV:TMP\secpol.inf /areas USER_RIGHTS) /quiet
    
    #Declare the SID of the AD user or MSA that we want to add to the security policy
    try {
        #THOUGHT:  We probably want to change this to LDAP query in case Get-ADServiceAccount is unavailable..
        $u_newSID = $(Get-ADServiceAccount -Identity $IDENTITY -ErrorAction Stop).SID
    }
    catch {
        throw $_
    }

    #Read the current security policy export to an array
    $u_URresults = $(Get-Content $ENV:TMP\secpol.inf)
    
    #Find the index of the security policy item we care about
    Foreach($item in $u_URresults){
        if($item -like "$u_secpolitem*"){
            $u_arrayindex = [array]::indexof($u_URresults,$item)
            break
        }
    }
    
    #Save the list of users from the current (active) security policy to a string.  We don't want to overwrite what's currently there.
    $u_currentbatchlogonusers = $u_URresults[$u_arrayindex]
    
    #Does the user SID we're trying to add alreay exist?  If so, don't do anything more - we are done.
    if(
        ($u_currentbatchlogonusers -split "= " -split "," -replace "\*","") -contains $u_newSID
    ){
        throw [exception]::new("New SID is already a batch operator")
    }
    else{
        #Since it doesn't already exist, lets create a new string with the added SID
        Write-Output "Adding in $IDENTITY as BatchLogon user.."
        $u_updatedbatchlogonusers = "$u_currentbatchlogonusers,*$u_newSID"
    }

#Using a here-string, create the ordered content of values we need to import into the active security policy.
#We'll output this to a temporary .inf file.
$u_contents = @'
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Privilege Rights]
'@+"`n$u_updatedbatchlogonusers"


    $u_contents | Set-Content $ENV:TMP\batchlogon.inf

    #Lets get to it!
    #Did we explicitly declare that we want to live-update our local security policy?  Otherwise, this is just test
    if($LIVE){
        try {
            secedit.exe /import /db $ENV:TMP\batchlogon.sdb /cfg $ENV:TMP\batchlogon.inf /quiet
            secedit.exe /configure /db $ENV:TMP\batchlogon.sdb /quiet
        }
        catch {
            throw $_
        }
        finally {
            #Cleanup
            WRite-Host "Cleanup"
            Remove-Item @(
                "$ENV:TMP\batchlogon.sdb"
                "$ENV:TMP\batchlogon.inf"
                "$ENV:TMP\secpol.inf"
            )
        }
        
        Write-Host -ForegroundColor Green "Success.  Our new Security Policy looks like.."
        
        #Confirm the new settings
        secedit.exe /export /cfg $ENV:TMP\secpol2.inf /areas USER_RIGHTS /quiet
        Get-Content $ENV:TMP\secpol2.inf
        #And cleanup after ourselves..
        Remove-Item "$ENV:TMP\secpol2.inf"
    }
}

Clear-Host

try {
    #If this script was not invoked with the Identity parameter passed, ask the user for the identity
    if(!$IDENTITY){$Identity = Read-Host "Name of Group Managed Service Account"}
    
    #function call
    SetSeBatchLogon -ErrorAction Stop
}
catch {
    $_.Exception.Message
    return
}
finally {
    #Cleanup
    Get-Variable @('IDENTITY','LIVE') -ErrorAction SilentlyContinue | Remove-Variable -ErrorAction SilentlyContinue
}

Write-Host -ForegroundColor Green "Success!"

#END
