<#PSScriptInfo

.VERSION 1.0

.GUID 7ef87947-5523-4b88-88d1-a0a036d7336b

.AUTHOR 

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
    2024-10-16 - Script created

.PRIVATEDATA

#>

<# 

.DESCRIPTION 
 Collect User Lockout events from all domain controllers, beginning at midnight the previous day. 

#> 
[CmdletBinding()]
Param
(
    [Parameter()] [switch] $Silent,
    [Parameter()] [switch] $All,
    [Parameter()] [Switch] $File,
    [Parameter()] [string] $Account = '*',
    [Parameter()] [string[]] $DomainControllers = $(Get-ADDomainController -Filter * | Select-Object Name | Sort-Object -Property Name).Name,
    [Parameter()] [int] $Days = 1,
    
    [Parameter(ParameterSetName='Emailing')] [switch] $Email,
    [Parameter(ParameterSetName='Emailing')] [string[]] $Recipients
)

BEGIN{
    
    if(
        ($Days -isnot [int]) -or
        ($Days -gt 20) -or 
        ($Days -lt 0)
    ){
        if(!$Silent){ Write-Host "We are defaulting to 1 day of data.  Your input was invalid"}
        $Days = 1
    }

    $StartTime = (Get-Date -Hour 0 -Minute 0 -Second 0 -Millisecond 0).AddDays($Days*-1)
    $referenceDC = "[REDACTED]"
    $now = Get-Date
    $outDir = (Get-Item -Path ".").FullName
    $outFile = "AcctLockout-$(Get-Date $now -format "yyyyMMdd").html"
    $outPathFull = "$outDir\$outFile"
    $tempFile = New-TemporaryFile
    if($PSCmdlet.ParameterSetName -eq "Emailing" -and !$Recipients){$Recipients = Read-Host "Please provide recipient email addresses`n(Separate addresses with a comma)"}

    $head = @"
<style>
BODY{background-color:navajowhite;}
TABLE{border-width: 1px;border-style: solid;border-color: black;border-collapse: collapse;}
TH{border-width: 1px;padding: 2px;border-style: solid;border-color: black;background-color:lightcoral}
TD{border-width: 1px;padding: 5px;border-style: solid;border-color: black;background-color:PaleGoldenrod}
</style>
"@

    Switch ($Account) {
        '*'         {$sb1 = [scriptblock]::Create('$_.Properties[0].Value -Like "'+$Account+'"')}
        Default     {$sb1 = [scriptblock]::Create('$_.Properties[0].Value -Like "'+$Account+'*"')}
    }

    $getProps = @{
        FilterHashTable = @{
            LogName     = "Security"
            Id          = 4740
            StartTime   = $StartTime
        }

        ComputerName    = [string]$null
        ErrorAction     = "SilentlyContinue"
    }
    
    $selectProps = @{
        Property = @(
            'RecordID'
            'TimeCreated'
            @{n="UserName";             e={$_.Properties[0].Value}}
            @{n="ClientName";           e={$_.Properties[1].Value}}
            @{n="DomainController";     e={$dc}}
            @{n="Current_AD_LockedOut"; e={$(Get-ADUser -Server $referenceDC -Identity $_.Properties[0].Value -Properties LockedOut).LockedOut}}
            @{n="Current_AD_Enabled";   e={$(Get-ADUser -Server $referenceDC -Identity $_.Properties[0].Value -Properties Enabled).Enabled}}
        )
    }

    #If we did not explicistly declare that we want all events, lets get just the newest.
    #Get-WimEvent returns newest to olders, so we want to select the first record.
    if(!$All){$selectProps.First = 1}

    $sortProps = @(
        @{Expression="UserName";    Descending=$false}
        @{Expression="TimeCreated"; Descending=$true}
    )

    $moveProps = @{
        Path = $tempFile.ResolvedTarget
        Destination = -join ($tempFile.Directory,"\",($outFile -Replace ".html",".csv"))
    }

    $htmlProps = @{
        Head = $head
        
        Body = @(
            "<H2>Locked Out User Accounts</H2>"
            "<h3>Events from all Domain Controllers, beginning $StartTime</h3>"
            "<p>Script Execution Timestamp: $now</p>"
        )
    }

    $sendMailProps = @{
        SmtpServer      = '[REDACTED]'
        From            = '[REDACTED]'
        To              = $Recipients
        Subject         = 'Lockout Events Report'
        BodyAsHTML      = $true
        WarningAction   = 'SilentlyContinue'
    }
}

PROCESS {
    $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()

    $results = foreach($dc in ($domainControllers)){
        if(!$Silent){Write-Host "Checking $dc"}
        $getProps.ComputerName = $dc
        Get-WinEvent @getProps | Where-Object -FilterScript $sb1 | Select-Object @selectProps
    }

    $results = $results | Sort-Object -Property $sortProps

    #Calculate our runtime
    $stopwatch.stop()
    $elapsedTime = $stopWatch.Elapsed

    #Add some more HTML content
    $htmlProps.body += "<p>Run Time:  $($elapsedTime.Minutes) min. $($elapsedTime.Seconds) sec.</p>"
    $htmlProps.body += "<p>Total Lockout Events: $($results.count) || Total Unique Users: $(($results | Select-Object -Property UserName -Unique).count)</p>"
    $htmlProps.body += "<hr />"
    if(!$results){
        $htmlProps.body += "<h2>No Results</h2>"
    }
    
    if($File){
        if(!$Silent){Write-Host "Output path is: $outPathFull"}
        $results | ConvertTo-HTML @htmlProps | Out-File $outPathFull
    }

    if(
        ($PSCmdlet.ParameterSetName -eq "Emailing") -and 
        $results
    ){
        #If we had results, lets export as a CSV and attach them to the mail message
        if($results){
            $results | Export-Csv -NoTypeInformation -Path $tempFile.FullName
            $tempFile = Move-Item @moveProps -PassThru
            $sendMailProps.Attachments = $tempFile.FullName
            $sendMailProps.Body = $results | ConvertTo-HTML @htmlProps | Out-String
        }
        
        Send-MailMessage @sendMailProps
    }
}

END {
    $tempFile | Remove-Item
    Get-Variable @('results','tempFile') -ErrorAction SilentlyContinue | Remove-Variable -ErrorAction SilentlyContinue
}
