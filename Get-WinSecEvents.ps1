[CmdletBinding()]
    Param
    (
        #we'll add some stuff later
    )

BEGIN {
    
    #Microsoft Security Audit Event ID's and complete messages
    #https://download.microsoft.com/download/8/E/1/8E11AD26-98A1-4EE3-9F7F-1DB4EB18BADF/WindowsSecurityAuditEvents.xlsx

    #Setup output files and directories, then test for existing file and ability to write data in the destination..
    $now = Get-Date
    $outFileName = "SecurityEvents_$(Get-Date $now -format "yyyy-MM-dd").csv"
    $outDir = "."
    $outFile = "$outDir\$outFileName"

    #Does our file already exist?  Can we rite to the dir?
    try {
        if(Test-Path -Path $outFile){Remove-Item -Path $outFile -ErrorAction Stop}
        else{
            New-Item -ItemType File -Name "test" -Path $outDir -ErrorAction Stop | Out-Null
            Remove-Item -Path "$outDir\test" | Out-Null
        }
    }
    catch {
        throw
    }

    #What hosts should we get out logs from?
    
    #Lets get all the domain controllers in the domain
    $computerList = $(Get-ADDomainController -Filter * | Select-Object Name | Sort-Object -Property Name).Name

    #or lets name our hosts explicity..
    #$computerList = @()
    
    #Ask the console user to select a reference date. We'll then get x number of days worth of data, Before this date.
    #if you want today's data up to now, use tomorrow as your reference data
    $refDateInput = Read-Host "Please choose your a reference date in format (MM/DD/YYYY) [now]"
    if(!$refDateInput){$refDate = Get-Date -Hour 0 -Minute 0 -Second 0 -Millisecond 0}
    else {
        $refDate = Get-Date `
            -Year $($refDateInput -split "/")[2] `
            -Month $($refDateInput -split "/")[0] `
            -Day $($refDateInput -split "/")[1] `
            -Hour 0 `
            -Minute 0 `
            -Second 0 `
            -Millisecond 0
    }

    Do {
        
        #We really don't want this script to take too long, so let's cap the number days we're allowed to query
        Write-Host -ForeGroundColor Yellow "Your input has to be a positive number and less than 30."
        
        #using try / catch because  if someone does not use an integer value it throws an error since we are caseting our variable type
        try {
            [int]$numDays = Read-Host "Number of days of logs to retrieve" -ErrorAction Stop
        }
        catch {
            $numDays = $null
        }
    
    } While (
        ($numDays -isnot [int]) -or
        ($numDays -gt 30) -or 
        ($numDays -lt 0)
    )
    
    #Now lets create a start date sometime in the past
    $startTime = (Get-Date $refDate).AddDays($(if(!$numdays -or $numDays -eq 0){0}else{$numDays*-1}))
    
    $filterProps = @{
    
        FilterHashTable = @{
            LogName      = "Security"
            ProviderName = 'Microsoft-Windows-Security-Auditing'
            ID           = @(
                            
                            #Lockout Related
                            #===============
                            '4740' #A user account was locked out.
                            '4625' #An account failed to log on.
                            #'4771' #Kerberos pre-authentication failed.
                            #'4777' #The domain controller failed to validate the credentials for an account.

                            )
            StartTime   = $startTime
            EndTime     = $refDate
        }
    
        ComputerName = [string]$null
    }
}

PROCESS {
    foreach ($computer in $computerList){
        Write-Host $computer

        try {
            $filterProps.ComputerName = $computer
            $results = Get-WinEvent @filterProps -ErrorAction SilentlyContinue

            $allResults = foreach ($result in ($results)){
                
                #Many of the event messages have footer text that is not relevant.  Lets remove that data
                switch ($result.Id){
                    4740 { $messageTrim = 15 }
                    4625 { $messageTrim = 35 }
                    4771 { $messageTrim = 22 }
                    4777 { $messageTrim = 6 }
                }

                #produce array of property values, rather than walk an XML to get numbered elements
                $eventDetails = foreach ($kvp in ($result | Select-Object -ExpandProperty Properties).GetEnumerator()) {$kvp.Value}

                #Create a custom object with all the data we need from the printer event and store
                $thisObject = [PSCustomObject]@{
                    RecordID            = $result.RecordID
                    ProcessID           = $result.ProcessID
                    ThreadID            = $result.ThreadID
                    EventID             = $result.Id
                    HostName            = $result.MachineName
                    TimeCreated         = $result.TimeCreated
                    LevelDisplayName    = $result.LevelDisplayName
                    OpcodeDisplayName   = $result.OpcodeDisplayName
                    Message             = $result.Message.Split("`n") | Select-Object -First $messageTrim | Out-String
                }

                $i=1

                foreach($value in $eventDetails){
                    $thisObject | Add-Member -MemberType NoteProperty -Name "Element$i" -Value $value
                    $i++
                }

                $thisObject
            }

            #Store our data only if there are results to store..
            if($allResults){$allResults | Export-Csv -NoTypeInformation -Path $outFile -Append}
        }
        catch {
            throw
        }
        finally {
            $filterProps.ComputerName = $null
            Get-Variable @('allResults','thisObject','eventDetails','i') | Remove-Variable -ErrorAction SilentlyContinue | Out-Null
        }
    }
}

END {
    
}
