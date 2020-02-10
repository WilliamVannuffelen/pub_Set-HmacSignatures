#---------------------------------------------------------- 
# STATIC / INITIAL VARIABLE DECLARATIONS
#---------------------------------------------------------- 
#
$dateNow = Get-Date -Format yyyy-MM-dd
$logFile = "path\logFile_$($dateNow).txt"
$secretPath = "path\hmacKey.xml"
$office365CredentialsPath = "path\office365Credentials.xml"
$invalidRrnUserPath = "path\invalidRrnUsers_$($dateNow).csv"
$script:errors = $false # used to send trigger error report for non-terminating errors

#---------------------------------------------------------- 
# FUNCTION DEFINITIONS
#---------------------------------------------------------- 
#
# add timestamp
function Get-TimeStamp {
    return Get-Date -f "yyyy-MM-dd HH:mm:ss -"
}

# remove non-numerical characters from string
Function Format-Num {
    [System.Text.RegularExpressions.Regex]::Replace($args,"[^01-9]","");
}

# test employeeNumber to see if value is empty, invalid, RRN or BIS
Function Test-Rrn($employeeNumber){
    If(!$employeeNumber){
        Return $null
    }
    If($employeeNumber.Length -lt 11){
        Return $false
    }
    #if user born after 2000 --> use different formula
    If($employeeNumber[0] -eq '0'){
        $employeeNumber_temp = '2' + $employeeNumber.SubString(0,9)
        $validationNum = 97 - ([int64]$employeeNumber_temp % 97)

        If($validationNum -lt 10){$validationNum = "0$($validationNum)"}

        #check valid RRN
        If(($employeeNumber.SubString(9,2) -eq [string]$validationNum) -and ([int]($employeeNumber.SubString(2,2) -le 12))){
            Return "RRN"
        }
        #check valid BIS
        ElseIf(($employeeNumber.SubString(9,2) -eq [string]$validationNum) -and (([int]($employeeNumber.SubString(2,2) -gt 20 -and [int]$employeeNumber.SubString(2,2) -le 52)))){
            Return "BIS"
        }
        Else{
            Return $false
        }       
    }
    #if user is born before 2000, use default formula
    Else{
        $employeeNumber_temp = $employeeNumber.SubString(0,9)
        $validationNum = 97 - ([int64]$employeeNumber_temp % 97)

        If($validationNum -lt 10){$validationNum = "0$($validationNum)"}

        #check valid RRN
        If(($validationNum -eq $employeeNumber.SubString(9,2)) -and ([int]($employeeNumber.SubString(2,2) -le 12))){
            Return "RRN"
        }
        #check valid BIS
        ElseIf(($validationNum -eq $employeeNumber.SubString(9,2)) -and (([int]($employeeNumber.SubString(2,2) -gt 20 -and [int]$employeeNumber.SubString(2,2) -le 52)))){
            Return "BIS"
        }
        Else{
            Return $false
        }
    }
}

# import hmac key
function Import-HmacKey($secretPath){
    try{
        "$(Get-Timestamp) Importing CliXml containing hmac secret key." | Add-Content -Path $logFile
        $secretSecurestring = (Import-CliXml -Path $secretPath -ErrorAction Stop).Password
    }
    catch [System.Security.Cryptography.CryptographicException]{
        "$(Get-Timestamp) ERROR - DPAPI: Failed to decrypt key in current context. Make sure the script is running under the service account's context and from the original machine. Terminating script." | Add-Content -Path $logFile
        $_.Exception.Message | Add-Content -Path $logFile
        Send-ErrorReport
        "$(Get-Timestamp) Script ended." | Add-Content -Path $logFile
        exit
    }
    catch{
        "$(Get-Timestamp) ERROR - Failed to import HMAC secret key. Please check logs for details. Terminating script." | Add-Content -Path $logFile
        $_.Exception.Message | Add-Content -Path $logFile
        Send-ErrorReport
        "$(Get-Timestamp) Script ended." | Add-Content -Path $logFile
        exit
    }

    # convert hmac key from securestring to plaintext
    $secretBstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secretSecureString)
    $secretHexString = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($secretBstr)

    return $secretHexString
}

#import O365 credentials
function Import-O365Credentials($office365CredentialsPath){
    try{
        "$(Get-Timestamp) Importing CliXml containing O365 credentials." | Add-Content -Path $logFile
        $office365Credentials = Import-CliXml -Path $office365CredentialsPath -ErrorAction Stop
        return $office365Credentials
    }
    catch [System.Security.Cryptography.CryptographicException]{
        "$(Get-Timestamp) ERROR - DPAPI: Failed to decrypt key in current context. Make sure the script is running under the service account's context and from the original machine." | Add-Content -Path $logFile
        $_.Exception.Message | Add-Content -Path $logFile
        $script:errors = $true
        return $false
    }
    catch{
        "$(Get-Timestamp) ERROR - Failed to import O365 credentials. Please check logs for details." | Add-Content -Path $logFile
        $_.Exception.Message | Add-Content -Path $logFile
        $script:errors = $true
        return $false
    }
}

# generate hmac signature
function New-HmacSignature($secretHexString, $employeeNumber){
    ### 1: Convert secret key hex string to byte array
    # instantiate empty byte array
    $secretByteArray = [Byte[]]::New($secretHexString.Length / 2)
    # decode hex string and populate array
    For($i=0; $i -lt $secretHexString.Length; $i+=2){
        $secretByteArray[$i/2] = [System.Convert]::ToByte($secretHexString.SubString($i, 2), 16)
        }

    ### 2: Generate hmac signature of rrn
    # instantiate hmac object    
    $hmacSha = New-Object System.Security.Cryptography.HMACSHA256
    # set key to secret byte array
    $hmacSha.key = $secretByteArray
    # generate hmac signature byte array
    $hmacSig = $hmacSha.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($employeeNumber))

    ### 3: Convert hmac signature byte array to hex string
    # instantiate string builder
    $hexStringBuilder = [System.Text.StringBuilder]::New($hmacSig.Length * 2)
    # generate hex string from hmac sig byte array
    ForEach($byte in $hmacSig){
        [void]$hexStringBuilder.AppendFormat("{0:x2}", $byte)
        }
    # cast builder to string
    $hmacSigHexString = $hexStringBuilder.ToString()
    
    return $hmacSigHexString
}

function New-UserList($secretHexString){
    "$(Get-Timestamp) Creating collection of all user objects in default user OU." | Add-Content -Path $logFile

    $attempts = 0
    $success = $false

    $params = @{
        Filter = "*"
        SearchBase = "OU=Users,DC=CONTOSO,DC=COM"
        Properties = "enabled","name","sAMAccountName","userPrincipalName","employeeNumber","extensionAttribute15","whenCreated"
    }
    Do{
        Try{
            # list instead of array for performance
            $allUsers = New-Object System.Collections.Generic.List[System.Object]
            $user = Get-ADUser @params -ErrorAction Stop |
                Select-Object   @{Name="name";                  Expression={$_.name}},
                                @{Name="sAMAccountName";        Expression={$_.sAMAccountName}},
                                @{Name="userPrincipalName"; 	Expression={$_.userPrincipalName}},
                                @{Name="enabled";               Expression={$_.enabled}},
                                @{Name="employeeNumber";        Expression={Format-Num $_.employeeNumber}},
                                @{Name="rrnType";               Expression={Test-Rrn (Format-Num $_.employeeNumber)}},
                                @{Name="hmacSigAd";             Expression={$_.extensionAttribute15}},
                                @{Name="hmacSigCalc";           Expression={
                                    switch ($_.employeeNumber){
                                        {(Test-Rrn (Format-Num $_)) -eq "RRN"} {New-HmacSignature $secretHexString (Format-Num $_); break}
                                        {(Test-Rrn (Format-Num $_)) -eq "BIS"} {New-HmacSignature $secretHexString (Format-Num $_); break}
                                        default {$null}
                                    }
                                }},
                                @{Name="whenCreated";           Expression={$_.whenCreated}}

            $allUsers.Add($user)
            $allUsers = $allUsers[0]
                                
            "$(Get-Timestamp) Collected data on $($allUsers.Count) user objects." | Add-Content -Path $logFile
            $success = $true
        }
        Catch{
            "$(Get-Timestamp) Could not create collection of Kompas users. Trying again in five seconds." | Add-Content -Path $logFile
            $_.Exception.Message | Add-Content -Path $logFile
            $script:errors = $true
            Start-Sleep -Seconds 5
        }
    }Until(($attempts -eq 5) -or $success)

    If(!$success){
        "$(Get-Timestamp) ERROR - Failed to query AD for user data. The script will now send an error report and terminate." | Add-Content -Path $logFile
        Send-ErrorReport
        "$(Get-Timestamp) Script ended." | Add-Content -Path $logFile
        exit
    }
    
    $validRrnUsers = $allUsers | Where-Object {($_.rrnType -eq "RRN") -or ($_.rrnType -eq "BIS")}
    $invalidRrnUsers = $allUsers | Where-Object {($_.rrnType -ne "RRN") -and ($_.rrnType -ne "BIS")}

    return $allUsers, $validRrnUsers, $invalidRrnUsers
}

# sanity check; ensure correct data isn't overwritten in bulk because of hashing error
# report and terminate if more than 50 changes would occur
function Test-HmacSignatures($validRrnUsers){
    $hmacDelta = $validRrnUsers | Where-Object {($_.hmacSigAd -ne $_.hmacSigCalc) -and ($_.hmacSigAd.Length -eq 64)}
    
    if($hmacDelta.Count -gt 50){
        "$(Get-Timestamp) ERROR - Found $(($hmacDelta | Measure-Object).Count) mismatches in HMAC between AD and current calculated value. Root cause should be investigated." | Add-Content -Path $logFile
        "$(Get-Timestamp) Terminating script without making any changes to AD." | Add-Content -Path $logFile
        Send-ErrorReport
        exit
    }
    "$(Get-Timestamp) Calculated $(($hmacDelta | Measure-Object).Count) HMAC signatures different to values stored in AD." | Add-Content -Path $logFile
    "$(Get-Timestamp) Comparing calculated HMAC signature values to values stored in AD." | Add-Content -Path $logFile
}

function Set-HmacSignature($user){
    if(($user.hmacSigCalc -ne $user.hmacSigAd) -and ($user.hmacSigCalc.Length -eq 64)){
        try{
            Set-ADUser -Identity $user.sAMAccountName -Replace @{extensionAttribute15 = $user.hmacSigCalc} -ErrorAction Stop
            "$(Get-Timestamp) Successfully set new HMAC signature for $($user.sAMAccountName) - $($user.hmacSigCalc)." | Add-Content -Path $logFile
            "$(Get-Timestamp) Old value was: '$($user.hmacSigAd)'." | Add-Content -Path $logFile
        }
        catch{
            "$(Get-Timestamp) ERROR - Failed to overwrite HMAC signature in AD for user $($user.sAMAccountName)." | Add-Content -Path $logFile
            $_.Exception.Message | Add-Content -Path $logFile
            $script:errors = $true
        }
    }
    elseif($user.hmacSigCalc.Length -ne 64){
        "$(Get-Timestamp) Calculated HMAC value is invalid: '$($user.hmacSigCalc)'." | Add-Content -Path $logFile
        $script:errors = $true
    }
    else{
        # calculated hmac sig matches hmac sig in ad - do nothing
    }
}

function Connect-Msol($office365Credentials){
    $attempts = 0
    $success = $false
    
    do{
        try{
            "$(Get-Timestamp) Connecting to MSOL." | Add-Content -Path $logFile
            Connect-MsolService -Credential $office365Credentials -ErrorAction Stop
            $success = $true
        }
        catch{
            "$(Get-Timestamp) Failed to create connection to MSOL. Trying again in 5 seconds." | Add-Content -Path $logFile
            $_.Exception.Message | Add-Content -Path $logFile
            $script:errors = $true
            Start-Sleep -Seconds 5
        }
        $attempts += 1
    }until(($attempts -eq 5) -or $success)

    if(!$success){
        "$(Get-Timestamp) ERROR - Failed to connect to MSOL to check user licences." | Add-Content -Path $logFile
        "$(Get-Timestamp) Script will continue, but users with an invalid RRN will not be reported." | Add-Content -Path $logFile
        return $false
    }
    return $true
}

function Test-O365Licence($user){
    try{
        # ignore accounts without UPN
        if($user.userPrincipalName.Length -gt 3){
            $userObject = Get-MsolUser -UserPrincipalName $user.userPrincipalName -ErrorAction Stop
        }
    }
    catch [Microsoft.Online.Administration.Automation.MicrosoftOnlineException]{
        if($_.fullyQualifiedErrorId -eq "Microsoft.Online.Administration.Automation.UserNotFoundException,Microsoft.Online.Administration.Automation.GetUser"){
            "$(Get-Timestamp) Not found in O365: $($user.userPrincipalName)." | Add-Content -Path $logFile
        }
        else{
            "$(Get-Timestamp) ERROR - Error while searching for user: $($user.userPrincipalName)." | Add-Content -Path $logFile
            $_.Exception.Message | Add-Content -Path $logFile
        }
    }
    catch{
        "$(Get-Timestamp) ERROR - Failed to find user $($user.userPrincipalName)." | Add-Content -Path $logFile
        $_.Exception.Message | Add-Content -Path $logFile
    }
    
    if($userObject.isLicensed -eq $true){
        "$(Get-Timestamp) Has a licence in O365 but is not able to authenticate: $($user.userPrincipalName)." | Add-Content -Path $logFile
        return $true
    }
    else{
        #"$(Get-Timestamp) User $($user.userPrincipalName) has no O365 licence." | Add-Content -Path $logFile
        return $false
    }
}

function Send-InvalidRrnUserReport{
    $body = "
    mail body
    "

    $attempts = 0
    $success = $false

    "$(Get-Timestamp) Sending report containing users who can't authenticate." | Add-Content -Path $logFile

    do{
        try{
            Send-MailMessage -SmtpServer "smtp.contoso.com" -To "" -From "" -Subject "mail title - $($dateNow)" -Body $body -Attachment $invalidRrnUserPath -ErrorAction Stop
            "$(Get-Timestamp) Mail sent successfully." | Add-Content -Path $logFile
            $success = $true
        }
        catch{
            "$(Get-Timestamp) Error sending email, trying again in five seconds." | Add-Content -Path $logFile
            $_.Exception.Message | Add-Content -Path $logFile
            Start-Sleep -Seconds 5
        }
    }until(($attempts -eq 5) -or $success)

    if(!$success){
        "$(Get-Timestamp) ERROR - Failed to send report on users with authentication problems." | Add-Content -Path $logFile
        $script:errors = $true
    }
}

# send logfile in case nonterminating errors were logged during runtime
function Send-ErrorReport{

    $body = "
    mail body
    "
    
    $attempts = 0
    $success = $false

    "$(Get-Timestamp) Script encountered errors. Sending logfile for investigation." | Add-Content -Path $logFile

    do{
        try{
            Send-MailMessage -SmtpServer "smtp.contoso.com" -To "" -From "" -Subject "mail title - $($dateNow)" -Body $body -attachment $logFile -ErrorAction Stop
            "$(Get-Timestamp) Mail sent successfully." | Add-Content -Path $logFile
            $success = $true
        }
        catch{
            "$(Get-Timestamp) Error sending email, trying again in five seconds." | Add-Content -Path $logFile
            $_.Exception.Message | Add-Content -Path $logFile
            Start-Sleep -Seconds 5
        }
    }until(($attempts -eq 5) -or $success)

    if(!$success){
        "$(Get-Timestamp) Failed to send log file. Sending plaintext mail." | Add-Content -Path $logFile
        $body = "
        mail body
        "

        Send-MailMessage -SmtpServer "smtp.contoso.com" -To "" -From "" -Subject "mail title - $($dateNow)" -Body $body
    }
}

#---------------------------------------------------------- 
# FUNCTION CALLS
#---------------------------------------------------------- 
#
"$(Get-Timestamp) Script started." | Add-Content -Path $logFile

$secretHexString = Import-HmacKey($secretPath)                                  # get secret from securestring
$allUsers, $validRrnUsers, $invalidRrnUsers = New-UserList $secretHexString     # create list of users with calculated properties
Test-HmacSignatures $validRrnUsers                                              # sanity check to ensure correct data isn't overwritten in bulk
ForEach($user in $validRrnUsers){
    Set-HmacSignature $user                                                     # set new hmac signature in ad if different
}
"$(Get-Timestamp) There are $(($invalidRrnUsers | Measure-Object).Count) users with an invalid RRN." | Add-Content -Path $logFile

$office365Credentials = Import-O365Credentials $office365CredentialsPath        # import service account credentials
$msolConnectionResult = Connect-Msol $office365Credentials                      # connect to O365
if($msolConnectionResult){              
    $licencedUsers = @()
    foreach($invalidRrnUser in $invalidRrnUsers){                               # for each user with an invalid RRN:
        if($invalidRrnUser.whenCreated -gt (Get-Date).AddDays(-3)){
            if(Test-O365Licence $invalidRrnUser){                               # test whether they exist in O365 and have an active licence
                $licencedUsers += $invalidRrnUser
            }
        }
    }
    if($licencedUsers.Count -gt 0){
        "$(Get-Timestamp) There are $(($licencedUsers | Measure-Object).Count) users with an invalid RRN who do have an O365 licence." | Add-Content -Path $logFile
        $licencedUsers | Sort-Object -Property sAMAccountName |
        Select-Object name, sAMAccountName, userPrincipalName, enabled |
            Export-Csv -Path $invalidRrnUserPath -NoTypeInformation -Encoding UTF8
    
        Send-InvalidRrnUserReport                                               # send mail report for licenced users with invalid RRN -> no auth possible
    }
}

if($script:errors){Send-ErrorReport}                                            # send mail report for nonterminating errors
"$(Get-Timestamp) Script ended." | Add-Content -Path $logFile