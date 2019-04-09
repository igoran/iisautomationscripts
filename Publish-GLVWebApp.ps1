param([string] $webApplicationPath,
[string] $webSiteName = "Default Web Site")

Import-Module WebAdministration;

function CleanUpWebSite([string] $webSiteName)
{
    $webSite = Get-Website | Where {($_.bindings.collection.protocol -eq 'http') -and ($_.bindings.collection.bindingInformation -eq '*:80:')}; 
    #$webSite = dir IIS:\Sites | Where-Object -Property Name -eq $webSiteName;
    if($webSite)
    {
        $existingWebSiteName = $webSite.Name;
        Remove-Website -Name $webSiteName;
        "Website $webSiteName removed"
    }
}

function CleanUpAppPool([string] $webAppPoolName)
{
    $webAppPool = Get-ChildItem IIS:\AppPools | Where-Object -Property Name -eq $webAppPoolName;
    if($webAppPool)
    {
        Remove-WebAppPool -Name $webAppPoolName;
        "Application Pool $webAppPoolName removed"
    }
}

function AddAppPool([string] $webAppPoolName, [string] $recycleTime = "03:15:00")
{
    New-WebAppPool -Name $webAppPoolName -Force;

    # Set Properties
    ## 
    Set-ItemProperty "IIS:\AppPools\$webAppPoolName" "managedRuntimeVersion" -Value "v4.0"
    Set-ItemProperty "IIS:\AppPools\$webAppPoolName" "managedPipelineMode" -Value "0" #Integrated
    Set-ItemProperty "IIS:\AppPools\$webAppPoolName" "Recycling.periodicRestart.schedule" -Value @{value=$recycleTime}
    Set-ItemProperty "IIS:\AppPools\$webAppPoolName" "Recycling.periodicRestart.time" -Value "0"
    Set-ItemProperty "IIS:\AppPools\$webAppPoolName" -Name processModel.idleTimeout -value ([TimeSpan]::FromMinutes(0))

    $appPool = Get-ChildItem "IIS:\AppPools" | ? { $_.name -eq $webAppPoolName }
    $appPool.processModel.identityType = "NetworkService"

    $appPool | Set-Item
}

function AddWebSite([string] $webSiteName, [string]$webApplicationRootPath, [string] $webAppPoolName)
{
    try 
    {
        New-Website -Name $webSiteName -Port 80 -PhysicalPath $webApplicationRootPath -ApplicationPool $webAppPoolName -Force;
        $webSite = Get-ChildItem IIS:\Sites\$webSiteName;
        if($webSite)
        {
            "Web Site $webSiteName successfully created."
        }
        else {
            Write-Error "Error while creating the Site $webSiteName"
        }        
    }
    catch 
    {
        Write-Error "Error while creating the Site $webSiteName - $_";
    }
}

function SetAcl([string] $parentFolder, [string]$userName, [System.Security.AccessControl.FileSystemRights] $rights)
{

    $InheritanceFlag = ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit)
    $PropagationFlag = [System.Security.AccessControl.PropagationFlags]::None

    $objType =[System.Security.AccessControl.AccessControlType]::Allow 

    $objUser = New-Object System.Security.Principal.NTAccount($userName) 

    $objACE = New-Object System.Security.AccessControl.FileSystemAccessRule ($objUser, $rights, $InheritanceFlag, $PropagationFlag, $objType) 

    $objACL = Get-ACL $parentFolder
    $objACL.AddAccessRule($objACE) 

    Set-ACL $parentFolder $objACL
}

function AddWebApplication([string] $Name, [string] $PhysicalPath,[string] $Site, [string] $ApplicationPool)
{
    New-WebApplication -Name $Name -ApplicationPool $ApplicationPool -PhysicalPath $PhysicalPath -Site $Site -Force;
    
    #Set Anonymous Identity to the App Pool one
    set-webconfigurationproperty /system.webServer/security/authentication/anonymousAuthentication -name userName -value ""

    #Grant AppPool Identity to the FileSystem
    SetAcl -parentFolder $PhysicalPath -userName "IIS AppPool\$ApplicationPool" -rights Modify;
    #As an alternative, you can set filesystem rights to allow the access to the IUSR User
    #SetAcl -parentFolder $PhysicalPath -userName "IUSR" -rights ReadAndExecute;
}

function ConfigureWebServer
{
    #Enable Static and Dynamic Compression
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/urlCompression" -name "doDynamicCompression" -value "true";
    Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' -filter "system.webServer/urlCompression" -name "doStaticCompression" -value "true";
}

$webApplicationPath = Resolve-Path $webApplicationPath;

if(Test-Path $webApplicationPath)
{
    ConfigureWebServer
    $appPoolName = ($webSiteName + "AppPool"); # Naming convention
    CleanUpWebSite -webSiteName $webSiteName
    CleanUpAppPool -webAppPoolName $appPoolName
    AddAppPool -webAppPoolName $appPoolName -recycleTime "00:15:00"

    $webSitePath = Split-Path -Path $webApplicationPath -Parent
    AddWebSite -webSiteName $webSiteName -webApplicationRootPath $webSitePath -webAppPoolName $appPoolName;
    AddWebApplication -Name GLVWebApp -Site $webSiteName -PhysicalPath $webApplicationPath -ApplicationPool $appPoolName;
}