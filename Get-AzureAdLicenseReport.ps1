<#
.SYNOPSIS
    pull a license report from AzureAD for specific or all users
.DESCRIPTION
    The script querys the requested users (all or specific) from AzureAD as well as the licenses the company has subscribed to.
    It then creates a list ticking off ('x') the licenses for every user
.EXAMPLE
    PS C:\> .\Get-AzureADLicenseReport.ps1 -All | Export-Csv report.csv -Encoding UTF8 -NoTypeInformation

    get a report for all users and save it in a .csv file
.EXAMPLE
    PS C:\> .\Get-AzureADLicenseReport.ps1 -UserPrincipalName einstein@physics.net

    get license report for user einstein@physics.net (standard output)
.INPUTS
    UserPrincipalName or -All
.OUTPUTS
    OrganizationalUnit, DisplayName, UserPrincipalName, AzureADLicenses 1..n
.NOTES
    Maximilian Otter, 20.05.2020
#>

#requires -Version 5.1
#requires -Modules AzureADPreview

[CmdletBinding()]
param(
    [Parameter(Position=0,ValueFromPipelineByPropertyName)]
    [string]$UserPrincipalName,
    [Parameter()]
    [switch]$All
)

begin {

    # Gather all licenses we have subscribed to
    $Licenses = Get-AzureADSubscribedSku | Sort-Object SkuPartNumber

    # Build basic structure for splatting Select-Object.
    # Use an [arraylist] to enable dynamic expansion of the structure based on the subscribed licenses
    $splat_SelectAzureADUser = @{

        Property = [System.Collections.ArrayList]@(

            # extract relevant path (with out domain and object name) and convert to classic path format
            @{
                Name        = 'OrganizationalUnit'
                Expression  = {
                    $OU= $_.ExtensionProperty['onPremisesDistinguishedName'] -split ',OU\=|,DC\='
                    $OU[($OU.count-3)..1] -join '/'
                }
            }
            # get DisplayName
            @{
                Name        = 'DisplayName'
                Expression  = { $_.DisplayName }
            }
            # get UserPrincipalName, in case there are people with equal DisplayNames
            @{
                Name        = 'UserPrincipalName'
                Expression  = { $_.UserPrincipalName }
            }

        )

    }

    # expand splat structure based on the subscribed licenses and add the hashes to the splat structure
    # licenses may be added or removed, so this must be dynamic
    foreach ($license in $Licenses) {

        $hash = @{
            Name        = $license.SkuPartNumber
            Expression  = [ScriptBlock]::Create( 'if ( "' + $license.SkuId + '" -in $_.AssignedLicenses.SkuId) { "x" }' )
        }
        $null = $splat_SelectAzureADUser.Property.Add($hash)

    }

    # if requested, process ALL AzureAd users, but return only those with at least one license set
    if ($All) {
        Get-AzureADUser -All $true `
        | Select-Object @splat_SelectAzureADUser `
        | Where-Object {
            process {
                $_.PSObject.Properties.Value -contains 'x'
            }
        }
    }

}

process {

    # process requested users(s), if licensed or not,
    # but only if -All was not requested
    if (!$All) {
        Get-AzureADUser -ObjectId $UserPrincipalName `
        | Select-Object @splat_SelectAzureADUser
    }

}

end {
    # nothing yet
}