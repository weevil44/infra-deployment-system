<#
.DESCRIPTION
Validate the parameter file to ensure it meets standards before attmepting to deploy it to Azure
when prevalidation and manual approvals are desired

.PARAMETER DeploymentList
A serialized list of parameer files that include the changes that need to be deployed

.PARAMETER WorkingDirectory
Allow you to provide an explicit working directory and override the default
This is not typically necessary
#>

# use the environment variable if a working directory is not passed in
[CmdletBinding()]
param(
    [string]$deploymentList,
    [string]$workingDirectory = $env:SYSTEM_DEFAULTWORKINGDIRECTORY
)

# import the local modules
Import-Module (Get-ChildItem -Recurse "$workingDirectory\pipeline\modules" | Where-Object { ($_.Name -like "*.psm1") } | Select-Object FullName).FullName

if ($workingDirectory -ne "") {
  Write-LoggerIDS -type "info" -message "Writing explicit working directory provided"
  Set-Location $workingDirectory
} else {
  $workingDirectory = (Get-Location).Path
}

$deploymentDetails = ConvertFrom-TransportStringIDS -transportString $deploymentList
$deploymentType = $deploymentDetails.DeploymentType

Write-LoggerIDS -type "info" -message "DeploymentType: $deploymentType"
Write-LoggerIDS -type "info" -message "Changes:"
$fileList = ($deploymentDetails.ParameterFiles -Join "`n")
Write-LoggerIDS -type "info" -message "$fileList`n"

if ($deploymentDetails.ParameterFiles.Count -gt 0) {
  $deploymentType = $deploymentDetails.deploymentType
  ForEach ( $parameterFile in $deploymentDetails.ParameterFiles ) {
    # If the resource does not exist, that would mean it is a delete operation
    # (unless it was moved, that would be bad), i'm not going to implement that yet either way
    if ( -not (Test-Path -Path $workingDirectory/$parameterFile -PathType leaf)) {
      Write-LoggerIDS -type "deprecated" -message "Resource deletion event found for [ $($parameterFile) ]"
      Write-LoggerIDS -type "deprecated" -message "Deletions are not yet supported. Please remove the resource manually"
    } else {
      Write-LoggerIDS -type "info" -message "Modified resource detected [ $($parameterFile) ]"
      $parameterPath = Join-Path -Path $WorkingDirectory -ChildPath $ParameterFile

      if (-not (Test-Path $parameterPath -PathType leaf)) {
        Write-LoggerIDS -type "error" -message "Parameter file could not be found @ [ $parameterPath ]"
      }

      $parameterObj = Get-Content -Raw $parameterPath | ConvertFrom-Json
      Write-LoggerIDS -type "info" -message "Performing $deploymentType deployment validation for $parameterFile..."
  
      try {   
        $validationResult = Test-DeploymentIDS -deploymentType $deploymentType -parameterObj $parameterObj
      } catch {
        Write-LoggerIDS -type "warning" -message "ErrorDetails.Message: $($_.ErrorDetails.Message)"
        Write-LoggerIDS -type "error" -message "Exception.Message: $($_.Exception.Message)"
      }

      if ( $ValidationResult.Valid -eq $false ) {
        Write-LoggerIDS -type "error" -message "Validation Failed!" -NoFailWhenError
        Write-LoggerIDS -type "error" -message $ValidationResult.ValidationMessage 
      } else {
        Write-LoggerIDS -type "success" -message "Validation Succeeded!"
      }
    }
  }
} else {
  # there arent any updates for this environment
  # log and exit cleanly here
  Write-Host "No changes pending for this environment"
}
