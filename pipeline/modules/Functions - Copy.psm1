function Add-AadGroupMemberADS {
  # add a new member to an AAD group
	Param(
		[Parameter(Mandatory=$true)][string]$newMemberName,
    [Parameter(Mandatory=$true)][string]$groupId
	)
    
	$newMemberId = Get-PrincipalIdADS -principalName $newMemberName
	
	$groupMembers = Get-AzADGroupMember -ObjectId $groupId
	$existingMember =  $groupMembers | Where-Object { $_.Id -eq $newMemberId }
	if (!$existingMember) {
		write-LoggerADS -type "info" -message "Adding new member to group"
		Add-AzADGroupMember -MemberObjectId $newMemberId -TargetGroupObjectId $groupId
	}
}

function Add-CannotDeleteLockADS {
  # add a CanNotDelete lock at a specified scope.
  param (
    [Parameter(Mandatory = $true)][string]$subscriptionId,
    [Parameter(Mandatory = $true)][string]$resourceGroupName,
    [Parameter(Mandatory = $true)][string]$resourceProviderNamespace,
    [Parameter(Mandatory = $true)][string]$resourceType,
    [Parameter(Mandatory = $true)][string]$resourceName,
    [Parameter(Mandatory = $true)][string]$lockName
  )
  
  $Url = "https://management.azure.com/subscriptions/$subscriptionId/resourcegroups/$resourceGroupName/providers/$resourceProviderNamespace/$resourceType/$resourceName/providers/Microsoft.Authorization/locks/${lockName}?api-version=2016-09-01"
  $properties = @{
    "level" = "CanNotDelete"
  }
  $body = @{
    "properties" = $properties
  }
  Invoke-AzureApiADS -Method PUT -uri $Url -body $body
  Write-LoggerADS -type "info" -message "A CanNotDelete lock is being added for $resourceName"
}

function Add-RoleAssignmentADS {
  # add a role assignment on a resource
  param (
    [Parameter(Mandatory = $true)]$objectId,
    [Parameter(Mandatory = $true)]$scope,
    [Parameter(Mandatory = $true)]$role
  )

  if (-not [string]::IsNullOrEmpty($ObjectId)) {

      #get the role ID on target object to verfiy if already assigned
      Write-Host "Get RoleId..."
      $roleId = Get-AzRoleAssignment -Scope $scope -RoleDefinitionName $role -ObjectId $ObjectId 
      #Set the role on target object to verfiy if not already assigned
      if ( $null -eq $roleId -or $roleId.Length -eq 0 ) {
          $result = New-AzRoleAssignment -ObjectId $ObjectId -Scope $scope -RoleDefinitionName $role
          if (!$result) {
              Write-Error "Error creating role assignment"
              return
          }      
      } else {
          Write-Host "Role assignment already exist for $ObjectId" 
      }   
  } 
  Write-Host ":: Exit from set-RoleAssignmentCLIs "
}

function ConvertFrom-TransportStringADS {
  #  convert a deployment list back to a Powershell object
  param {
    [Parameter()][string]$transportString
  }

  $decodedTransportString = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($deploymentList))
  $transportObj = $decodedTransportString | ConvertFrom-Json
  
  return $transportObj
}

function ConvertTo-TransportStringADS {
  # convert a Powershell object to a string that can be passed between pipeline tasks
  #param {
  #  [Parameter()][PSCustomObject]$transportObj
  #}

    $jsonObj = $transportObj | ConvertTo-Json
    $jsonBytes = [System.Text.Encoding]::Unicode.GetBytes($jsonObj)
    $transportString =[Convert]::ToBase64String($jsonBytes)

    return $transportString
}

function Find-AzResourceADS {
  param (
    [Parameter(Mandatory = $true)][array]$resourceNames,
    [Parameter(Mandatory = $true)][string]$resourceType,
    [Parameter()][array]$subscriptions = $null
  )

  $subscriptionIds = @()
  $resources = @{}
  $token = Get-CachedTokenADS
  $apiUrl = "https://management.azure.com/subscriptions?api-version=2020-01-01"

  $subs = (Invoke-AzureApiADS -method Get -Uri $apiUrl).value
  foreach ($subscription in $subs) {
    if (-Not $subscriptions -or ($subscriptions -Contains $subscription.displayName)) {
      $subscriptionIds += ($subscription.subscriptionId).Trim()
    }
  }

  foreach ($resourceName in $resourceNames) {
    if ($resourceName) {
      $f = "resourceType eq '$resourceType' and name eq '$resourceName'"
      foreach ($subscriptionId in $subscriptionIds) {
        Logger -type "info" -message "Checking in subscription: $subscriptionId"
        $apiUrl = "https://management.azure.com/subscriptions/$subscriptionId/resources?`$filter=$f&api-version=2020-06-01"
        $resource = Invoke-AzureApiADS -method Get -Uri $apiUrl
        if ($resource.value.Count -Eq 1) {
          $resources[$resourceName] = @{
            subscriptionId = $subscriptionId;
            resourceId = ($resource.value.id).Trim();
            location = ($resource.value.location).Trim();
          }
          break
        }
      }
    }
  }
  return $resources
}

function Get-BearerTokenADS {
    # With this function you will get a bearer token to invoke azure rest api #
    param (
        [Parameter(Mandatory = $false)][String]$endpointUri  = "https://management.azure.com/"
    )

    $encodedSecret = [System.Web.HttpUtility]::UrlEncode(${env:APP_SECRET})
    $tokenUri = "https://login.microsoftonline.com/${env:SUBSCRIPTION_ID}/token"
    $authBody = "grant_type=client_credentials&client_id=${env:APP_ID}&client_secret=$encodedSecret&resource=$endpointUri"
    $contentType  = 'application/x-www-form-urlencoded'
    # make a rest call to get an access token

    try {
        $authToken = Invoke-RestMethod -Method Post -Uri "$tokenUri" -Body "$authBody" -ContentType $contentType
    } catch {
        $response = $_
        Write-LoggerADS -type "warning" -message "StatusCode: $($response.Exception.Response.StatusCode.value)"
        Write-LoggerADS -type "warning" -message "StatusDescription: $($response.Exception.Response.StatusDescription)"
    }

  return  ('Bearer {0}' -f ($authToken.access_token))
}

function Get-CachedTokenADS {
    # this function retrieves the current token after the user has already authenticated to Azure
    $context = Get-AzContext
    $profile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($profile)
    $t = $profileClient.AcquireAccessToken($context.Subscription.TenantId)
    $token = $t.AccessToken

    return $token
}

function Get-PrincipalADS {
  # query AD for a principal ID
  param (
    [Parameter(Mandatory = $true)][String]$principalName
  )

  $principalId = $null
  $principalType = $null
  $endpoint = "https://graph.microsoft.com"
  try {
    # get a token for graph to use in the API calls below
    $authToken = Get-BearerTokenADS -endpointUri "$endpoint"
    $headers = @{
        "Authorization" = "$authToken"
        'Content-Type'  = 'application/json'
    }
  } catch {
    Write-LoggerADS -type "warning" -message "exceptionMessage: $($_.Exception.Message)"
    Write-LoggerADS -type "warning" -message "errorDetailsMessage: $($_.ErrorDetails.Message)"
  }


  $supportedTypes = @('user','group','servicePrincipal','application')
  foreach ($type in $supportedTypes) {
    # try each supported type until the principalId is retrieved
    if ($null -eq $principalId) {
      if ($type -eq 'user') {
        $uri = "$endpoint/v1.0/users/$principalName"
      } elseif ($type -eq 'group') {
        $uri = "$endpoint/v1.0/groups?`$filter=displayName eq '$principalName'"
      } elseif ($type -eq 'servicePrincipal') {
        $uri = "$endpoint/v1.0/servicePrincipals?`$filter=displayName eq '$principalName'"
      } elseif ($type -eq 'application') {
        $uri = "$endpoint/v1.0/applications?`$filter=displayName eq '$principalName'"
      }

      try {
        $principal = Invoke-AzureApiADS -method GET -uri $uri -headers $headers -rawOutput
        $principalObj = $principal.content | ConvertFrom-Json
        if ($type -eq 'user') {
          $principalId = $principalObj.Id
        } else {
          $principalId = $principalObj.value.Id
        }

        if ($principalId) {
          $principalType = $type
          break
        }
      } catch {
        if ($_.Exception.Response.StatusCode.Value__ -ne "404") {
          # show the error unless it was not found
          Write-LoggerADS -type "warning" -message "exceptionMessage: $($_.Exception.Message)"
          Write-LoggerADS -type "warning" -message "errorDetailsMessage: $($_.ErrorDetails.Message)"
        }
      }
    }
  }

  $principal = [PSCustomObject]@{
    id = $principalId
    type = $principalType
  }

  #Write-LoggerADS -type "warning" -message "$principalName - $principalId"
  return $principal
}

function Invoke-AzureApiADS {
    param (
		[Parameter(Mandatory = $true)][string]$uri,
        [ValidateSet("Get", "HEAD", "Post", "Put", "Patch","Delete")][Parameter(Mandatory = $true)][string]$method,
		[Parameter(Mandatory = $false)][PSCustomObject]$body,
		[Parameter(Mandatory = $false)][Hashtable]$headers,
		[switch]$rawOutput,
		[switch]$throwError
    )

    if (-Not $headers) {
        $headers = @{
            "Authorization" = "Bearer $(Get-CachedTokenADS)"
            'Content-Type'  = 'application/json'
        }
    }

    if ($method -in ("Post", "Put", "Patch", "Delete")) {
        [Int32]$i = 0
        [int32]$numberOfRetries = 3
        [int32]$secondsBetweenRetries = 2
        $bodyStr = ($body | ConvertTo-Json -Depth 100)
        while ($true) {
            try {
                $response = Invoke-WebRequest -Method $method -headers $headers -Body $bodyStr -uri $uri -UseBasicParsing
                # $responseContent = $response | ConvertFrom-Json -Depth 10
                Write-LoggerADS -type "info" -message "statusCode: [ $($response.statusCode) ]"
                # Write-LoggerADS -type "info" -message "provisioningState: $($responseContent.properties.provisioningState)"
                # Write-LoggerADS -type "info" -message "provisioningState: $($response.properties.provisioningState)"
				if ($rawOutput.isPresent) {
					return $response
				}
                return $response.content | ConvertFrom-Json
            } catch {
                if ([int32]$_.Exception.Response.StatusCode -like "4*" -or $i -eq $numberOfRetries ) {
                    Write-LoggerADS -type "error" -message "exceptionMessage: $($_.Exception.Message)" -NoFailWhenError
                    Write-LoggerADS -type "error" -message "errorDetailsMessage $($_.ErrorDetails.Message)" -NoFailWhenError
					if ($throwError.isPresent) {
						Throw $_
                    } elseif ($rawOutput.isPresent) {
#                        Write-LoggerADS -type "info" -message "Returning raw output: $_"
					    return $_
					} else {
						return $null
					}
                } else {
                    $i++
                    Write-LoggerADS -type "warning" -message "exceptionMessage: $($_.Exception.Message)" -NoFailWhenError
                    Write-LoggerADS -type "warning" -message "errorDetailsMessage: $($_.ErrorDetails.Message)"
                    Write-LoggerADS -type "warning" -message "Retrying in [ $secondsBetweenRetries ] seconds, [ $i/$numberOfRetries ]"
                    Start-Sleep $secondsBetweenRetries
                }
            }
        }
    } elseif ($method -in ("Get", "HEAD") ) {
        [array]$allResponses = @()
        do {
            [Int32]$i = 0
            [int32]$numberOfRetries = 5
            [int32]$secondsBetweenRetries = 1
            while ($true) {
                try {
                    $response = Invoke-WebRequest -Method $method -Uri $uri -Headers $headers -UseBasicParsing
                    $responseObj = $response.content | ConvertFrom-Json
                    Write-LoggerADS -type "info" -message "statusCode: $($response.statusCode)"
					          if ($rawOutput.isPresent) {
						          $allResponses += $response
					          } else {
						          $allResponses += $responseObj
					          }
                    break
                } catch {
                    if ($_.Exception.Response.StatusCode.Value__ -like "4*" -or $i -eq $numberOfRetries ) {
                        # Write-LoggerADS -type "error" -message "exceptionMessage: $($_.Exception.Message)" -NoFailWhenError
						          if ($throwError.isPresent) {
							          throw $_
						          } else {
							          return $null
						          }   
                    } else {
                        $i++
                        Write-LoggerADS -type "warning" -message "exceptionMessage: $($_.Exception.Message)"
                        Write-LoggerADS -type "warning" -message "errorDetailsMessage: $($_.ErrorDetails.Message)"
                        Write-LoggerADS -type "warning" -message "Retrying in [ $secondsBetweenRetries ] seconds, [ $i/$numberOfRetries ]"
                        Start-Sleep $secondsBetweenRetries
                    }
                }
            }
            $uri = $responseObj.nextLink
        } until ($null -eq $responseObj.nextLink)
        return  $allResponses
    }
}

Function New-RandomStringADS {
  # https://powersnippets.com/create-password/
  [CmdletBinding()]
  param (									# Version 01.01.00, by iRon
    [Int]$Size = 8,
    [Char[]]$Complexity = "ULNS",
    [Char[]]$Exclude
  )
  $AllTokens = @(); $Chars = @(); $TokenSets = @{
    UpperCase = [Char[]]'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    LowerCase = [Char[]]'abcdefghijklmnopqrstuvwxyz'
    Numbers   = [Char[]]'0123456789'
    Symbols   = [Char[]]'!"#$%&''()*+,-./:;<=>?@[\]^_`{|}~'
  }
  $TokenSets.Keys | Where { $Complexity -Contains $_[0] } | ForEach {
    $TokenSet = $TokenSets.$_ | Where { $Exclude -cNotContains $_ } | ForEach { $_ }
    If ($_[0] -cle "Z") { $Chars += $TokenSet | Get-Random }					#Character sets defined in uppercase are mandatory
    $AllTokens += $TokenSet
  }
  While ($Chars.Count -lt $Size) { $Chars += $AllTokens | Get-Random }
  ($Chars | Sort-Object { Get-Random }) -Join ""								#Mix the (mandatory) characters and output string
}

function Register-ResourceProviderADS {
  <#
  This function will register a resource provider.
  The function will enable the passed providerNamespace.  You can determine the provider namespace by looking at the resource name in a template. For resourceType "Microsoft.KeyVault/vaults",
  the providerNamespace would be Microsoft.KeyVault
  #>
  param (
    [Parameter(Mandatory = $true)][string]$providerNamespace,
    [Parameter(Mandatory = $true)][string]$subscriptionId
  )

  $uri = "https://management.azure.com/subscriptions/$($subscriptionId)/providers/$($providerNamespace)?api-version=2020-06-01"
  $response = Invoke-AzureApiADS -method GET -uri $uri
  $content = $response.content | ConvertFrom-Json
  if ($content.namespace) {
    Write-LoggerADS -type "info" -message "Resource provider [$providerNamespace] is already set, nothing to do"
  } else {
    Write-LoggerADS -type "info" -message "Registering resource provider [$providerNamespace]"
  }
}

function Show-MessageADS {
  # show a warning or error message in the pipeline
	param (
		[Parameter(Mandatory = $true)][string]$message,
		[Parameter(Mandatory = $false)][string][ValidateSet("error", "warning")]$type = 'warning',
		[Parameter(Mandatory = $false)][string]$sourcePath,
		[Parameter(Mandatory = $false)][string]$lineNumber,
		[Parameter(Mandatory = $false)][string]$columnNumber,
		[Parameter(Mandatory = $false)][string]$code
	)

  if ($sourcePath) {
    $source = "sourcepath=$sourcePath;"
  }
  if ($lineNumber) {
    $line = "linenumber=$lineNumber;"
  }
  if ($columnNumber) {
    $column = "columnnumber=$columnNumber;"
  }
  if ($code) {
    $errorCode = "code=$errorCode;"
  }

  Write-Host "##vso[task.logissue type=$type;$source$line$column$errorCode]$message"
  $messageDetails = @{
    type      = "$type"
    source    = "$source"
    errorCode = "$errorCode"
    Message   = "$message"
  }  
}



function Test-IsBase64ADS {
  Param(
    [Parameter(Mandatory = $true)][string]$base64String	
  )

  try { 
    $null = [Convert]::FromBase64String($base64String)
    $isBase64 = $true 
  } catch {
    $isBase64 = $false
  }

  return $isBase64
}

function Test-NameAvailabilityADS {
	param (
		[Parameter(Mandatory = $true)][string]$resourceName,
		[Parameter(Mandatory = $true)][string]$provider,
		[Parameter(Mandatory = $true)][string]$resourceType,
		[Parameter(Mandatory = $true)][string]$apiVersion,
		[Parameter(Mandatory = $true)][string]$subscriptionId,
		[Parameter(Mandatory = $false)][string]$location = $null
	)
	
	$body = @{
		"name" = $resourceName
		"type" = "$($provider)/$($resourceType)"
	}
	
	$uri = "https://management.azure.com/subscriptions/$subscriptionId/providers/$provider/checkNameAvailability?api-version=$apiVersion"
	if ($location) {
		$uri = "https://management.azure.com/subscriptions/$subscriptionId/providers/$provider/locations/$location/checkNameAvailability?api-version=$apiVersion"
	}
	
	write-host $uri
	$results = Invoke-AzureApiADS -method POST -uri $uri -body $body
	return $results
}

function Test-ResourceIdExistenceADS {
  param (
    [Parameter(Mandatory = $true)][string]$resourceId
  )

  # the API call to check if the resourceId exists
  Write-LoggerADS -type "info" -message "Checking whether resource exists or not"

  [nullable[bool]]$idExists = $null
  try {
    # getting the current API version for this resource type
    $resourceSubscriptionId =  $resourceId.split("/")[2]
    $providerUri = "https://management.azure.com/subscriptions/$resourceSubscriptionId/providers?&api-version=2019-10-01"
    $resourceProviders = Invoke-AzureApiADS -method GET -uri $providerUri -throwError
    $provider = ($resourceId).split("/")[6]
    $resourceType = ($resourceId).split("/")[7]
    $apiVersion = ((($resourceProviders.value | Where-Object { $_.namespace -eq $provider }).resourceTypes | Where-Object { $_.resourceType -eq $resourceType }).apiVersions | Measure-Object -Maximum).Maximum

    $resourceUri = "https://management.azure.com$resourceId" + "?api-version=$apiVersion"

    $response = Invoke-AzureApiADS -Method GET -uri $resourceUri -throwError
    if ($response) {
      $idExists = $true
    }
  } catch {
    Write-LoggerADS -type "debug" -message "ErrorDetails.Message: $($_.ErrorDetails.Message)"
    Write-LoggerADS -type "debug" -message "Exception.Message: $($_.Exception.Message)"
    if ($_.Exception.Response.StatusCode -eq 404) {
      # if the statusCode is not 404, idExists will be empty instead of false and will fail the pipeline when checked later
      $idExists = $false
      Write-LoggerADS -type "debug" -message "Resource does not exist, the resourceExists is [ $idExists ]. This is not a failure, just a check to determine whether this is a new deployment or an update of an existing one"
    } else {
      Write-LoggerADS -type "error" -message "Failed to perform a REST API call to check whether the resource exists or not, got error code [ $($_.Exception.Response.StatusCode ) ]" -NoFailWhenError
    }
  }
  return $idExists
}

function Test-ResourceOwnershipAuthADS {
	Param(
		[Parameter(Mandatory=$true)][string]$resourceId
	)	
	
	$token = Get-PipelineAuthTokenADS
	$requestedForEmail = $env:BUILD_REQUESTEDFOREMAIL
	
	$resourceName = $resourceId.Split("/")[-1]
	
	if (-Not $env:DISABLE_AUTH_SYSTEM -And $resourceId -And $resourceName -And $requestedForEmail) 
	{

		$endUserToken = Get-AuthSystemUserTokenADS -Contact $requestedForEmail -requestorToken $token
		if (-Not $endUserToken) {
			Write-LoggerADS -type "error" -message "Unable to get Auth Token for User: [$requestedForEmail]"
		}

		$response = Check-AuthRecordOwnershipADS -Token $endUserToken -ResourceName $resourceName -ResourceId $resourceId
		Write-LoggerADS -type "info" -message "response: $($response.message)"

		$response.authorized | Should -Be $true -Because "
		:`n
		The end user: [$requestedForEmail] should be authorized to access [$resourceId] because you are creating a child resource to communicate with the resource [$resourceName]"
	} 
	else {
		Write-LoggerADS -type "warning" -message "Skipping Auth System protection"
	}
}

function Test-SkuAvailabilityADS {
	Param(
		[Parameter(Mandatory=$true)][string]$skuName,
		[Parameter(Mandatory=$true)][string]$location,
		[Parameter(Mandatory=$true)][string]$subscriptionId,
		[Parameter(Mandatory=$false)][string]$resourceProvider="Microsoft.Compute",
		[Parameter(Mandatory=$true)][string]$resourceType,
		[Parameter(Mandatory=$false)][array]$excludedSkuNames=@(),
		[Parameter(Mandatory=$false)][string]$capabilityName,
		[Parameter(Mandatory=$false)][string]$capabilityValue,
		[Parameter(Mandatory=$false)][string]$apiVersion="2019-04-01"
	)

    $url = "https://management.azure.com/subscriptions/$subscriptionId/providers/$($resourceProvider)/skus?api-version=$apiVersion&$" + "filter=location eq '$location'"
    $skus = Invoke-AzureApiADS -uri $url -method "GET"

    $allowedSkuNames = @()
    foreach ($sku in $skus.value) {
        if (($sku.resourceType -Eq $resourceType) -And ($sku.name -NotIn $excludedSkuNames)) {
          if ($capabilityName) {
            foreach($capability in $sku.capabilities) {
                if ($capability.Name -eq $capabilityName -and $capability.Value -eq $capabilityValue) {
                    $allowedSkuNames += $sku.name
                }
            }
          } else {
            $allowedSkuNames += $sku.name
          }
        }
    }
    return ($skuName -In $allowedSkuNames)
}

function Write-LoggerADS {
    param (
        [Parameter(Mandatory = $true)][string]$type,
        [Parameter(Mandatory = $true)][string]$message,
        [switch]$NoFailWhenError
    )

    if ($type -eq "error") {
        $message = "##[error]$message" # red
    } elseif ($type -eq "warning") {
        $message = "##[warning]$message" # orange
    } elseif ($type -eq "deprecated") {
        $message = "##[deprecated]$message" # yellow
    } elseif ($type -eq "success") {
        $message = "##[section]$message" # green
    } elseif ($type -eq "info") {
        $message = "##[command]$message" # blue
    } elseif ($type -eq "debug") {
        $message = "##[debug]$message" # purple
    }
    if ($type -eq "error" -and -Not $NoFailWhenError) {
        # Write-Error ($message.Replace("##[error]", ""))
        $ErrorActionPreference = "stop"
        Write-Error $message
    } else {
        Write-Host $message
    }
}
