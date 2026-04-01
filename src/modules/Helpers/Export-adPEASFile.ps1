<#
.SYNOPSIS
    Central helper function for file export operations in adPEAS.

.DESCRIPTION
    Provides consistent file export handling across all adPEAS modules with:
    - Filename sanitization (removes invalid characters)
    - Path validation (checks directory exists)
    - Overwrite handling (warns if file exists, optional force)
    - Consistent error handling and logging

    Supports three export types:
    - Text: Plain text content (UTF-8)
    - Json: PowerShell objects converted to JSON (UTF-8, no BOM)
    - Binary: Raw byte arrays

.PARAMETER Path
    The target file path. Can be:
    - Full path: C:\Reports\output.json
    - Relative path: .\output.json
    - Filename only: output.json (uses current directory)

.PARAMETER Content
    The content to write. Type depends on -Type parameter:
    - Text: String content
    - Json: PowerShell object (will be converted to JSON)
    - Binary: Byte array

.PARAMETER Type
    The export type: Text, Json, or Binary.
    Default: Text

.PARAMETER JsonDepth
    For Json type: Maximum depth for ConvertTo-Json.
    Default: 10

.PARAMETER Force
    Overwrite existing file without warning.
    Default: $false (warns if file exists)

.PARAMETER SanitizeFilename
    Sanitize the filename part of the path (remove invalid characters).
    Default: $true

.PARAMETER CreateDirectory
    Create the target directory if it doesn't exist.
    Default: $false

.EXAMPLE
    Export-adPEASFile -Path "report.txt" -Content $reportText -Type Text
    Exports text content to report.txt in current directory.

.EXAMPLE
    Export-adPEASFile -Path "C:\Reports\templates.json" -Content $templateData -Type Json
    Exports object as JSON with depth 10.

.EXAMPLE
    Export-adPEASFile -Path "ticket.kirbi" -Content $ticketBytes -Type Binary -Force
    Exports binary data, overwriting if exists.

.EXAMPLE
    $result = Export-adPEASFile -Path "CertTemplate_$name.json" -Content $data -Type Json -SanitizeFilename
    Sanitizes filename (removes invalid chars) and exports.

.OUTPUTS
    PSCustomObject with:
    - Success: $true/$false
    - Path: Final resolved path (after sanitization)
    - Message: Success/error message
    - BytesWritten: Number of bytes written (if successful)

.NOTES
    Author: Alexander Sturz (@_61106960_)
#>

function Export-adPEASFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [Parameter(Mandatory=$true)]
        [object]$Content,

        [Parameter(Mandatory=$false)]
        [ValidateSet('Text', 'Json', 'Binary')]
        [string]$Type = 'Text',

        [Parameter(Mandatory=$false)]
        [int]$JsonDepth = 10,

        [Parameter(Mandatory=$false)]
        [switch]$Force,

        [Parameter(Mandatory=$false)]
        [switch]$SanitizeFilename = $true,

        [Parameter(Mandatory=$false)]
        [switch]$CreateDirectory
    )

    begin {
        # Characters invalid in Windows filenames
        $InvalidChars = [System.IO.Path]::GetInvalidFileNameChars()
    }

    process {
        try {
            # Resolve and validate path
            $resolvedPath = $Path

            # If path contains directory, split it
            $directory = [System.IO.Path]::GetDirectoryName($Path)
            $filename = [System.IO.Path]::GetFileName($Path)

            # Handle empty directory (filename only)
            if ([string]::IsNullOrEmpty($directory)) {
                $directory = Get-Location
            }

            # Sanitize filename if requested
            if ($SanitizeFilename -and -not [string]::IsNullOrEmpty($filename)) {
                $originalFilename = $filename
                foreach ($char in $InvalidChars) {
                    $filename = $filename -replace [regex]::Escape($char), '_'
                }
                # Also replace some problematic characters not in InvalidChars
                $filename = $filename -replace '[\[\]{}()]', '_'
                # Remove consecutive underscores
                $filename = $filename -replace '_+', '_'
                # Trim underscores from start/end
                $filename = $filename.Trim('_')

                if ($filename -ne $originalFilename) {
                    Write-Log "[Export-adPEASFile] Sanitized filename: '$originalFilename' -> '$filename'"
                }
            }

            # Reconstruct full path
            $resolvedPath = Join-Path -Path $directory -ChildPath $filename

            # Convert to absolute path
            if (-not [System.IO.Path]::IsPathRooted($resolvedPath)) {
                $resolvedPath = Join-Path -Path (Get-Location) -ChildPath $resolvedPath
            }

            Write-Log "[Export-adPEASFile] Target path: $resolvedPath"

            # Validate directory
            $targetDir = [System.IO.Path]::GetDirectoryName($resolvedPath)

            if (-not (Test-Path -Path $targetDir -PathType Container)) {
                if ($CreateDirectory) {
                    Write-Log "[Export-adPEASFile] Creating directory: $targetDir"
                    New-Item -Path $targetDir -ItemType Directory -Force | Out-Null
                } else {
                    return [PSCustomObject]@{
                        Success = $false
                        Path = $resolvedPath
                        Message = "Directory does not exist: $targetDir"
                        BytesWritten = 0
                    }
                }
            }

            # Check existing file
            if ((Test-Path -Path $resolvedPath) -and -not $Force) {
                Write-Warning "[Export-adPEASFile] File already exists: $resolvedPath (use -Force to overwrite)"
                return [PSCustomObject]@{
                    Success = $false
                    Path = $resolvedPath
                    Message = "File already exists (use -Force to overwrite)"
                    BytesWritten = 0
                }
            }

            # Write content based on type
            $bytesWritten = 0

            switch ($Type) {
                'Text' {
                    # Text content - use Out-File with specified encoding
                    $Content | Out-File -FilePath $resolvedPath -Encoding UTF8 -Force
                    $bytesWritten = (Get-Item $resolvedPath).Length
                    Write-Log "[Export-adPEASFile] Wrote text file: $bytesWritten bytes"
                }

                'Json' {
                    # JSON content - convert object and write without BOM
                    $jsonContent = $Content | ConvertTo-Json -Depth $JsonDepth

                    # Use UTF8 without BOM for JSON (better compatibility)
                    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
                    [System.IO.File]::WriteAllText($resolvedPath, $jsonContent, $utf8NoBom)

                    $bytesWritten = (Get-Item $resolvedPath).Length
                    Write-Log "[Export-adPEASFile] Wrote JSON file: $bytesWritten bytes"
                }

                'Binary' {
                    # Binary content - write raw bytes
                    if ($Content -isnot [byte[]]) {
                        return [PSCustomObject]@{
                            Success = $false
                            Path = $resolvedPath
                            Message = "Binary type requires byte array content"
                            BytesWritten = 0
                        }
                    }

                    [System.IO.File]::WriteAllBytes($resolvedPath, $Content)
                    $bytesWritten = $Content.Length
                    Write-Log "[Export-adPEASFile] Wrote binary file: $bytesWritten bytes"
                }
            }

            # Return success
            return [PSCustomObject]@{
                Success = $true
                Path = $resolvedPath
                Message = "Successfully exported to: $resolvedPath"
                BytesWritten = $bytesWritten
            }
        }
        catch {
            Write-Log "[Export-adPEASFile] Error: $($_.Exception.Message)"
            return [PSCustomObject]@{
                Success = $false
                Path = $resolvedPath
                Message = "Export failed: $($_.Exception.Message)"
                BytesWritten = 0
            }
        }
    }
}
