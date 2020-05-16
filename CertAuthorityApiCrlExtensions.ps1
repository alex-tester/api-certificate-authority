#ENCODE CRLS TO ASN1

[string[]]$CRLStrings = @("http://wootupdatedcontroller.crl","http://hmm-wow.crl")

$EncodeToAsnBody = @{
Oid = "2.5.29.31"
CrlLocations = $CRLStrings
} | ConvertTo-Json

$Base64EncodedCrlExtension = Invoke-RestMethod -Method Post -Uri http://dev-11.observicing.net/certificateauthority/Certificate/ConvertToBase64X509CrlExtensionData -Body $EncodeToAsnBody -ContentType application/json

#DECODE THE CRLS WE JUST ENCODED

$CRLDecodeFromAsnBody = @{
Oid = "2.5.29.31"
Base64ExtensionData = $Base64EncodedCrlExtension
} | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri http://dev-11.observicing.net/certificateauthority/Certificate/AsnFormattedDataFromBase64String -Body $CRLDecodeFromAsnBody -ContentType application/json

#EXTRA SAMPLES! FILES AND STUFF

#region extra samples
Invoke-RestMethod -Method get -Uri http://dev-11.observicing.net/certificateauthority/test/getasnformatteddata

$FileBytes = [System.IO.File]::ReadAllBytes("F:\DevGit\certs\csharptest\encodingusinglib\crltext-base64decode-bytes2.txt")
$FileBytesBase64 = [System.Convert]::ToBase64String($FileBytes)
$DataBody = @{
Oid = "2.5.29.31"
Base64ExtensionData = $FileBytesBase64
} | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri http://dev-11.observicing.net/certificateauthority/test/AsnFormattedDataFromBase64String -Body $DataBody -ContentType application/json


$FileDataBody = @{
Oid = "2.5.29.31"
FilePath = "F:\DevGit\certs\csharptest\encodingusinglib\crltext-base64decode-bytes1.txt"
} | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri http://dev-11.observicing.net/certificateauthority/test/AsnFormattedDataFromFile -Body $FileDataBody -ContentType application/json
#endregion

$base64bytes = Invoke-RestMethod -Method Get -Uri http://dev-11.observicing.net/certificateauthority/certificate/testcreateroot


$base64bytes = Invoke-RestMethod -Method Get -Uri http://dev-11.observicing.net/certificateauthority/certificate/testrequestclienttobase64bytespfx
$base64bytes = Invoke-RestMethod -Method Get -Uri http://dev-11.observicing.net/certificateauthority/test/testrequestclienttobase64bytescrt
$cb = [System.Convert]::FromBase64String($base64bytes)

[System.IO.File]::WriteAllBytes("F:\devgit\certs\csharptest\psexport6.pfx", $cb)
[System.IO.File]::WriteAllBytes("F:\devgit\certs\csharptest\psexport5.crt", $cb)


#from docker
$base64bytesc = Invoke-RestMethod -Method Get -Uri http://dev-11.observicing.net/certificateauthority/test/testrequestclienttobase64bytespfx
$base64bytesc = Invoke-RestMethod -Method Get -Uri http://dev-11.observicing.net/certificateauthority/test/testrequestclienttobase64bytescrt
$cbc = [System.Convert]::FromBase64String($base64bytesc)

[System.IO.File]::WriteAllBytes("F:\devgit\certs\csharptest\psexportc1.pfx", $cbc)
[System.IO.File]::WriteAllBytes("F:\devgit\certs\csharptest\psexportc1.crt", $cbc)


Export-PfxCertificate -Cert $crt -FilePath F:\DevGit\certs\csharptest\psexport.pfx



#get CRL CRT
$base64Crl = Invoke-RestMethod -Method Get -Uri http://dev-11.observicing.net/certificateauthority/test/testcrlgen
$crlb = [System.Convert]::FromBase64String($base64Crl)
[System.IO.File]::WriteAllBytes("F:\devgit\certs\csharptest\crltest.crt", $crlb)