<?php

//----------------------------------------------------------------------------------------
// Configuration.
// Where to store the current CRL file.
$CRL_CURRENT = "vpn.crl";
// Where to temporarily store the new CRL file for verification.
$CRL_TEMP    = "update_vpn_crl.tmp";
// Where the root certificate can be found.
$ROOT_CRT    = "update_vpn_crl.root.crt";
// Normally a CRL is quite small.
$SIZE_LIMIT  = 1024*1024*10;

//----------------------------------------------------------------------------------------
// Quit with bad request message.
function bad_request(string $msg) : void {
   http_response_code(400);
   die($msg);
}

//----------------------------------------------------------------------------------------
// Verify a CRL file and get its serial number.
function get_crl_info(string $filename) {
   if (!file_exists($filename)) return false;

   global $ROOT_CRT;
   exec("openssl crl -noout -CAfile $ROOT_CRT -in $filename -crlnumber 2>&1", $res, $code);
   $res = join("\n", $res);
   
   if (!preg_match("/^verify OK$/m", $res)) return false;
   if (!preg_match('/^crlNumber=([0-9a-fA-F]+)$/m', $res, $matches)) return false;
   
   return ["crl_number" => hexdec($matches[1])];
}

//----------------------------------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] !== 'POST') bad_request("must be a POST request");

// Fetch POST payload.
$json = file_get_contents('php://input');
$data = json_decode($json, true);

if (!$data) bad_request("input needs to be json");
if (!isset($data["crl"])) bad_request("no crl in json");

$crl = (string)$data["crl"];

// Block huge files.
if (strlen($crl) > $SIZE_LIMIT) bad_request("too big");

// Store the new CRL temporarily for verification.
file_put_contents($CRL_TEMP, $crl);

// Validate it against the root certificate.
$info_tmp = get_crl_info($CRL_TEMP);
if (!$info_tmp) bad_request("validation failed");

// Read the current one and make sure that the new one has a newer serial number.
$info_c = get_crl_info($CRL_CURRENT);
if ($info_c) {
   if ($info_tmp["crl_number"] <= $info_c["crl_number"])
      bad_request("input is outdated");
}

// Save and serve the new CRL.
file_put_contents($CRL_CURRENT, $crl);

http_response_code(200);
echo "OK";
