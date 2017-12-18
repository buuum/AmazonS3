<?php

namespace AmazonS3;

class S3
{
    const ACL_PRIVATE = 'private';
    const ACL_PUBLIC_READ = 'public-read';
    const ACL_PUBLIC_READ_WRITE = 'public-read-write';
    const ACL_AUTHENTICATED_READ = 'authenticated-read';

    const STORAGE_CLASS_STANDARD = 'STANDARD';
    const STORAGE_CLASS_RRS = 'REDUCED_REDUNDANCY';
    const STORAGE_CLASS_STANDARD_IA = 'STANDARD_IA';


    private $accessKey;
    private $secretKey;
    private $bucket = false;

    private $acl = self::ACL_PUBLIC_READ;
    private $storage = self::STORAGE_CLASS_STANDARD;

    private $urlhttp;
    private $urlhttps;

    private $defaultHeaders = [];

    private $request = [
        'method' => '',
        'bucket' => '',
        'uri'    => ''
    ];

    public $endpoint = 's3.amazonaws.com';

    public function __construct($accessKey, $secretKey, $bucket)
    {
        $this->accessKey = $accessKey;
        $this->secretKey = $secretKey;
        $this->setBucket($bucket);
    }

    /**
     * @param $acl
     */
    public function setAcl($acl)
    {
        $this->acl = $acl;
    }

    /**
     * @param $headers
     */
    public function setDefaultHeaders($headers)
    {
        $this->defaultHeaders = $headers;
    }

    /**
     * @param $storage
     */
    public function setStorage($storage)
    {
        $this->storage = $storage;
    }

    /**
     * @param $bucket
     */
    public function setBucket($bucket)
    {
        if (substr($bucket, -1) == '/') {
            $bucket = substr($bucket, 0, -1);
        }

        $this->urlhttp = 'http://' . $this->endpoint . '/' . $bucket;
        $this->urlhttps = 'https://' . $this->endpoint . '/' . $bucket;

        $this->bucket = $bucket;
    }

    /**
     * @return mixed
     */
    public function getBucket()
    {
        return $this->bucket;
    }

    /**
     * @param bool $bucket
     * @return array|bool
     */
    public function listFiles($bucket = false)
    {
        $this->request = [
            'method' => 'GET',
            'bucket' => ($bucket) ? $bucket : $this->getBucket(),
            'uri'    => ''
        ];

        $response = $this->getResponse();

        if ($response['error']) {
            return false;
        }

        $xml_response = simplexml_load_string($response['message']);

        $results = [];
        foreach ($xml_response->Contents as $b) {
            $results[] = (string)$b->Key;
        }

        return $results;

    }

    /**
     * @return array|bool
     */
    public function listBuckets()
    {
        $this->request = [
            'method' => 'GET',
            'bucket' => '',
            'uri'    => ''
        ];

        $response = $this->getResponse();

        if ($response['error']) {
            return false;
        }

        $xml_response = simplexml_load_string($response['message']);

        $results = [];
        foreach ($xml_response->Buckets->Bucket as $b) {
            $results[] = (string)$b->Name;
        }

        return $results;
    }

    /**
     * @param $bucket
     * @return array
     */
    public function putBucket($bucket)
    {
        $this->request = [
            'method' => 'PUT',
            'bucket' => $bucket,
            'uri'    => ''
        ];

        return $this->getResponse();
    }

    /**
     * @param $bucket
     * @return array
     */
    public function deleteBucket($bucket)
    {
        $this->request = [
            'method' => 'DELETE',
            'bucket' => $bucket,
            'uri'    => ''
        ];

        return $this->getResponse();
    }


    /**
     * @param $url
     * @return array
     */
    public function deleteObjectUrl($url)
    {
        list($bucket, $file) = $this->parseS3($url);
        return $this->deleteObject($file, $bucket);
    }

    /**
     * @param $uri
     * @param $bucket
     * @return array
     */
    public function deleteObject($uri, $bucket = false)
    {
        $this->request = [
            'method' => 'DELETE',
            'bucket' => ($bucket) ? $bucket : $this->getBucket(),
            'uri'    => $uri
        ];

        return $this->getResponse();
    }

    /**
     * @param $uri
     * @param $bucket
     * @return array
     */
    public function getObject($uri, $bucket = false)
    {
        $this->request = [
            'method' => 'GET',
            'bucket' => ($bucket) ? $bucket : $this->getBucket(),
            'uri'    => $uri
        ];

        return $this->getResponse();
    }

    /**
     * @param $url
     * @param $uri
     * @param array $requestHeaders
     * @return array
     */
    public function putObjectUrl($url, $uri, $requestHeaders = [])
    {
        $string = $this->getImg($url);
        return $this->putObjectString($string, $uri, $requestHeaders);
    }

    /**
     * @param $string
     * @param $uri
     * @param array $requestHeaders
     * @return array
     */
    public function putObjectString($string, $uri, $requestHeaders = [])
    {
        if (extension_loaded('fileinfo')) {
            $file_info = new \finfo(FILEINFO_MIME_TYPE);
            $requestHeaders['Content-Type'] = $file_info->buffer($string);
        }
        if (empty($requestHeaders['Content-Type'])) {
            $requestHeaders['Content-Type'] = 'text/plain';
        }
        return $this->putObject($string, $uri, $requestHeaders);
    }

    /**
     * @param $file
     * @param $uri
     * @param array $requestHeaders
     * @return array
     */
    public function putObject($file, $uri, $requestHeaders = [])
    {

        $this->request = [
            'method' => 'PUT',
            'bucket' => $this->getBucket(),
            'uri'    => $uri
        ];

        return $this->getResponse($file, $requestHeaders);

    }

    /**
     * @param bool $sourcefile
     * @param array $headers
     * @return array
     */
    private function getResponse($sourcefile = false, $headers = [])
    {

        $verb = $this->request['method'];
        $bucket = $this->request['bucket'];
        $uri = $this->request['uri'];
        $uri = $uri !== '' ? '/' . str_replace('%2F', '/', rawurlencode($uri)) : '/';

        $headers = array_merge([
            'Content-MD5'         => '',
            'Content-Type'        => '',
            'Date'                => gmdate('D, d M Y H:i:s T'),
            'Host'                => $this->endpoint,
            'x-amz-storage-class' => $this->storage,
            'x-amz-acl'           => $this->acl
        ], $this->defaultHeaders, $headers);

        $resource = $uri;
        if ($bucket !== '') {
            if ($this->dnsBucketName($bucket)) {
                $headers['Host'] = $bucket . '.' . $this->endpoint;
                $resource = '/' . $bucket . $uri;
            } else {
                $uri = '/' . $bucket . $uri;
                $resource = $uri;
            }
        }

        $response = [];

        $url = 'https://' . $headers['Host'] . $uri;

        $curl = curl_init();
        curl_setopt($curl, CURLOPT_USERAGENT, 'S3/php');
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 0);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, 0);
        curl_setopt($curl, CURLOPT_URL, $url);

        // PUT
        if ($verb == 'PUT') {

            if ($sourcefile) {

                if ($file = $this->inputFile($sourcefile)) {
                    curl_setopt($curl, CURLOPT_PUT, true);
                    $fp = @fopen($file['file'], 'rb');
                    curl_setopt($curl, CURLOPT_INFILE, $fp);
                    curl_setopt($curl, CURLOPT_INFILESIZE, $file['size']);
                    $headers['Content-Type'] = $file['type'];
                } else {
                    $input = array(
                        'data'   => $sourcefile,
                        'size'   => strlen($sourcefile),
                        'md5sum' => base64_encode(md5($sourcefile, true))
                    );

                    $headers['Content-MD5'] = $input['md5sum'];

                    curl_setopt($curl, CURLOPT_CUSTOMREQUEST, $verb);
                    curl_setopt($curl, CURLOPT_POSTFIELDS, $input['data']);
                }


            } else {
                curl_setopt($curl, CURLOPT_CUSTOMREQUEST, $verb);
            }
        } elseif ($verb == 'DELETE') {
            curl_setopt($curl, CURLOPT_CUSTOMREQUEST, 'DELETE');
        }

        $sendheaders = [];
        $amz = [];

        foreach ($headers as $header => $value) {
            if (strlen($value) > 0) {
                $sendheaders[] = $header . ': ' . $value;
                if (strpos($header, 'x-amz-') === 0) {
                    $amz[] = strtolower($header) . ':' . $value;
                }
            }
        }

        if (sizeof($amz) > 0) {
            usort($amz, array(__CLASS__, 'sortAmzHeaders'));
            $amz = "\n" . implode("\n", $amz);
        } else {
            $amz = '';
        }

        $sendheaders[] = 'Authorization: ' . $this->getSignature(
                $verb . "\n" .
                $headers['Content-MD5'] . "\n" .
                $headers['Content-Type'] . "\n" .
                $headers['Date'] . $amz . "\n" .
                $resource
            );

        curl_setopt($curl, CURLOPT_HTTPHEADER, $sendheaders);
        curl_setopt($curl, CURLOPT_HEADER, false);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);


        $data = curl_exec($curl);
        $code = curl_getinfo($curl, CURLINFO_HTTP_CODE);

        $response['code'] = $code;
        $response['error'] = (in_array($code, [200, 204])) ? false : true;
        $response['message'] = $data;
        $response['url'] = [
            'default' => $url,
            'http'    => $this->urlhttp . $uri,
            'https'   => $this->urlhttps . $uri
        ];

        @curl_close($curl);

        if (isset($fp) && $fp !== false && is_resource($fp)) {
            fclose($fp);
        }

        return $response;
    }

    /**
     * @param $file
     * @return array|bool
     */
    private function inputFile($file)
    {
        if (!@file_exists($file) || !is_file($file) || !is_readable($file)) {
            return false;
        }

        return [
            'file'   => $file,
            'size'   => filesize($file),
            'type'   => $this->getMIMEType($file),
            'md5sum' => ''
        ];
    }

    /**
     * @param $file
     * @return string
     */
    private function getMIMEType($file)
    {
        $exts = [
            'jpg'  => 'image/jpeg',
            'jpeg' => 'image/jpeg',
            'gif'  => 'image/gif',
            'png'  => 'image/png',
            'ico'  => 'image/x-icon',
            'pdf'  => 'application/pdf',
            'tif'  => 'image/tiff',
            'tiff' => 'image/tiff',
            'svg'  => 'image/svg+xml',
            'svgz' => 'image/svg+xml',
            'swf'  => 'application/x-shockwave-flash',
            'zip'  => 'application/zip',
            'gz'   => 'application/x-gzip',
            'tar'  => 'application/x-tar',
            'bz'   => 'application/x-bzip',
            'bz2'  => 'application/x-bzip2',
            'rar'  => 'application/x-rar-compressed',
            'exe'  => 'application/x-msdownload',
            'msi'  => 'application/x-msdownload',
            'cab'  => 'application/vnd.ms-cab-compressed',
            'txt'  => 'text/plain',
            'asc'  => 'text/plain',
            'htm'  => 'text/html',
            'html' => 'text/html',
            'css'  => 'text/css',
            'js'   => 'text/javascript',
            'xml'  => 'text/xml',
            'xsl'  => 'application/xsl+xml',
            'ogg'  => 'application/ogg',
            'mp3'  => 'audio/mpeg',
            'wav'  => 'audio/x-wav',
            'avi'  => 'video/x-msvideo',
            'mpg'  => 'video/mpeg',
            'mpeg' => 'video/mpeg',
            'mov'  => 'video/quicktime',
            'flv'  => 'video/x-flv',
            'php'  => 'text/x-php'
        ];

        $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
        if (isset($exts[$ext])) {
            return $exts[$ext];
        }

        if (extension_loaded('fileinfo')) {
            $finfo = new \finfo(FILEINFO_MIME);
            $type = $finfo->file($file);
            $re = "@/(.*?);@";

            preg_match($re, $type, $matches);

            if (!empty($matches)) {
                $type = $matches[1];
            }

            if (isset($exts[$type])) {
                return $exts[$type];
            }
        }

        return 'application/octet-stream';
    }

    /**
     * @param $bucket
     * @return bool
     */
    private function dnsBucketName($bucket)
    {
        if (strlen($bucket) > 63 || preg_match("/[^a-z0-9\.-]/", $bucket) > 0) {
            return false;
        }
        if (strstr($bucket, '-.') !== false) {
            return false;
        }
        if (strstr($bucket, '..') !== false) {
            return false;
        }
        if (!preg_match("/^[0-9a-z]/", $bucket)) {
            return false;
        }
        if (!preg_match("/[0-9a-z]$/", $bucket)) {
            return false;
        }
        return true;
    }

    /**
     * @param $a
     * @param $b
     * @return int
     */
    private function sortAmzHeaders($a, $b)
    {
        $lenA = strpos($a, ':');
        $lenB = strpos($b, ':');
        $minLen = min($lenA, $lenB);
        $ncmp = strncmp($a, $b, $minLen);
        if ($lenA == $lenB) {
            return $ncmp;
        }
        if (0 == $ncmp) {
            return $lenA < $lenB ? -1 : 1;
        }
        return $ncmp;
    }

    /**
     * @param $string
     * @return string
     */
    private function getSignature($string)
    {
        return 'AWS ' . $this->accessKey . ':' . $this->getHash($string);
    }

    /**
     * @param $string
     * @return string
     */
    private function getHash($string)
    {
        return base64_encode(extension_loaded('hash') ?
            hash_hmac('sha1', $string, $this->secretKey, true) : pack('H*', sha1(
                (str_pad($this->secretKey, 64, chr(0x00)) ^ (str_repeat(chr(0x5c), 64))) .
                pack('H*', sha1((str_pad($this->secretKey, 64, chr(0x00)) ^
                        (str_repeat(chr(0x36), 64))) . $string)))));
    }

    /**
     * @param $url
     * @return mixed
     */
    private function getImg($url)
    {
        $ch = curl_init();
        $timeout = 5;
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)');
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, $timeout);

        if (substr($url, 0, strlen('https://')) == 'https://') {
            curl_setopt($ch, CURLOPT_BINARYTRANSFER, 1);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 0);
            curl_setopt($ch, CURLOPT_HEADER, 0);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        }

        $data = curl_exec($ch);
        curl_close($ch);
        return $data;
    }

    /**
     * @param $url
     * @return array
     */
    private function parseS3($url)
    {
        $bucket = $file = false;

        $re = '@//([^\/]+)/(.*?)$@';
        preg_match_all($re, $url, $matches);
        if (!empty($matches[0])) {
            $bucket = $matches[1][0];
            $file = $matches[2][0];
        }

        $re = '@//([^.]+).s3.amazonaws.com/(.*?)$@';
        preg_match_all($re, $url, $matches);
        if (!empty($matches[0])) {
            $bucket = $matches[1][0];
            $file = $matches[2][0];
        }

        $re = '@//s3-.*.amazonaws.com/([^\/]+)/(.*?)$@';
        preg_match_all($re, $url, $matches);
        if (!empty($matches[0])) {
            $bucket = $matches[1][0];
            $file = $matches[2][0];
        }

        $re = '@//s3.amazonaws.com/([^\/]+)/(.*?)$@';
        preg_match_all($re, $url, $matches);
        if (!empty($matches[0])) {
            $bucket = $matches[1][0];
            $file = $matches[2][0];
        }

        return [
            $bucket,
            $file
        ];

    }
}