<?php
/**
 * @author zwh
 * @date 20200509
 * Json Web Token 生成和验证
 */


namespace Jwt;


class Jwt
{
    private $header = [];

    private $payload = [];

    private static $instance;

    private function __construct()
    {
        // 默认
        $this->header = ['alg' => 'HS256', 'typ' => 'JWT'];
    }

    /**
     * @return Jwt
     */
    public static function builder()
    {
        if (!self::$instance instanceof self) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * @param $val
     * @return $this
     * 设置签名算法类型
     */
    public function setHeaderOfAlg($val)
    {
        $this->header['alg'] = $val;
        return $this;
    }

    /**
     * @param $val
     * @return $this
     * 设置类型
     */
    public function setHeaderOfTyp($val)
    {
        $this->header['typ'] = $val;
        return $this;
    }

    /**
     * @param $val
     * @return $this
     * 设置jwt签发者
     */
    public function setPayloadOfIss($val)
    {
        $this->payload['iss'] = $val;
        return $this;
    }

    /**
     * @param $val
     * @return $this
     * 设置jwt过期时间
     */
    public function setPayloadOfExp($val)
    {
        $this->payload['exp'] = $val;
        return $this;
    }

    /**
     * @param $val
     * @return $this
     * 设置主题
     */
    public function setPayloadOfSub($val)
    {
        $this->payload['sub'] = $val;
        return $this;
    }

    /**
     * @param $val
     * @return $this
     * 设置接收方
     */
    public function setPayloadOfAud($val)
    {
        $this->payload['aud'] = $val;
        return $this;
    }

    /**
     * @param $val
     * @return $this
     * 设置jwt生效时间
     */
    public function setPayloadOfNbf($val)
    {
        $this->payload['nbf'] = $val;
        return $this;
    }

    /**
     * @param $val
     * @return $this
     * 设置签发时间
     */
    public function setPayloadOfIat($val)
    {
        $this->payload['iat'] = $val;
        return $this;
    }

    /**
     * @param $val
     * @return $this
     * 设置jwt唯一身份标识
     */
    public function setPayloadOfJti($val)
    {
        $this->payload['jti'] = $val;
        return $this;
    }

    /**
     * @param $val
     * @return $this
     * 设置payload自定义信息
     */
    public function setPayload(array $val)
    {
        $this->payload = array_merge($this->payload, $val);
        return $this;
    }

    /**
     * @param $key
     * @return string jwt
     * @throws JwtException
     * 生成jwt
     */
    public function encode($key)
    {
        $header = base64_encode(json_encode($this->header, 320));
        $payload = base64_encode(json_encode($this->payload, 320));
        $signature = base64_encode($this->sign($header . '.' . $payload, $key));
        return $header . '.' . $payload. '.' . $signature;
    }

    /**
     * @param $jwt
     * @param $key
     * @return mixed
     * @throws JwtException
     * 解码jwt
     */
    public function decode($jwt, $key)
    {
        $cur_time = time();
        if (empty($jwt)) {
            throw new JwtException('jwt不能为空');
        }
        if (empty($key)) {
            throw new JwtException('jwt秘钥不能为空');
        }
        $jwt = explode('.', $jwt);
        // 检查jwt是否由三部分组成header,payload,signature
        if (3 != count($jwt)) {
            throw new JwtException('jwt错误');
        }
        list($header_base64, $payload_base64, $signature_base64) = $jwt;
        // 检查header部分是否存在
        if (empty($header = json_decode(base64_decode($header_base64), true))) {
            throw new JwtException('jwt header 错误');
        }
        // 检查header部分alg是否存在
        if (empty($header['alg'])) {
            throw new JwtException('jwt header alg 错误');
        }
        // 检查payload部分是否存在
        if (empty($payload = json_decode(base64_decode($payload_base64), true))) {
            throw new JwtException('jwt payload 错误');
        }
        // 验证签名
        $signature = base64_decode($signature_base64);
        if (!$this->verify($header_base64 . '.' . $payload_base64, $signature, $key, $header['alg'])) {
            throw new JwtException('jwt签名错误');
        }
        // 检查生效时间
        if (isset($payload['nbf']) && $payload['nbf'] > $cur_time) {
            throw new JwtException('jwt未到生效时间');
        }
        // 检查签发时间
        if (isset($payload['iat']) && $payload['iat'] > $cur_time) {
            throw new JwtException('jwt签发时间错误');
        }
        // 检查是否过期
        if (empty($payload['exp'])) {
            throw new JwtException('jwt过期时间不能为空');
        }
        if ($payload['exp'] < $cur_time) {
            throw new JwtException('jwt已过期');
        }
        return $payload;
    }

    /**
     * @param $input
     * @param $key
     * @return string
     * @throws JwtException
     * 生成签名
     */
    private function sign($input, $key)
    {
        $signature = '';
        switch (strtoupper($this->header['alg'])) {
            case 'RS256':
                openssl_sign($input, $signature, $key, "sha256");
                break;
            case 'HS256':
            default:
                $signature = hash_hmac('sha256', $input, $key, true);
                break;
        }
        if (empty($signature)) {
            throw new JwtException('签名失败');
        }
        return $signature;
    }

    /**
     * @param $input
     * @param $signature
     * @param $key
     * @param $alg
     * @return bool
     * 校验签名
     */
    private function verify($input, $signature, $key, $alg)
    {
        switch (strtoupper($alg)) {
            case 'RS256':
                $status = openssl_verify($input, $signature, $key, "sha256");
                if (1 == $status) {
                    return true;
                } else {
                    return false;
                }
                break;
            case 'HS256':
            default:
                $signature2 = hash_hmac('sha256', $input, $key, true);
                if ($signature == $signature2) {
                    return true;
                } else {
                    return false;
                }
                break;
        }
    }
}