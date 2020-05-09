<?php
require './Jwt.php';
require './JwtException.php';

// ---------------------------------------------------------------------------------------------------------------------
echo "测试HS256 ======================================================================== \n";
$key = '123456';
// 生成jwt
$jwt = \Jwt\Jwt::builder()->setPayload(['user_id' => 10000, 'exp' => 1600000000])->encode($key);
echo '生成jwt：' . $jwt;
echo "\n";

// 获取数据
$data = \Jwt\Jwt::builder()->decode($jwt, $key);
echo '解码jwt：';
print_r($data);
echo "\n";

// ---------------------------------------------------------------------------------------------------------------------
echo "测试RS256 ======================================================================== \n";
$key_pri = <<<EOD
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC/+/cZ2hV7EKh9
mnGOy3NpCQE69DbYHjj3KSbz7rBWN1K0fN8q+6U3cVFRgOJFDKeB/5Kf9Qdj694Q
jHvvBaIpgAALVYA01vfg4hR/XduW/9CChed3Wv9ka2TOSIO6F0iL5ToHBtXSm6Zx
jIZgXavFSahulBd3QYzFnPBOhutaFhRAnqdUqgyvk0swYWrqrpNEi54xnngW2F6/
+h1GSiDqYEVTISkoY8NKVy3YKOydRUNtGGi6dACo9X7hFY1CtC0YkkBrYiXv8G19
gGRM08WJihHI6PTloSyiwE+lrbIypl8wYU9EMpF8OuqZSTahmW0HptgszW8+wgCp
uzIW/7Q9AgMBAAECggEAK91oIhIAInQ16yzkkVnO7srN6yhtd4fAQEi4y7dXtvtA
/FgjrXB92WMcz2CBUoGHrF42pDGaFKyJuoI+tug0mwLR/8TzXB9Z15oQUOGjEKc2
fvwVXOH/xHP9Ply3LEexnbUsQvq+1DYYG42eDlqYqqUfxNQ1YFwry+MFzQtqrtRC
epsSMDdfNpaDCVXzTJ7mLZEzMvjAEdWHTac9Xa109HrMlJms3w2gis94s6ULZ4ND
c3NBiYCXExzfwzpOOIIVOHC7jdsa4JPMaQBOkcapaBMXS9na4ja5enQAvII6N8lE
VCsTazsT9DAvVZRjyPxgLFYAnf0T5vet9ogFjR+KgQKBgQD8JHL8psqDmDO2+hac
jPhrtiOKHXuoXod4cIRUFAsDWuxIzmqTKPliBl8H6hgG0QOuPCaB+lDya5eYnrAq
ydvf12/lqBO05Oc50Mwpn9kA9ed8ASZ0oSff9Gw5i98MLrTUTn3tT39qqtDpCefY
b/g9MC/CGyyifr2McjuVFH4mbQKBgQDC6+X393aS8IBGBCYkCv8KG8T3dN4ihkPR
kcjSg+JolHvMYq/tam4Lo8bZzFJ+zNw4LNRpFGtltZ+ABZD0mOmS3JMWb6A3veLJ
Y+4OZRXuR3IK1vSu566K7PGo4YJ9OTCxvB2V46ET40tgsBt9N5xPzLEGwC/CzJuA
P706Gu9jEQKBgQDiV5n9YYCj9updlEzeBdIvZtaqcmMCNrFnlaHElCV6wpEfnmSf
bAXKUCvYv/UHkXO7YfWzclBd/eWdNL6x+njtjMi/IU1ncqB7DwtnRj4YFabSc3ng
8pYH/bN1STFWD0t21mtGr7mSuHpG6AR/D6yIyQvmNFyyFhHz1MvVvQqtVQKBgEgX
lZurxAg+uUKsICsugfuMH8JiUBI21Hh7UepCawfA+zSxv12xAnh9n3tIba6GOGDy
e7FNoxcgIJjp9h3xPFpcCG7A5GIZcfqIYjCixIS3mf9WV3MlL1IkppCOr4N/Fnp2
F/8rDJVdeLCPEeuzGLYO/95+UGvc3xqE+Ii4E5fxAoGACxrCKrGnwiT41PVtJIj4
det7ofpItrgKdRJwdWoHmFSdmvttWxwa2aWUdiSiKHw/GzbJMV8IpcmtaklAXYxk
vxAENZ5HiEjkt/abYCfZFM9+K7CAncDu/QQf/p4xr5u6uiC55UAuB9ftouzJSfi+
7cDQ386Bz6ThH7iXk80wOlQ=
-----END PRIVATE KEY-----
EOD;
$key_pub = <<<EOD
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv/v3GdoVexCofZpxjstz
aQkBOvQ22B449ykm8+6wVjdStHzfKvulN3FRUYDiRQyngf+Sn/UHY+veEIx77wWi
KYAAC1WANNb34OIUf13blv/QgoXnd1r/ZGtkzkiDuhdIi+U6BwbV0pumcYyGYF2r
xUmobpQXd0GMxZzwTobrWhYUQJ6nVKoMr5NLMGFq6q6TRIueMZ54Fthev/odRkog
6mBFUyEpKGPDSlct2CjsnUVDbRhounQAqPV+4RWNQrQtGJJAa2Il7/BtfYBkTNPF
iYoRyOj05aEsosBPpa2yMqZfMGFPRDKRfDrqmUk2oZltB6bYLM1vPsIAqbsyFv+0
PQIDAQAB
-----END PUBLIC KEY-----
EOD;

// 生成jwt
$jwt = \Jwt\Jwt::builder()->setPayload(['user_id' => 10000, 'exp' => 1600000000])->setHeaderOfAlg('RS256')->encode($key_pri);
echo '生成jwt：' . $jwt;
echo "\n";

// 获取数据
$data = \Jwt\Jwt::builder()->decode($jwt, $key_pub);
echo '解码jwt：';
print_r($data);
