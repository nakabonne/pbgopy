package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptDecrypt(t *testing.T) {
	tests := []struct {
		name        string
		keyForEnc   string
		keyForDec   string
		wantSuccess bool
	}{
		{
			name:        "wrong key given",
			keyForEnc:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			keyForDec:   "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			wantSuccess: false,
		},
		{
			name:        "right key given",
			keyForEnc:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			keyForDec:   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			wantSuccess: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				data       = []byte("data")
				cipherText = []byte{}
				plainText  = []byte{}
				err        error
			)
			cipherText, err = Encrypt([]byte(tt.keyForEnc), data)
			require.NoError(t, err)
			plainText, err = Decrypt([]byte(tt.keyForDec), cipherText)
			assert.Equal(t, tt.wantSuccess, err == nil)

			assert.Equal(t, tt.wantSuccess, string(data) == string(plainText))
		})
	}
}

func TestEncryptWithRSA(t *testing.T) {
	tests := []struct {
		name    string
		pubKey  string
		data    string
		wantErr bool
	}{
		{
			name:    "public key is not in pem format",
			pubKey:  "wrong format",
			data:    "data",
			wantErr: true,
		},
		{
			name: "public key is not an RSA key",
			pubKey: `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEHCNt1leLTTAoFkgUVxfG09WcJUUd
oiqxT2O1XOGpo9H4HnnEqVSvUuyd1immmS/1zTp+/gV6sE/ggdew5P5z7w==
-----END PUBLIC KEY-----
`,
			data:    "data",
			wantErr: true,
		},
		{
			name: "public key in PKCS #1",
			pubKey: `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAxfF/4htmaoT582+d8PllIgyLV4DhUQJ0vEekgPuQ2Z5361pX53AG
2Isboo704sWp+mBd4cLwBHMlKpgKToEM/n7a5dD8rBD+jkjTt+9G033Vmg7bRaBs
edX90pTVERdw/Fj/Tk3i0bTNI6Rtd3bktiORpV/SsyHuYCBt0L6/ZDf/9XKhqYnw
hxvYi02fC57YKQXhRUZUTTuULEdkX/pzxA6EoL1iJaau3iMdnpDppntb8s7m4NJQ
gMVLuGggJuDHANjrhXeUpZmGwhWjD4H2w00sKGZOLkP00BzoE7BopfPe0V6V6qE/
UnSyBogA7OY6deUAf1nTrNVsXjuDUAwrYQIDAQAB
-----END RSA PUBLIC KEY-----
`,
			data:    "data",
			wantErr: false,
		},
		{
			name: "public key in PKCS #8",
			pubKey: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxfF/4htmaoT582+d8Pll
IgyLV4DhUQJ0vEekgPuQ2Z5361pX53AG2Isboo704sWp+mBd4cLwBHMlKpgKToEM
/n7a5dD8rBD+jkjTt+9G033Vmg7bRaBsedX90pTVERdw/Fj/Tk3i0bTNI6Rtd3bk
tiORpV/SsyHuYCBt0L6/ZDf/9XKhqYnwhxvYi02fC57YKQXhRUZUTTuULEdkX/pz
xA6EoL1iJaau3iMdnpDppntb8s7m4NJQgMVLuGggJuDHANjrhXeUpZmGwhWjD4H2
w00sKGZOLkP00BzoE7BopfPe0V6V6qE/UnSyBogA7OY6deUAf1nTrNVsXjuDUAwr
YQIDAQAB
-----END PUBLIC KEY-----
`,
			data:    "data",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := EncryptWithRSA([]byte(tt.pubKey), []byte(tt.data))
			assert.Equal(t, tt.wantErr, err != nil)
		})
	}
}

func TestDecryptWithRSA(t *testing.T) {
	tests := []struct {
		name    string
		privKey string
		pubKey  string
		data    string
		wantErr bool
	}{
		{
			name:    "private key is not in pem format",
			privKey: "wrong format",
			data:    "data",
			wantErr: true,
		},
		{
			name: "private key is not an RSA key",
			privKey: `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBrmPEa2FeCt6er0JjnBy3a/2+VfWemeHGkSULEtj2iOoAoGCCqGSM49
AwEHoUQDQgAEQkiV2hHuY1zOujXtuKRuj0sKXpt4vfO/kCYRcS6xe9FcLxYKzXWO
vI7VebGGA3OUmbqWMPoIR2epT3KLRi2pEA==
-----END EC PRIVATE KEY-----
`,
			data:    "data",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecryptWithRSA([]byte(tt.privKey), []byte(tt.data))
			assert.Equal(t, tt.wantErr, err != nil)
		})
	}
}

func TestEncryptDecryptWithRSA(t *testing.T) {
	tests := []struct {
		name    string
		privKey string
		pubKey  string
		data    string
		wantErr bool
	}{
		{
			name: "private-key in PKCS #1 and public-key in PKCS #1",
			privKey: `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0cksFqSJhY7BLO4bhia2I19H88vtBCrwiHhcIXJg8OXpzMG1
VeJeyeIcpRMkmNE0g8WQF+u+Exj8f6cuAO+c7Fo0tMVrB+6Hp5eNjosHXTMw+ZmY
IDcalWBdSoJpsciVQxXrjK1KoHW2vcuJ+eQD1CU0aNXXafCWGd/XCcWbdEJoNcsp
WErhYQpj9zXWi3X+fU18L4cnidYn3QiHn5TjQhllnriEMcpUfl7/oJ4USJTVkORo
wO4Sb2l3SWngZ+MOiYBGBw8ckl+cQ7Ol6nP81egphKGsumA7ZojV6B2IQlI6Lt9K
D+lDjjORSDUHoJ1dB2tsCg8shZz7/v7aKLWtOQIDAQABAoIBAQCneK+Hi+Z1BldU
ZOj4GSNB7ahlCaC2uQi4CU2TLdoRtZkFaoY2f7Yn+Cfh5/xJOolvwGGdlwZv/Hxl
87IX8TEWxZRZ01f0RwloUuYgqwA/+MPaHjGBVjwUj48qEh4KXRQ7L96QuS5gFljB
/yCwqsQbsW+7WSrUWcmZ8kWaeXP2RDITD7QecSJ1W01kX7sq4B5KAVL1U5OHUVe/
Sc3k8Hi5Jb0Pg/37V7/IjYvF2a0rMo8urKEbrDiOZUTIGVxNS5dWjzjsv5w8CHua
ML0AWlpsSgKxFz+0exXgCcl+VkVplDwsFiCkJNNa+5yNNKJI2AAtlw/NvMCkt15g
LEd5hiKZAoGBAPohhUi2c7h+WkSwoK9Wkt0fj5ylBQ3aa4gWLLNUicRqPm4MJ0BF
U1HT68TD6uGbwl0evpTZk5dyD7Hx63YtVL6x9yPDY1ExN5xTY/vfBkPBo4Rp4eMQ
XUWmaklKahqcttbMHA6P89d1calzMCYzoTqHMUqQsuhkk8PbDDTWZRO/AoGBANa1
Tsb4xqBQr+68uirOE2aGgOjau9XaGaCgB2HgtqMO3KY4/PxUkCpeDTxGN/k8J1rl
HkOVZXqnZfz64qJypstLoz8JRggYc0SdoAEFHp3PtoN7rs37L2NXgV+qukUpZCBM
kNlVAlo30wEqM/wMClRnPI+L6ZufCN8WV3dOqp0HAoGAA4yqOYftSHbyjPr8rMBL
wTuLbCujULkCwaGe7MSMV+8yB5nAjNbvAcBCHj6xfJYbQfsHtVEJGSMTOfE26Cxo
gXRBD47cP/C021ELoC1gB2IeEej2vaQjzrM32uZlbw8+QPoQg9xjF3GhNUhfLIub
BBubBXXcNBQJTMQ0/iL0uD0CgYAzh8ZFaNW7CkJ/SNphhZ4QYD22JTEprTOzYlUD
P7x1vA5m8ox9PwpusK36hlvOvIoxfYXa8JMvcde/dLNKC7xOVHP0oBQnwz5+/Fm3
hPQJKh4Cxn94vk1sSUcqn74e9UUrn1SwZH+xCW7h+7AIURd1lGVrikfh6rRlXmZV
oxK9pwKBgAmbT3Y+mYO5UCdORBBeXjA+zmf+HIoEN8u6v9FkH4A9W+EYCl+Gj+PT
QtbkH8CTqeg6AO+RbMV9E6+dzteBdx2B9/aKa5PJ/3cvesCTkFoxJf245raYiLGt
6b+40vbfRS/GB0nbjLorSrXgnD7yG9qH/b8uBByYtOxU3osJwDh5
-----END RSA PRIVATE KEY-----
`,
			pubKey: `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA0cksFqSJhY7BLO4bhia2I19H88vtBCrwiHhcIXJg8OXpzMG1VeJe
yeIcpRMkmNE0g8WQF+u+Exj8f6cuAO+c7Fo0tMVrB+6Hp5eNjosHXTMw+ZmYIDca
lWBdSoJpsciVQxXrjK1KoHW2vcuJ+eQD1CU0aNXXafCWGd/XCcWbdEJoNcspWErh
YQpj9zXWi3X+fU18L4cnidYn3QiHn5TjQhllnriEMcpUfl7/oJ4USJTVkORowO4S
b2l3SWngZ+MOiYBGBw8ckl+cQ7Ol6nP81egphKGsumA7ZojV6B2IQlI6Lt9KD+lD
jjORSDUHoJ1dB2tsCg8shZz7/v7aKLWtOQIDAQAB
-----END RSA PUBLIC KEY-----
`,
			data:    "data",
			wantErr: false,
		},
		{
			name: "private-key in PKCS #1 and public-key in PKCS #8",
			privKey: `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0cksFqSJhY7BLO4bhia2I19H88vtBCrwiHhcIXJg8OXpzMG1
VeJeyeIcpRMkmNE0g8WQF+u+Exj8f6cuAO+c7Fo0tMVrB+6Hp5eNjosHXTMw+ZmY
IDcalWBdSoJpsciVQxXrjK1KoHW2vcuJ+eQD1CU0aNXXafCWGd/XCcWbdEJoNcsp
WErhYQpj9zXWi3X+fU18L4cnidYn3QiHn5TjQhllnriEMcpUfl7/oJ4USJTVkORo
wO4Sb2l3SWngZ+MOiYBGBw8ckl+cQ7Ol6nP81egphKGsumA7ZojV6B2IQlI6Lt9K
D+lDjjORSDUHoJ1dB2tsCg8shZz7/v7aKLWtOQIDAQABAoIBAQCneK+Hi+Z1BldU
ZOj4GSNB7ahlCaC2uQi4CU2TLdoRtZkFaoY2f7Yn+Cfh5/xJOolvwGGdlwZv/Hxl
87IX8TEWxZRZ01f0RwloUuYgqwA/+MPaHjGBVjwUj48qEh4KXRQ7L96QuS5gFljB
/yCwqsQbsW+7WSrUWcmZ8kWaeXP2RDITD7QecSJ1W01kX7sq4B5KAVL1U5OHUVe/
Sc3k8Hi5Jb0Pg/37V7/IjYvF2a0rMo8urKEbrDiOZUTIGVxNS5dWjzjsv5w8CHua
ML0AWlpsSgKxFz+0exXgCcl+VkVplDwsFiCkJNNa+5yNNKJI2AAtlw/NvMCkt15g
LEd5hiKZAoGBAPohhUi2c7h+WkSwoK9Wkt0fj5ylBQ3aa4gWLLNUicRqPm4MJ0BF
U1HT68TD6uGbwl0evpTZk5dyD7Hx63YtVL6x9yPDY1ExN5xTY/vfBkPBo4Rp4eMQ
XUWmaklKahqcttbMHA6P89d1calzMCYzoTqHMUqQsuhkk8PbDDTWZRO/AoGBANa1
Tsb4xqBQr+68uirOE2aGgOjau9XaGaCgB2HgtqMO3KY4/PxUkCpeDTxGN/k8J1rl
HkOVZXqnZfz64qJypstLoz8JRggYc0SdoAEFHp3PtoN7rs37L2NXgV+qukUpZCBM
kNlVAlo30wEqM/wMClRnPI+L6ZufCN8WV3dOqp0HAoGAA4yqOYftSHbyjPr8rMBL
wTuLbCujULkCwaGe7MSMV+8yB5nAjNbvAcBCHj6xfJYbQfsHtVEJGSMTOfE26Cxo
gXRBD47cP/C021ELoC1gB2IeEej2vaQjzrM32uZlbw8+QPoQg9xjF3GhNUhfLIub
BBubBXXcNBQJTMQ0/iL0uD0CgYAzh8ZFaNW7CkJ/SNphhZ4QYD22JTEprTOzYlUD
P7x1vA5m8ox9PwpusK36hlvOvIoxfYXa8JMvcde/dLNKC7xOVHP0oBQnwz5+/Fm3
hPQJKh4Cxn94vk1sSUcqn74e9UUrn1SwZH+xCW7h+7AIURd1lGVrikfh6rRlXmZV
oxK9pwKBgAmbT3Y+mYO5UCdORBBeXjA+zmf+HIoEN8u6v9FkH4A9W+EYCl+Gj+PT
QtbkH8CTqeg6AO+RbMV9E6+dzteBdx2B9/aKa5PJ/3cvesCTkFoxJf245raYiLGt
6b+40vbfRS/GB0nbjLorSrXgnD7yG9qH/b8uBByYtOxU3osJwDh5
-----END RSA PRIVATE KEY-----
`,
			pubKey: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0cksFqSJhY7BLO4bhia2
I19H88vtBCrwiHhcIXJg8OXpzMG1VeJeyeIcpRMkmNE0g8WQF+u+Exj8f6cuAO+c
7Fo0tMVrB+6Hp5eNjosHXTMw+ZmYIDcalWBdSoJpsciVQxXrjK1KoHW2vcuJ+eQD
1CU0aNXXafCWGd/XCcWbdEJoNcspWErhYQpj9zXWi3X+fU18L4cnidYn3QiHn5Tj
QhllnriEMcpUfl7/oJ4USJTVkORowO4Sb2l3SWngZ+MOiYBGBw8ckl+cQ7Ol6nP8
1egphKGsumA7ZojV6B2IQlI6Lt9KD+lDjjORSDUHoJ1dB2tsCg8shZz7/v7aKLWt
OQIDAQAB
-----END PUBLIC KEY-----
`,
			data:    "data",
			wantErr: false,
		},
		{
			name: "private-key in PKCS #8 and public-key in PKCS #8",
			privKey: `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDAUBKXpm1+TsAB
lvcJSQnSbtJGp7D/R1HtBqA74PV5cZXUVwAHSEo9jN6ImV/lvPPlB9L2zoppJXaH
Xatre2OYvXPR/pyWggCcFkOZ+89neXdOBBDOIIGInZjL+0wmLU3l3zE/xmZJyF+Y
LFcxgIBJMM2n6yQMXO/kwB4//560RDdhfyc+O39X109pv5d+0VKC1g4MosF2JALI
XeTXoa7IWXvJYTi3IdYyxsYPtzeqyrDpmxW+Wi4y2xpYj0axQZmaKsKRUvdMXaC/
+YjvPceZYDEwrfOWW9IiN9nOKWC0fckoqwJYOes6n/7XeeJDGlFZ7RnOf08c/lax
7/H98V5DAgMBAAECggEAQN2BN+dpvRWgy6h40IfzKSg6ApzjJWeP6Yu3lhrNkVXP
fJyPpOUsLVCLarWY0+uEtDaMYLTPmKGLNiNRA2LN+CHGpAjmFhnpTLxxtslpbnRY
2laiuHPcXRETDZJIYAQd5y/9843eyHouTCyAiHDYVFeCtmWodgcO3zAxw9JbXF+k
N0wdtEnecX3qSsw8bQ2a44GvTrKdE3iDR5aTzKIGC5+tcuWanESZBchA2k/xtsMD
i/m6updEmhLT4sSLNPNew8gkZEG1GK5anYItXL07UJIz5YAh2WhmdB+/kux3QZnz
RnztEXSA8OibMaOCX8A5WJ623UCv61XmPmIFYfGnkQKBgQDjt9ea2trSD4LFBl7s
O+wqlYAkiF1fqCyH3xy8Lemjo6dObpCqo+VQrCJE1jfkBUSwBWsRSpecAMC3z0ZI
dPYhv51bA5nKO/WEYeBATUgQY1YXgsmDhHqFhq7hazlHWsn05E0gd/iGmOB2wOya
Dh3YloiJ5wW53aPELw/GvmlkaQKBgQDYMooEP29Uf2rWMJOrZZ1pareooo52GvB8
78m0/RTniRt1w8AUrwLhDvjUt7vNinwZG4fIRewQWy0crBfJDKe0CfRwgEy6A1aG
/BQtjpnXngUjYEaJgdrQwNjTS8ltfHpjbWtbNOgWMy1amEB/0Pz39c36q6/ckEXh
u/SuiCTnywKBgF9C0Rce5ttpUbNKbvs0Nh+6WtjtkuIpYDeWxlaSfmLOW3ccGbjI
x21wFQXm94qUCZ/5JEkfgzzns7cxJp25EB4eIp2oa/WGD7dJmp5LthHk/Gbpd5Nl
IDwrk40JZfTLriCcQQeMKJNl8MC9BD2OGj44+vV1h5exeIjhhyAFF+HBAoGASBzz
dF9EX0bw9+jUGMOYMeVqxVETe8mYldPV0AzqwCA3jJxyoXOO3ksELM/sUK70ndtU
+zR3fS0savfsJx+VgLQhWLUy4ojif7vtbxS1s/n9dMNUQ+GQfzkUGcaZtW9j025X
9OA82crQQfuu5/NprbvLrOU/j65/4L+06dJ3nOkCgYEAiEWLiPu6hXkRzEzI5ah+
C2BLVgmpL0CirpJ6iUrigifaqgUp6XXg4Yh+VrqqYmvBFyREPmbQDasRU8QaJ5LK
2xaxCdaIYkHdo6AJohbrz4bcJzNOTLGh2b+Eqi2+32Dit3aCH9w8kZpkjeAmTkG4
VFasALp7T9NXrczz59GeRuM=
-----END PRIVATE KEY-----
`,
			pubKey: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwFASl6Ztfk7AAZb3CUkJ
0m7SRqew/0dR7QagO+D1eXGV1FcAB0hKPYzeiJlf5bzz5QfS9s6KaSV2h12ra3tj
mL1z0f6cloIAnBZDmfvPZ3l3TgQQziCBiJ2Yy/tMJi1N5d8xP8ZmSchfmCxXMYCA
STDNp+skDFzv5MAeP/+etEQ3YX8nPjt/V9dPab+XftFSgtYODKLBdiQCyF3k16Gu
yFl7yWE4tyHWMsbGD7c3qsqw6ZsVvlouMtsaWI9GsUGZmirCkVL3TF2gv/mI7z3H
mWAxMK3zllvSIjfZzilgtH3JKKsCWDnrOp/+13niQxpRWe0Zzn9PHP5Wse/x/fFe
QwIDAQAB
-----END PUBLIC KEY-----
`,
			data:    "data",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := EncryptWithRSA([]byte(tt.pubKey), []byte(tt.data))
			assert.NoError(t, err)
			_, err = DecryptWithRSA([]byte(tt.privKey), encrypted)
			assert.Equal(t, tt.wantErr, err != nil)
		})
	}
}
