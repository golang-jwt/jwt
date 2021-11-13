package keyfunc_test

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/golang-jwt/jwt/v4/keyfunc"
)

const (

	// emptyJWKsJSON is a hard-coded empty JWKs in JSON format.
	emptyJWKsJSON = `{"keys":[]}`

	// jwksFilePath is the full path of th JWKs file on the test HTTP server.
	jwksFilePath = "/example_jwks.json"

	// jwksJSON is a hard-coded JWKs in JSON format.
	jwksJSON = `{"keys":[{"kid":"zXew0UJ1h6Q4CCcd_9wxMzvcp5cEBifH0KWrCz2Kyxc","kty":"RSA","alg":"PS256","use":"sig","n":"wqS81x6fItPUdh1OWCT8p3AuLYgFlpmg61WXp6sp1pVijoyF29GOSaD9xE-vLtegX-5h0BnP7va0bwsOAPdh6SdeVslEifNGHCtID0xNFqHNWcXSt4eLfQKAPFUq0TsEO-8P1QHRq6yeG8JAFaxakkaagLFuV8Vd_21PGJFWhvJodJLhX_-Ym9L8XUpIPps_mQriMUOWDe-5DWjHnDtfV7mgaOxbBvVo3wj8V2Lmo5Li4HabT4MEzeJ6e9IdFo2kj_44Yy9osX-PMPtu8BQz_onPgf0wjrVWt349Rj6OkS8RxlNGYeuIxYZr0TOhP5F-yEPhSXDsKdVTwPf7zAAaKQ","e":"AQAB","x5c":["MIICmzCCAYMCBgF4HR7HNDANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0ZXIwHhcNMjEwMzEwMTcwOTE5WhcNMzEwMzEwMTcxMDU5WjARMQ8wDQYDVQQDDAZtYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCpLzXHp8i09R2HU5YJPyncC4tiAWWmaDrVZenqynWlWKOjIXb0Y5JoP3ET68u16Bf7mHQGc/u9rRvCw4A92HpJ15WyUSJ80YcK0gPTE0Woc1ZxdK3h4t9AoA8VSrROwQ77w/VAdGrrJ4bwkAVrFqSRpqAsW5XxV3/bU8YkVaG8mh0kuFf/5ib0vxdSkg+mz+ZCuIxQ5YN77kNaMecO19XuaBo7FsG9WjfCPxXYuajkuLgdptPgwTN4np70h0WjaSP/jhjL2ixf48w+27wFDP+ic+B/TCOtVa3fj1GPo6RLxHGU0Zh64jFhmvRM6E/kX7IQ+FJcOwp1VPA9/vMABopAgMBAAEwDQYJKoZIhvcNAQELBQADggEBALILq1Z4oQNJZEUt24VZcvknsWtQtvPxl3JNcBQgDR5/IMgl5VndRZ9OT56KUqrR5xRsWiCvh5Lgv4fUEzAAo9ToiPLub1SKP063zWrvfgi3YZ19bty0iXFm7l2cpQ3ejFV7WpcdLJE0lapFdPLo6QaRdgNu/1p4vbYg7zSK1fQ0OY5b3ajhAx/bhWlrN685owRbO5/r4rUOa6oo9l4Qn7jUxKUx4rcoe7zUM7qrpOPqKvn0DBp3n1/+9pOZXCjIfZGvYwP5NhzBDCkRzaXcJHlOqWzMBzyovVrzVmUilBcj+EsTYJs0gVXKzduX5zO6YWhFs23lu7AijdkxTY65YM0="],"x5t":"IYIeevIT57t8ppUejM42Bqx6f3I","x5t#S256":"TuOrBy2NcTlFSWuZ8Kh8W8AjQagb4fnfP1SlKMO8-So"},{"kid":"ebJxnm9B3QDBljB5XJWEu72qx6BawDaMAhwz4aKPkQ0","kty":"EC","alg":"ES512","use":"sig","crv":"P-521","x":"YQ95Xj8MTzcHytbU1h8YkCN2kdEQA7ThuZ1ctB9Ekiw6tlM9RwL62eQvzEt4Rz8qN69uRqgU9RzxQOkSU5xVvyo","y":"SMMuP3QnAPHtx7Go2ARsG3NBaySWBLmVvS8s2Ss7Vm_ISWenNbdjKOsY1XvtiQz5scGzWDCEUoZzgV8Ve1mLOV0"},{"kid":"TVAAet63O3xy_KK6_bxVIu7Ra3_z1wlB543Fbwi5VaU","kty":"EC","alg":"ES384","use":"sig","crv":"P-384","x":"Pik2o5as-evijFABH5p6YLXHnWw8iQ_N1ummPY1c_UgG6NO0za-gNOhTz2-tsd_w","y":"e98VSff71k19SY_mHgp3707lgQVrhfVpiGa-sGaKxOWVpxd2jWMhB0Q4RpSRuCp5"},{"kid":"arlUxX4hh56rNO-XdIPhDT7bqBMqcBwNQuP_TnZJNGs","kty":"RSA","alg":"RS512","use":"sig","n":"hhtifu8LL3ICE3BAX5l1KZv6Lni0lhlhBusSfepnpxcb4C_z2U71cQTnLY27kt8WB4bNG6e5_KMx9K3xUdd3euj9MCq8vytwEPieeHE1KXQuhJfLv017lhpK_dRMOHyc-9-50YNdgs_8KWRkrzjjuYrCiO9Iu76n5319e-SC8OPvNUglqxp2N0Sp2ltne2ZrpN8T3OEEXT62TSGmLAVopRGw5gllNVrJfmEyZJCRrBM6s5CQcz8un0FjkAAC4DI6QD-eBL0qG3_NR0hQvR1he2o4BLwjOKH45Pk_jj-eArp-DD6Xq6ABQVb5SNOSdaxl5lnmuotRoY3G5d9YSl-K3w","e":"AQAB","x5c":["MIICmzCCAYMCBgF4HSCcDzANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0ZXIwHhcNMjEwMzEwMTcxMTE5WhcNMzEwMzEwMTcxMjU5WjARMQ8wDQYDVQQDDAZtYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCGG2J+7wsvcgITcEBfmXUpm/oueLSWGWEG6xJ96menFxvgL/PZTvVxBOctjbuS3xYHhs0bp7n8ozH0rfFR13d66P0wKry/K3AQ+J54cTUpdC6El8u/TXuWGkr91Ew4fJz737nRg12Cz/wpZGSvOOO5isKI70i7vqfnfX175ILw4+81SCWrGnY3RKnaW2d7Zmuk3xPc4QRdPrZNIaYsBWilEbDmCWU1Wsl+YTJkkJGsEzqzkJBzPy6fQWOQAALgMjpAP54EvSobf81HSFC9HWF7ajgEvCM4ofjk+T+OP54Cun4MPperoAFBVvlI05J1rGXmWea6i1Ghjcbl31hKX4rfAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAB7bpwPoL02WGCCVhCsbDkq9GeFUwF01opVyFTijZlTUoTf5RcaR2qAH9/irkLjZeFeyozzC5mGvIVruBwnx/6l4PcAMxKK4YiheFVoO/dytpGMCj6ToNmKpjlXzOLAHelieWIUDtAFSYzENjIO01PyXTGYpxebpQCocJBvppj5HqARS9iNPcqBltMhxWrWmMu81tOG3Y7yd2xsIYXk6KjaoefLeN8Was4BPJ0zR6tTSEm6ZOvSRvlppqh84kz7LmWem7gGHAsY2G3tWBUmOdO/SMNMThqV62yLf7sKsuoE1w06lfmrf6D2zGwoEyz+TT6fdSkc34Yeh7+c01X6nFWU="],"x5t":"geiCPGtT_10T8xGLUK1LA0_YQEE","x5t#S256":"dLp3_QNGwMbYll5VecnR8Q9NSeFVfqJPBTa2_8qf48I"},{"kid":"tW6ae7TomE6_2jooM-sf9N_6lWg7HNtaQXrDsElBzM4","kty":"RSA","alg":"PS512","use":"sig","n":"p32N7jqKfMUB6_dKY1uZ3wizzPlBAXg9XrntfUcwNLRPfTBnshpt4uQBf3T8fexkbzhtR18oHvim-YvcWfC5eLGQmWHYiVwACa_C7oGqx51ijK2LRbUg4TKhnZX2X3Ld9xvr3HsosKh2UXn_Ay8nuvdfH-U6S7btT6a-AIFlt3BpqZP0EOl7rY-ie8nXoA13xX6BoyzYiNcugdYCU6czQcmTIJ1JLS0zohi4aTNehRt-1VMRpIMx7q7Ouq3Zhbi7RcDo-_D8FPRhWc2eEKd-h8ebFTIxEOrkguBIomjEFTf3SfYbOB_h-14v9Q2yz-NzyId3-ujRCQGC0hn-cixe2w","e":"AQAB","x5c":["MIICmzCCAYMCBgF4BKAxqzANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0ZXIwHhcNMjEwMzA1MjMwMDEwWhcNMzEwMzA1MjMwMTUwWjARMQ8wDQYDVQQDDAZtYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCnfY3uOop8xQHr90pjW5nfCLPM+UEBeD1eue19RzA0tE99MGeyGm3i5AF/dPx97GRvOG1HXyge+Kb5i9xZ8Ll4sZCZYdiJXAAJr8LugarHnWKMrYtFtSDhMqGdlfZfct33G+vceyiwqHZRef8DLye6918f5TpLtu1Ppr4AgWW3cGmpk/QQ6Xutj6J7ydegDXfFfoGjLNiI1y6B1gJTpzNByZMgnUktLTOiGLhpM16FG37VUxGkgzHurs66rdmFuLtFwOj78PwU9GFZzZ4Qp36Hx5sVMjEQ6uSC4EiiaMQVN/dJ9hs4H+H7Xi/1DbLP43PIh3f66NEJAYLSGf5yLF7bAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAHVWNBTExqlg4LTcyhUXI5U0iNPcMIVdKDoGPDc3EPjXyYNyjURX0oZ6b1Wv5t+XGmpZRqJNYb92xraQatIzLEsRn4IrmzViP+dIyFU8BEDubixTxeqx7LSw2j6LIFnZ05XdmWknlksNTlqi4CT6KL+1c24+QU3CcmU3mkQEIPA2yC4SdAB1oXI0jh49uP6a+JrE7JREZGAdwbIpZ1cqV6acPiJW3tOYfLrHwo7KYn3KwJvIBHXgFBNwx7fl2gYNQ0VEGKub3qVwW5RO5R/6Tcla9uZEfEiamms/Pn4hFA1qbsNHtA9IRGVRSmVeBKDxRvo0fxOUXp+NuZxEnhsoP3I="],"x5t":"f1l1fxICz1fe9mI-sSrtc19EDhU","x5t#S256":"NUJWRA4ADpLEg_SMkSoE4FKQN0H1Tlz85L-i7puVcqQ"},{"kid":"Lx1FmayP2YBtxaqS1SKJRJGiXRKnw2ov5WmYIMG-BLE","kty":"RSA","alg":"PS384","use":"sig","n":"q7WM4SnrdzlFSo_A1DRhc-8Ho-pBsfs49kGRbw3O_OKFIUyZrzHaRuovW_QaEAyiO3HX8CNcGPcpHdmpl4DhTGEBLcd6xXtCaa65ct00Mq7ZHCRRCrKLh6lJ0rY9fP8vCV0RBigpkNoRfrqLQQN4VeVFTbGSrDaS0LzPbap0-q5FKXUR-OQmQEtOupXhKFQtbB73tL83YnG6Swl7nXsx54ulEoDzcCCYt7pjCVVp7L9fzI2_ucTdtQclAJVQZGKpsx7vabOJuiMUwuAIz56lOJyXRMePsW8UogwC4FA2A52STsYlhOPsDEW4iIExFVNqs-CGoDGhYLIavaCkZhXM0w","e":"AQAB","x5c":["MIICmzCCAYMCBgF4HR+9XjANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0ZXIwHhcNMjEwMzEwMTcxMDIyWhcNMzEwMzEwMTcxMjAyWjARMQ8wDQYDVQQDDAZtYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCrtYzhKet3OUVKj8DUNGFz7wej6kGx+zj2QZFvDc784oUhTJmvMdpG6i9b9BoQDKI7cdfwI1wY9ykd2amXgOFMYQEtx3rFe0Jprrly3TQyrtkcJFEKsouHqUnStj18/y8JXREGKCmQ2hF+uotBA3hV5UVNsZKsNpLQvM9tqnT6rkUpdRH45CZAS066leEoVC1sHve0vzdicbpLCXudezHni6USgPNwIJi3umMJVWnsv1/Mjb+5xN21ByUAlVBkYqmzHu9ps4m6IxTC4AjPnqU4nJdEx4+xbxSiDALgUDYDnZJOxiWE4+wMRbiIgTEVU2qz4IagMaFgshq9oKRmFczTAgMBAAEwDQYJKoZIhvcNAQELBQADggEBADTgP3SrcG3p9XUB7sM4a2IeY0J4bSEtqlZBuHgdgekYJ5DXETJ3hV/82GjitU50NBup0IJyI9KZ0KCwqHIKC2Jn/6biOpM9Ipk4BtNVzx3qKNsDac9qZmyMpm4V9QuWakajknerhwyynG3siGUntbPmLvf5UKvKtbiKlWS4dBPwfedIUnC85mYEnNKSzSI1NiM6TWHB9zQYkARXlb89sh0HBYs08BfRMyBVM+l3OczIyGeQAfhcL+pxPP/0jqPr1ctHUBj2zXkjZxDw1oJFgeD9GDtPcjc3spB20vsRtQUBlzbJElbGflqWGHJK5l5n7gNd3ZXZT0HJ+wUpPE8EUaM="],"x5t":"fjRYR1986VCLzbaZaw5r25UKahw","x5t#S256":"ZHNHpizlsjD3qSZh7gJQQBu8W9jBL2HR0y7-3u2Wb-g"},{"kid":"gnmAfvmlsi3kKH3VlM1AJ85P2hekQ8ON_XvJqs3xPD8","kty":"RSA","alg":"RS384","use":"sig","n":"qUNQewKl3APQcbpACMNJ2XphPpupt395z6OZvj5CW9tiRXY3J7dqi8U0bWoIhtmmc7Js6hjp-A5W_FVStuXlT1hLyjJsHeu9ZVPnfIl2MnYN83zQBKw8E4mFsVv0UXNvkVPBF_k0yXrz-ABleWLOgFGnkNU9csc3Z5aihHcwRmC_oS7PZ9Vc-l0xBCyF3YRHI-al8ppSHwFreOweF3-JP3poNAXd906_tjX2KlHSJmNqcUNiSfEluyCp02ALlRFKXUQ1HlfSupHcHySDlanfUyIzZgM9ysCvC1vfNdAuwZ44oUBMul_XPxxhzlewL2Y8PtSDLUDWGTIou8M8049D8Q","e":"AQAB","x5c":["MIICmzCCAYMCBgF4BJVfaDANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0ZXIwHhcNMjEwMzA1MjI0ODIxWhcNMzEwMzA1MjI1MDAxWjARMQ8wDQYDVQQDDAZtYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCpQ1B7AqXcA9BxukAIw0nZemE+m6m3f3nPo5m+PkJb22JFdjcnt2qLxTRtagiG2aZzsmzqGOn4Dlb8VVK25eVPWEvKMmwd671lU+d8iXYydg3zfNAErDwTiYWxW/RRc2+RU8EX+TTJevP4AGV5Ys6AUaeQ1T1yxzdnlqKEdzBGYL+hLs9n1Vz6XTEELIXdhEcj5qXymlIfAWt47B4Xf4k/emg0Bd33Tr+2NfYqUdImY2pxQ2JJ8SW7IKnTYAuVEUpdRDUeV9K6kdwfJIOVqd9TIjNmAz3KwK8LW9810C7BnjihQEy6X9c/HGHOV7AvZjw+1IMtQNYZMii7wzzTj0PxAgMBAAEwDQYJKoZIhvcNAQELBQADggEBABoThxhMd7Xiq4x0GJeoJFv2yDKXCL3dJEAEWtOr2+PqdeJl/ZfOxBXynIvrdtYnQdICztN5ydEgDsZ02piDsxZ+s/0SA0iqjw/MEoBYobmr8V+xwUv+WtRLpTBXqWGMuG7NEtrbjKid0iKLLAOAU4dcHQ49iOF9VLnbTkf1EXp4iphJreaubOXMwT6/JDzQPT1dRR34hlhYeKKzMSA0Cz5aYL1tI+eH12rar0MDczXykLChNS/8MlyTzreEf0siUiS9S1kj/lOZKQDg9E/z8fm5vmHEHzAVwf4ON5iO29tDsqLw7BeJqC4AESjliXIqMrdpFynfPnIsGgf3dnph5BM="],"x5t":"CmRnQVduZWtEsdOC4mauUUsSWxA","x5t#S256":"BvC0LmuM8ZIApN3TQQZWWbGO-d082Ah5d3D6vPvahGw"},{"kid":"CGt0ZWS4Lc5faiKSdi0tU0fjCAdvGROQRGU9iR7tV0A","kty":"EC","alg":"ES256","use":"sig","crv":"P-256","x":"DPW7n9yjfE6Rt-VvVmEdeu4QdW44qifocAPPDxACDDY","y":"-ejsVw8222-hg2dJWx3QV0hE4-I0Ujp7ZsWebE68JE0"},{"kid":"C65q0EKQyhpd1m4fr7SKO2He_nAxgCtAdws64d2BLt8","kty":"RSA","alg":"RS256","use":"sig","n":"ja99ybDrLvw11Z4CvNlDI-kkqJEBpSnvDf0pZF2DvBlvYmeVYL_ChqIe8E9GyHUmLMdtO_jifSgOqE5b8vILwi1kZnJR7N857uEnbWM9YTeevi_RZ-E_hr4frW2NKJ78YGvCzwLKG2GgtSjj0zuTLnSaK8fCGzqXgy6paXNhgHUSZgGwvO0YItpMlyJeqEj1wGTWz1IyA1sguF1cC7K0fojPbPoBwrhvaAeoGRPLraE0rrBsQv8iiLwnRBIez9B1j0NiUG8Iad953Y7UzaKOAw8crIEK45NIK_yxHUpxqcHLjPIcRyIyJGioRyGK7cp-_7iPLOCutQc-u46mom1_ZQ","e":"AQAB","x5c":["MIICmzCCAYMCBgF4BJRpbzANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0ZXIwHhcNMjEwMzA1MjI0NzE4WhcNMzEwMzA1MjI0ODU4WjARMQ8wDQYDVQQDDAZtYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCNr33JsOsu/DXVngK82UMj6SSokQGlKe8N/SlkXYO8GW9iZ5Vgv8KGoh7wT0bIdSYsx207+OJ9KA6oTlvy8gvCLWRmclHs3znu4SdtYz1hN56+L9Fn4T+Gvh+tbY0onvxga8LPAsobYaC1KOPTO5MudJorx8IbOpeDLqlpc2GAdRJmAbC87Rgi2kyXIl6oSPXAZNbPUjIDWyC4XVwLsrR+iM9s+gHCuG9oB6gZE8utoTSusGxC/yKIvCdEEh7P0HWPQ2JQbwhp33ndjtTNoo4DDxysgQrjk0gr/LEdSnGpwcuM8hxHIjIkaKhHIYrtyn7/uI8s4K61Bz67jqaibX9lAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAHrGJFhVNiQupIwkn2jiW/jBobm9CHUxOwQL5E7WdRz5uaOJ0v62PrynOQE9xim9Qk8bT3q7DThZs66U9bpIk3msKVRgXRfn5FZy1H5RKOlEEFZhGakPqSlC1yPbhUNhHXMs3GTzdGMLtYaGvSy6XM/8/zqVqVwgh6BpbAR9RfiSdyaiNTSBriu+n/tHW934G9J8UIzdfpVcb0Yt9y4o0UgIXt64NtGFq7zmNJijH88AxBZFB6eUUmQQCczebzoAjyYbVOes5gGFzboVWcyLe3iyD0vvsAVHJViXeiGoxhpKnc8ryISpRUBzsKngf5uZo3bnrD9PHLYBoGOHgzII1xw="],"x5t":"5GNr3LeRXHWI4YR8-QTSsF98oTI","x5t#S256":"Dgd0_wZZqvRuf4GEISPNHREX-1ixTMIsrPeGzk0bCxs"}]}`
)

// TestInvalidServer performs initialization + refresh initialization with a server providing invalid data.
// The test ensures that background refresh goroutine does not cause any trouble in case of init failure.
func TestInvalidServer(t *testing.T) {

	// Create the HTTP test server.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write(nil); err != nil {
			t.Errorf("Failed to write empty response.\nError: %s", err.Error())
			t.FailNow()
		}
	}))
	defer server.Close()

	// Create testing options.
	testingRefreshErrorHandler := func(err error) {
		t.Errorf("Unhandled JWKs error: %s", err.Error())
		t.FailNow()
	}

	// Set the options to refresh KID when unknown.
	refreshInterval := time.Second
	options := keyfunc.Options{
		RefreshInterval:     refreshInterval,
		RefreshErrorHandler: testingRefreshErrorHandler,
	}

	// Create the JWKs.
	if _, err := keyfunc.Get(server.URL, options); err == nil {
		t.Errorf("Creation of *keyfunc.JWKs with invalid server must fail.")
		t.FailNow()
	}
}

// TestJWKs performs a table test on the JWKs code.
func TestJWKs(t *testing.T) {

	// Create a temporary directory to serve the JWKs from.
	tempDir, err := ioutil.TempDir("", "*")
	if err != nil {
		t.Errorf("Failed to create a temporary directory.\nError: %s", err.Error())
		t.FailNow()
	}
	defer func() {
		if err = os.RemoveAll(tempDir); err != nil {
			t.Errorf("Failed to remove temporary directory.\nError: %s", err.Error())
			t.FailNow()
		}
	}()

	// Create the JWKs file path.
	jwksFile := filepath.Join(tempDir, jwksFilePath)

	// Write the empty JWKs.
	if err = ioutil.WriteFile(jwksFile, []byte(jwksJSON), 0600); err != nil {
		t.Errorf("Failed to write JWKs file to temporary directory.\nError: %s", err.Error())
		t.FailNow()
	}

	// Create the HTTP test server.
	server := httptest.NewServer(http.FileServer(http.Dir(tempDir)))
	defer server.Close()

	// Create testing options.
	testingRefreshInterval := time.Second
	testingRateLimit := time.Millisecond * 500
	testingRefreshTimeout := time.Second
	testingRefreshErrorHandler := func(err error) {
		panic(fmt.Sprintf("Unhandled JWKs error: %s", err.Error()))
	}

	// Set the JWKs URL.
	jwksURL := server.URL + jwksFilePath

	// Create a table of options to test.
	options := []keyfunc.Options{
		{}, // Default options.
		{
			Client: http.DefaultClient, // Should be ineffectual. Just for code coverage.
		},
		{
			Ctx: context.Background(), // Should be ineffectual. Just for code coverage.
		},
		{
			RefreshErrorHandler: testingRefreshErrorHandler,
		},
		{
			RefreshInterval: testingRefreshInterval,
		},
		{
			RefreshRateLimit: testingRateLimit,
		},
		{
			RefreshTimeout: testingRefreshTimeout,
		},
	}

	// Iterate through all options.
	for _, opts := range options {

		// Create the JWKs from the resource at the testing URL.
		jwks, err := keyfunc.Get(jwksURL, opts)
		if err != nil {
			t.Errorf("Failed to get JWKs from testing URL.\nError: %s", err.Error())
			t.FailNow()
		}

		// Create the test cases.
		testCases := []struct {
			token string
		}{
			{""}, // Empty JWT.
			{"eyJhbGciOiJFUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJDR3QwWldTNExjNWZhaUtTZGkwdFUwZmpDQWR2R1JPUVJHVTlpUjd0VjBBIn0.eyJleHAiOjE2MTU0MDY4NjEsImlhdCI6MTYxNTQwNjgwMSwianRpIjoiYWVmOWQ5YjItN2EyYy00ZmQ4LTk4MzktODRiMzQ0Y2VmYzZhIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.iQ77QGoPDNjR2oWLu3zT851mswP8J-h_nrGhs3fpa_tFB3FT1deKPGkjef9JOTYFI-CIVxdCFtW3KODOaw9Nrw"},                                                                                                                                                                                                                                                                 // Signing algorithm ES256.
			{"eyJhbGciOiJFUzM4NCIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJUVkFBZXQ2M08zeHlfS0s2X2J4Vkl1N1JhM196MXdsQjU0M0Zid2k1VmFVIn0.eyJleHAiOjE2MTU0MDY4OTAsImlhdCI6MTYxNTQwNjgzMCwianRpIjoiYWNhNDU4NTItZTE0ZS00MjgxLTljZTQtN2ZiNzVkMTg1MWJmIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.oHFT-RvbNNT6p4_tIoZzr4IS88bZqy20cJhF6FZCIXALZ2dppoOjutanPVxzuLC5axG3P71noVghNUF8X44bTShP1boLrlde2QKmj5GxDR-oNEb9ES_zC10rZ5I76CwR"},                                                                                                                                                                                                                       // Signing algorithm ES384.
			{"eyJhbGciOiJFUzUxMiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJlYkp4bm05QjNRREJsakI1WEpXRXU3MnF4NkJhd0RhTUFod3o0YUtQa1EwIn0.eyJleHAiOjE2MTU0MDY5MDksImlhdCI6MTYxNTQwNjg0OSwianRpIjoiMjBhMGI1MTMtN2E4My00OGQ2LThmNDgtZmQ3NDc1N2Y4OWRiIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.AdR59BCvGlctL5BMgXlpJBBToKTPG4SVa-oJKBqE7qxvTSBwAQM5D3uUc2toM3NAUERSMKOLTJfzfxenNRixrDMnAcrdFHgEY10vsDp6uqA7NMUevHE5f7jiAVK1talXS9O41IEnR2DKbAG0GgjIA2WHLhUgftG2uNN8LMKI2QSbLCfM"},                                                                                                                                                                       // Signing algorithm ES512.
			{"eyJhbGciOiJFUzUxMiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJlYkp4bm05QjNRREJsakI1WEpXRXU3MnF4NkJhd0RhTUFod3o0YUtQa1EwIn0.eyJleHAiOjE2MTU0MDY5MDksImlhdCI6MTYxNTQwNjg0OSwianRpIjoiMjBhMGI1MTMtN2E4My00OGQ2LThmNDgtZmQ3NDc1N2Y4OWRiIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.AdR59BCvGlctL5BMgXlpJBBToKTPG4SVa-oJKBqE7qxvTSBwAQM5D3uUc2toM3NAUERSMKOLTJfzfxenNRixrDMnAcrdFHgEY10vsDp6uqA7NMUevHE5f7jiAVK1talXS9O41IEnR2DKbAG0GgjIA2WHLhUgftG2uNN8LMKI2QSbLCfM"},                                                                                                                                                                       // ECDSA precomputed.
			{"eyJhbGciOiJQUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ6WGV3MFVKMWg2UTRDQ2NkXzl3eE16dmNwNWNFQmlmSDBLV3JDejJLeXhjIn0.eyJleHAiOjE2MTU0MDY5NjIsImlhdCI6MTYxNTQwNjkwMiwianRpIjoiNWIyZGY5N2EtNDQyOS00ZTA0LWFkMzgtOWZmNjVlZDU2MTZjIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.tafkUwLXm3lyyqJHwAGwFPN3IO0rCrESJnVcIuI1KHPSKogn5DgWqR3B9QCvqIusqlxhGW7MvOhG-9dIy62ciKGQFDRFA9T46TMm9t8O80TnhYTB8ImX90xYuf6E74k1RiqRVcubFWKHWlhKjqXMM4dD2l8VwqL45E6kHpNDvzvILKAfrMgm0vHsfi6v5rf32HLp6Ox1PvpKrM1kDgsdXm6scgAGJCTbOQB2Pzc-i8cyFPeuckbeL4zbM3-Odqc-eI-3pXevMzUB608J3fRpQK1W053kU7iG9RFC-5nBwvrBlN4Lff_X1R3JBLkFcA0wJeFYtIFnMm6lVbA7nwa0Xg"}, // Signing algorithm PS256.
			{"eyJhbGciOiJQUzM4NCIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJMeDFGbWF5UDJZQnR4YXFTMVNLSlJKR2lYUktudzJvdjVXbVlJTUctQkxFIn0.eyJleHAiOjE2MTU0MDY5ODIsImlhdCI6MTYxNTQwNjkyMiwianRpIjoiMGY2NGJjYTktYjU4OC00MWFhLWFkNDEtMmFmZDM2OGRmNTFkIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.Rxrq41AxbWKIQHWv-Tkb7rqwel3sKT_R_AGvn9mPIHqhw1m7nsQWcL9t2a_8MI2hCwgWtYdgTF1xxBNmb2IW3CZkML5nGfcRrFvNaBHd3UQEqbFKZgnIX29h5VoxekyiwFaGD-0RXL83jF7k39hytEzTatwoVjZ-frga0KFl-nLce3OwncRXVCGmxoFzUsyu9TQFS2Mm_p0AMX1y1MAX1JmLC3WFhH3BohhRqpzBtjSfs_f46nE1-HKjqZ1ERrAc2fmiVJjmG7sT702JRuuzrgUpHlMy2juBG4DkVcMlj4neJUmCD1vZyZBRggfaIxNkwUhHtmS2Cp9tOcwNu47tSg"}, // Signing algorithm PS384.
			{"eyJhbGciOiJQUzUxMiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ0VzZhZTdUb21FNl8yam9vTS1zZjlOXzZsV2c3SE50YVFYckRzRWxCek00In0.eyJleHAiOjE2MTU0MDcwMDUsImlhdCI6MTYxNTQwNjk0NSwianRpIjoiYzJmMmZiMjQtOTQ1Yi00YTA4LWE3ZTQtYTZhNzRlZTIwMDFiIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.d5E6m_isNWy0Y5E-udUruMbThe3NHMb7x90rzOxlrEyyhZEqjuREP97KQXIospLY41TKj3VURJbRFebg-my4R8w1-OlaciDdoWND2juk8y_vIMlgYb9lLMnS1ZI5Ayq3OQ4Bh2TXLsZwQaBWoccyVSD1qCgZsCH-ZIbxJmefkM6k99fA8QWwNFL-bD1kHELBdZfk-26JSRWiA_0WocQZcC5DWsmbslwICo2yT59X4ancvxNA-mns0Wt41-sj9sAAr-qOAubGjpPC8-FqVZXeDTiuaAqQA2K3MRKMwHMZY6e-duwCltGll_kZf2jUlwfF7LLuT7YP6p7rxCjIhHaAMw"}, // Signing algorithm PS512.
			{"eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJDNjVxMEVLUXlocGQxbTRmcjdTS08ySGVfbkF4Z0N0QWR3czY0ZDJCTHQ4In0.eyJleHAiOjE2MTU0MDcwMjYsImlhdCI6MTYxNTQwNjk2NiwianRpIjoiMzg1NjE4ODItOTA5MS00ODY3LTkzYmYtMmE3YmU4NTc3YmZiIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.Cmgz3aC_b_kpOmGM-_nRisgQul0d9Jg7BpMLe5F_fdryRhwhW5fQBZtz6FipQ0Tc4jggI6L3Dx1jS2kn823aWCR0x-OAFCawIXnwgAKuM1m2NL7Y6LKC07nytdB_qU4GknAl3jEG-tZIJBHQwYP-K6QKmAT9CdF1ZPbc9u8RgRCPN8UziYcOpvStiG829BO7cTzCt7tp5dJhem8_CnRWBKzelP1fs_z4fAQtW2sgyhX9SUYb5WON-4zrn4i01FlYUwZV-AC83zP6BuHIiy3XpAuTiTp2BjZ-1nzCLWBRpIm_lOObFeo-3AQqWPxzLVAmTFQMKReUF9T8ehL2Osr1XQ"}, // Signing algorithm RS256.
			{"eyJhbGciOiJSUzM4NCIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJnbm1BZnZtbHNpM2tLSDNWbE0xQUo4NVAyaGVrUThPTl9YdkpxczN4UEQ4In0.eyJleHAiOjE2MTU0MDcwNDUsImlhdCI6MTYxNTQwNjk4NSwianRpIjoiYzJiZGRhNGItMWNjNy00MzhmLWI1YzktMDk2ZDk4MTg4YWQ4IiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.F-y1IULtpWICLu0lrTniJwf3x1wHSQvVJ2BmXhRm-bhEdwftJG2Ep4rg4_SZPU8CZTazqSRQE4quWw5e8m8yyVrdpAts3NDAJB6m6Up1qQvN2YBtSoGjujzRZuJ72rOGqHf0e9wUQYWsmgE4Aes0kCeOlQ0EwfTnd6qfJaqYuZj9T0KIedt7T9KBmk3ndzDQALRJ2vo12b2M2DHL6gYqokUJ4lhw9Tnm785a6Bamc_F0otAKS5e4KVFhtRzCgdZWdEXX9VfwmtZpvZYImHWFe8HnB8jqLfRhKIc5xkXE0cwiuz6eYnneSRMrM3qAPus6fbc78rIVZl7Qaxa-h1vZYQ"}, // Signing algorithm RS384.
			{"eyJhbGciOiJSUzUxMiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJhcmxVeFg0aGg1NnJOTy1YZElQaERUN2JxQk1xY0J3TlF1UF9UblpKTkdzIn0.eyJleHAiOjE2MTU0MDcwNjcsImlhdCI6MTYxNTQwNzAwNywianRpIjoiYWNlNGQ5ODgtMjVjMS00NzkxLWJjZDgtNTQ3MzNiYTg0MTZiIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.BHygL0iGWEL46QdcnInqgjhgtlfBN8H2BMhFAK1sZuGB6rX-FGHFav0NgnWzT5Ae6wM3KqJY30aME5OOvycV--5w7ZX8uqnYjXYdLbJ-azLtP3Hw8vwY9u6GC81ZvWZdKvQNpbcuvtJYL2uhrbv0GdXcClTHmA-NiReGFuBFgo0fBX_ipjNx_q94OnaDxSHUSGeKqNFoNOttXBV7Xqa_K9j60zfoO9E2OV0jkYI5_8MPPZI85Y8XG7PUK2opg7LHNrFbB67C_RxJ7ZDKt0jBApzJyZ96_8UBSvNtBnytQO-CexOG-5y-nN3mcw7NU7g7dFxlb18Yur194h7VTT9tHQ"}, // Signing algorithm RS512.
			{"eyJhbGciOiJSUzUxMiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJhcmxVeFg0aGg1NnJOTy1YZElQaERUN2JxQk1xY0J3TlF1UF9UblpKTkdzIn0.eyJleHAiOjE2MTU0MDcwNjcsImlhdCI6MTYxNTQwNzAwNywianRpIjoiYWNlNGQ5ODgtMjVjMS00NzkxLWJjZDgtNTQ3MzNiYTg0MTZiIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.BHygL0iGWEL46QdcnInqgjhgtlfBN8H2BMhFAK1sZuGB6rX-FGHFav0NgnWzT5Ae6wM3KqJY30aME5OOvycV--5w7ZX8uqnYjXYdLbJ-azLtP3Hw8vwY9u6GC81ZvWZdKvQNpbcuvtJYL2uhrbv0GdXcClTHmA-NiReGFuBFgo0fBX_ipjNx_q94OnaDxSHUSGeKqNFoNOttXBV7Xqa_K9j60zfoO9E2OV0jkYI5_8MPPZI85Y8XG7PUK2opg7LHNrFbB67C_RxJ7ZDKt0jBApzJyZ96_8UBSvNtBnytQO-CexOG-5y-nN3mcw7NU7g7dFxlb18Yur194h7VTT9tHQ"}, // RSA precomputed.
		}

		// Wait for the interval to pass, if required.
		if opts.RefreshInterval != 0 {
			time.Sleep(opts.RefreshInterval)
		}

		// Iterate through the test cases.
		for _, tc := range testCases {
			t.Run(fmt.Sprintf("token: %s", tc.token), func(t *testing.T) {

				// Use the JWKs jwt.Keyfunc to parse the token.
				//
				// Don't check for general errors. Unfortunately, an error occurs when a token is expired. All hard
				// coded tokens are expired.
				if _, err = jwt.Parse(tc.token, jwks.Keyfunc); err != nil {
					if errors.Is(err, jwt.ErrInvalidKeyType) {
						t.Errorf("Invaild key type selected.\nError: %s", err.Error())
						t.FailNow()
					}
				}
			})
		}

		// End the background goroutine.
		jwks.EndBackground()
	}
}

// TestKIDs confirms the JWKs.KIDs returns the key IDs (`kid`) stored in the JWKs.
func TestJWKs_KIDs(t *testing.T) {

	// Create the JWKs from JSON.
	jwks, err := keyfunc.NewJSON([]byte(jwksJSON))
	if err != nil {
		t.Errorf("Failed to create a JWKs from JSON.\nError: %s", err.Error())
		t.FailNow()
	}

	// The expected key IDs.
	expectedKIDs := []string{
		"zXew0UJ1h6Q4CCcd_9wxMzvcp5cEBifH0KWrCz2Kyxc",
		"ebJxnm9B3QDBljB5XJWEu72qx6BawDaMAhwz4aKPkQ0",
		"TVAAet63O3xy_KK6_bxVIu7Ra3_z1wlB543Fbwi5VaU",
		"arlUxX4hh56rNO-XdIPhDT7bqBMqcBwNQuP_TnZJNGs",
		"tW6ae7TomE6_2jooM-sf9N_6lWg7HNtaQXrDsElBzM4",
		"Lx1FmayP2YBtxaqS1SKJRJGiXRKnw2ov5WmYIMG-BLE",
		"gnmAfvmlsi3kKH3VlM1AJ85P2hekQ8ON_XvJqs3xPD8",
		"CGt0ZWS4Lc5faiKSdi0tU0fjCAdvGROQRGU9iR7tV0A",
		"C65q0EKQyhpd1m4fr7SKO2He_nAxgCtAdws64d2BLt8",
	}

	// Get all key IDs in the JWKs.
	actual := jwks.KIDs()

	// Confirm the length is the same.
	actualLen := len(actual)
	expectedLen := len(expectedKIDs)
	if actualLen != expectedLen {
		t.Errorf("The number of key IDs was not as expected.\n  Expected length: %d\n  Actual length: %d\n  Actual key IDs: %v", expectedLen, actualLen, actual)
		t.FailNow()
	}

	// Confirm all expected keys are present.
	var found bool
	for _, expectedKID := range expectedKIDs {
		found = false
		for _, kid := range actual {
			if kid == expectedKID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Failed to find expected key ID in the slice of key IDs in the JWKs.\n  Missing: %s", expectedKID)
		}
	}
}

// TestRateLimit performs a test to confirm the rate limiter works as expected.
func TestRateLimit(t *testing.T) {

	// Create a temporary directory to serve the JWKs from.
	tempDir, err := ioutil.TempDir("", "*")
	if err != nil {
		t.Errorf("Failed to create a temporary directory.\nError: %s", err.Error())
		t.FailNow()
	}
	defer func() {
		if err = os.RemoveAll(tempDir); err != nil {
			t.Errorf("Failed to remove temporary directory.\nError: %s", err.Error())
			t.FailNow()
		}
	}()

	// Create an integer to keep track of how many times the JWKs has been refreshed.
	refreshes := uint(0)
	refreshMux := sync.Mutex{}

	// Create the HTTP test server.
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {

		// Increment the number of refreshes that have occurred.
		refreshMux.Lock()
		refreshes++
		refreshMux.Unlock()

		// Write the JWKs to the response, regardless of the request.
		writer.WriteHeader(200)
		if _, serveErr := writer.Write([]byte(jwksJSON)); serveErr != nil {
			t.Errorf("Failed to serve JWKs.\nError: %s", err.Error())
		}
	}))
	defer server.Close()

	// Set the JWKs URL.
	jwksURL := server.URL + jwksFilePath

	// Create the testing options.
	refreshInterval := time.Second
	refreshRateLimit := time.Millisecond * 500
	refreshTimeout := time.Second
	refreshUnknownKID := true
	options := keyfunc.Options{
		RefreshErrorHandler: func(err error) {
			t.Errorf("The package itself had an error.\nError: %s", err.Error())
		},
		RefreshInterval:   refreshInterval,
		RefreshRateLimit:  refreshRateLimit,
		RefreshTimeout:    refreshTimeout,
		RefreshUnknownKID: &refreshUnknownKID,
	}

	// Create the JWKs.
	var jwks *keyfunc.JWKs
	if jwks, err = keyfunc.Get(jwksURL, options); err != nil {
		t.Errorf("Failed to create *keyfunc.JWKs.\nError: %s", err.Error())
		t.FailNow()
	}
	defer jwks.EndBackground()

	// Create four JWTs with unknown kids.
	//
	// These should prompt two refreshes.
	// The first one will not be rate limited.
	// The second will get a rate limit queue.
	// The third will get no rate limit queue and will be ignored because there is already a one in the queue.
	// The fourth will get no rate limit queue and will be ignored because there is already a one in the queue.
	token1 := "eyJraWQiOiI0NWU3ZDcyMiIsInR5cCI6IkpXVCIsImFsZyI6IlJTNTEyIn0.eyJzdWIiOiJBbmRyZWEiLCJhdWQiOiJUYXNodWFuIiwiaXNzIjoiandrcy1zZXJ2aWNlLmFwcHNwb3QuY29tIiwiZXhwIjoxNjI0NzU2OTAwLCJpYXQiOjE2MjQ3NTY4OTUsImp0aSI6IjA5ZjkzZjljLTU0ZjMtNDM5Yi04Njg2LWZhMGYwMjlmYmIwZSJ9.g643vWnvDvR5u5TeCUaCblp-Ss8SPWoZrOxBo3y6WP9xQnRW63VSbacCirl-5nGRPoX6vostZAkRyUl62ICQHpTj3bRnDY4ZbkcQ42xtrWMBsI2Sw6dAmZtGsCR_tguQZmvdKE4gVNnFWLp0hBjCeLxPVbc59vC6njMdz7XHcOdW7RXN6iUYjLFoPAr4Qg93Vbrwfo9Qmkm8bDgbnuoJ3aQq0RFa02G1KC2-cx8SuUbxso_Uu7ddY6HDRL5OPF3xS9cKO5ty4zCfGYIVDhfH7V-zA2cJZyA2dlv3Ddd-ntU42aud0M4PcTTdjHf1CE29sCZHk5wTRgxsTjfWglYQQiVQJEkw6DD6kTlQ_MwN4p_OWNj06b55mXM6Bj9c9y8TfPLETDy_PRc1lHu1PuiizLg019JaGidpTLF8IdKTa9emkEnf2n8xWi-YMkkRk57hpuc56GmnBR0d8ODfuL0XILlQp2guFsVRo9A4Sdqy7fGdZGoSS4XzSR-TIEw7W_KSqlYCtWC0xNk1Kze3xSY2mDqrn1YFFlvXgXQlgzU8GN1eL7QRRQlxaPGti2wEH6OYH4A160nR_OM-zFBobpQn79g8HsK8yZgPiY0p94F6pvKBQtSHDBvAe3W0-UHYfspwT9cQGVgqCGol6A8XNeBlVQpko9ves4UgCRSb6o9u_p4"
	token2 := "eyJraWQiOiIyYTFkODRhMCIsInR5cCI6IkpXVCIsImFsZyI6IkVTMzg0In0.eyJzdWIiOiJBbmRyZWEiLCJhdWQiOiJUYXNodWFuIiwiaXNzIjoiandrcy1zZXJ2aWNlLmFwcHNwb3QuY29tIiwiZXhwIjoxNjI0NzU3MjExLCJpYXQiOjE2MjQ3NTcyMDYsImp0aSI6ImU4YjQ1YmIwLTczZjgtNDkzNi04MjQxLWE1OGFlZWMyZWE2NCJ9.6Isd4unU2TAmRB1SouaHBV9LUjFGIuhOrxkQlDjh6qKRgb7UsiPtQm87S2qrriLaFjyCmrmU6cDpVBpTOutjPxweIqT-1EfsS-dkENIVWPVgQ5-KuNu2jXyGYpPeFBUA"
	token3 := "eyJraWQiOiIxZjEyOGFkZSIsInR5cCI6IkpXVCIsImFsZyI6IkVTMjU2In0.eyJzdWIiOiJSZWJlY2NhIiwiYXVkIjoiQWxpY2UiLCJpc3MiOiJqd2tzLXNlcnZpY2UuYXBwc3BvdC5jb20iLCJleHAiOjE2MjQ3NTkzODIsImlhdCI6MTYyNDc1OTM3NywianRpIjoiMzU2MWY4MDctNDRkNi00OWE5LWFlYWItMmQ1MjQ2YWYxNDhlIn0.5eZbJlvnaFsRwPhBHmXljp9vgsrB0Q9d3dSz4va29ahTKsFGFo8tYy0e69ehqSb-dbFy9azRRtygwwtYuaEFuA"
	token4 := "eyJraWQiOiIyZDQ3NjUwYSIsInR5cCI6IkpXVCIsImFsZyI6IlBTMzg0In0.eyJzdWIiOiJGcmVkYSIsImF1ZCI6Ikx1Y2lhIiwiaXNzIjoiandrcy1zZXJ2aWNlLmFwcHNwb3QuY29tIiwiZXhwIjoxNjI0ODA0MTk0LCJpYXQiOjE2MjQ4MDQxODksImp0aSI6IjdjNTQ2Y2RmLTYwMTEtNDI3Ny04Y2Q0LTMwNjZmZTYwNTExZSJ9.hQm-OP_MMk8_S13-ohiINRuDP2IlCiB3yn8Ov6qTjeFbq4gZ6MegeJH_qiZOvXqlzOAwpwd5P4nm5JeS6LlNGdW6V_agwYwnAd08GI7APQNRib692_sEk1DKdSk-S-Y8V_ZAgeTT8asdaSDw4EBPxkDvROcuEqesZrfqnrOcpdqqa2BcmwX8q5sLtQ8TMp4cOvEZg-J8_0j2kdCUkv_n9ZdsRoA3EUT8M1bYqnGRRxIRqflsm-S_xq3HxMAnPF5hPlqIKFVKuRsU0SKgcHZGwXpuK2lJqPobl6MI987tGrc9sPPFzVkNYxeltcxu34-ZjzN6iCQN8r0w-mfqCZav7A"

	// Use the JWKs jwk.Keyfunc to parse the tokens signed with unknown kids at nearly the same time.
	waitGroup := sync.WaitGroup{}
	waitGroup.Add(3)
	go func() {
		defer waitGroup.Done()
		if _, parseErr := jwt.Parse(token1, jwks.Keyfunc); parseErr != nil {
			if errors.Is(parseErr, jwt.ErrInvalidKeyType) {
				t.Errorf("Invaild key type selected.\nError: %s", parseErr.Error())
			}
		}
	}()
	go func() {
		defer waitGroup.Done()
		if _, parseErr := jwt.Parse(token2, jwks.Keyfunc); parseErr != nil {
			if errors.Is(parseErr, jwt.ErrInvalidKeyType) {
				t.Errorf("Invaild key type selected.\nError: %s", parseErr.Error())
			}
		}
	}()
	go func() {
		defer waitGroup.Done()
		if _, parseErr := jwt.Parse(token3, jwks.Keyfunc); parseErr != nil {
			if errors.Is(parseErr, jwt.ErrInvalidKeyType) {
				t.Errorf("Invaild key type selected.\nError: %s", parseErr.Error())
			}
		}
	}()
	if _, parseErr := jwt.Parse(token4, jwks.Keyfunc); parseErr != nil {
		if errors.Is(parseErr, jwt.ErrInvalidKeyType) {
			t.Errorf("Invaild key type selected.\nError: %s", parseErr.Error())
			t.FailNow()
		}
	}
	waitGroup.Wait()

	// Confirm the JWKs was only refreshed once. (Refresh counter was first incremented on the creation of the JWKs.)
	refreshMux.Lock()
	expected := uint(2)
	if refreshes != expected {
		t.Errorf("An incorrect number of refreshes occurred.\n  Expected: %d\n  Got: %d\n", expected, refreshes)
		t.FailNow()
	}
	refreshMux.Unlock()

	// Wait for the rate limiter to take the next queue.
	time.Sleep(refreshRateLimit + time.Millisecond*100)
	refreshMux.Lock()
	expected = uint(3)
	if refreshes != expected {
		t.Errorf("An incorrect number of refreshes occurred.\n  Expected: %d\n  Got: %d\n", expected, refreshes)
		t.FailNow()
	}
	refreshMux.Unlock()

	// Wait for the refresh interval to occur.
	time.Sleep(refreshInterval + time.Millisecond*100)
	refreshMux.Lock()
	expected = uint(4)
	if refreshes != expected {
		t.Errorf("An incorrect number of refreshes occurred.\n  Expected: %d\n  Got: %d\n", expected, refreshes)
		t.FailNow()
	}
	refreshMux.Unlock()
}

// TestUnknownKIDRefresh performs a test to confirm that an Unknown kid with refresh the JWKs.
func TestUnknownKIDRefresh(t *testing.T) {

	// Create a temporary directory to serve the JWKs from.
	tempDir, err := ioutil.TempDir("", "*")
	if err != nil {
		t.Errorf("Failed to create a temporary directory.\nError: %s", err.Error())
		t.FailNow()
	}
	defer func() {
		if err = os.RemoveAll(tempDir); err != nil {
			t.Errorf("Failed to remove temporary directory.\nError: %s", err.Error())
			t.FailNow()
		}
	}()

	// Create the JWKs file path.
	jwksFile := filepath.Join(tempDir, strings.TrimPrefix(jwksFilePath, "/"))

	// Write the empty JWKs.
	if err = ioutil.WriteFile(jwksFile, []byte(emptyJWKsJSON), 0600); err != nil {
		t.Errorf("Failed to write JWKs file to temporary directory.\nError: %s", err.Error())
		t.FailNow()
	}

	// Create the HTTP test server.
	server := httptest.NewServer(http.FileServer(http.Dir(tempDir)))
	defer server.Close()

	// Create testing options.
	testingRefreshErrorHandler := func(err error) {
		t.Errorf("Unhandled JWKs error: %s", err.Error())
		t.FailNow()
	}

	// Set the JWKs URL.
	jwksURL := server.URL + jwksFilePath

	// Set the options to refresh KID when unknown.
	options := keyfunc.Options{
		RefreshErrorHandler: testingRefreshErrorHandler,
		RefreshUnknownKID:   &[]bool{true}[0],
	}

	// Create the JWKs.
	var jwks *keyfunc.JWKs
	if jwks, err = keyfunc.Get(jwksURL, options); err != nil {
		t.Errorf("Failed to create *keyfunc.JWKs.\nError: %s", err.Error())
		t.FailNow()
	}
	defer jwks.EndBackground()

	// Write the empty JWKs.
	if err = ioutil.WriteFile(jwksFile, []byte(jwksJSON), 0600); err != nil {
		t.Errorf("Failed to write JWKs file to temporary directory.\nError: %s", err.Error())
		t.FailNow()
	}

	// Use any JWT signed by a key in the non-empty JWKs.
	token := "eyJhbGciOiJFUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJDR3QwWldTNExjNWZhaUtTZGkwdFUwZmpDQWR2R1JPUVJHVTlpUjd0VjBBIn0.eyJleHAiOjE2MTU0MDY4NjEsImlhdCI6MTYxNTQwNjgwMSwianRpIjoiYWVmOWQ5YjItN2EyYy00ZmQ4LTk4MzktODRiMzQ0Y2VmYzZhIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL2F1dGgvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhZDEyOGRmMS0xMTQwLTRlNGMtYjA5Ny1hY2RjZTcwNWJkOWIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ0b2tlbmRlbG1lIiwiYWNyIjoiMSIsInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwiY2xpZW50SG9zdCI6IjE3Mi4yMC4wLjEiLCJjbGllbnRJZCI6InRva2VuZGVsbWUiLCJlbWFpbF92ZXJpZmllZCI6ZmFsc2UsInByZWZlcnJlZF91c2VybmFtZSI6InNlcnZpY2UtYWNjb3VudC10b2tlbmRlbG1lIiwiY2xpZW50QWRkcmVzcyI6IjE3Mi4yMC4wLjEifQ.iQ77QGoPDNjR2oWLu3zT851mswP8J-h_nrGhs3fpa_tFB3FT1deKPGkjef9JOTYFI-CIVxdCFtW3KODOaw9Nrw"

	// Use the JWKs jwk.Keyfunc to parse the token.
	//
	// Don't check for general errors. Unfortunately, an error occurs when a token is expired. All hard
	// coded tokens are expired.
	if _, err = jwt.Parse(token, jwks.Keyfunc); err != nil {
		if errors.Is(err, jwt.ErrInvalidKeyType) {
			t.Errorf("Invaild key type selected.\nError: %s", err.Error())
			t.FailNow()
		}
	}
}
