package definition

import (
	"fmt"
	"os"
	"path"
	"runtime"
	"strings"

	"simple_ca/src/tools"
)

func getEmailTemp(fail string, dict map[string]string) string {
	_, currently, _, _ := runtime.Caller(0)
	filename := path.Join(path.Dir(currently), fail)
	fmt.Println(filename)
	temp, err := os.ReadFile(filename)
	if err != nil {
		tools.ExceptionLog(err, "")
		panic("Read temp Fail")
	}
	t := string(temp)
	for k, v := range dict {
		t = strings.Replace(t, "{# "+k+" #}", v, -1)
	}
	return t
}

// CerSuccessTemp 证书申请成功邮件模板
func CerSuccessTemp(dict map[string]string) string {
	return getEmailTemp("./success.html", dict)
}

func CerUnPassTemp(dict map[string]string) string {
	return getEmailTemp("./fail.html", dict)
}
