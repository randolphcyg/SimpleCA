package main

import (
	"github.com/520MianXiangDuiXiang520/GoTools/dao"
	"github.com/gin-gonic/gin"

	"simple_ca/src"
)

func init() {
	src.InitSetting("./setting.json")
	//smtp := src.GetSetting().SMTPSetting
	//email.InitSMTPDialer(smtp.Host, smtp.Username, smtp.Password, smtp.Port)
	_ = dao.InitDBSetting(src.GetSetting().Database)

}

func main() {
	engine := gin.Default()
	Register(engine)
	err := engine.Run("localhost:8081")
	if err != nil {
		panic(err)
	}
}
