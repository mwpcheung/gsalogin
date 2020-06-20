package main

import (
	"encoding/hex"

	"github.com/astaxie/beego/logs"
)

func GSALogin(username, password string, udid, imd, imdm string) (*GSAStatus, []byte) {
	context := NewLoginSession("mwpcheung@gmail.com", "password_clear_text")
	var status GSAStatus
	resp := context.LoginStep1(udid, imd, imdm)
	if resp.Status.ErrorCode != 0 {
		return &resp.Status, nil
	}
	m1 := context.HandleStep1(resp)
	if len(m1) == 0 {
		logs.Debug("计算M1 挂掉")
		status.ErrorCode = 1000
		status.ErrorMessage = "internal error"
		return &status, nil
	}
	c := resp.Complete
	sp := resp.SeverProto
	resp2 := context.LoginStep2(m1, c, sp)
	if resp2.Status.ErrorCode != 0 {
		logs.Debug("登陆失败 %d %s", resp2.Status.ErrorCode, resp2.Status.ErrorMessage)
		return &resp2.Status, nil
	} else {
		//解密spd
		M2 := resp2.M2
		if hex.EncodeToString(M2) != hex.EncodeToString(context.srp.M2) {
			logs.Debug("srp M2 校验失败")
			status.ErrorCode = 1001
			status.ErrorMessage = "m2 check failed"
			return &status, nil
		}
	}
	if len(resp2.SPD) > 0 {
		dict := context.HandleStep2(resp2)
		status.ErrorCode = 0
		logs.Debug("%s", dict)
		return &status, dict
	}
	status.ErrorCode = 1002
	status.ErrorMessage = "unknown error"
	return &status, nil

}
func main() {
	logs.SetLogFuncCall(true)
	udid := "223f8d08c8dd96a1bba1435dfaa379a74893b15c"
	imd := "AAAABQAAABBk4XZ4uF6VeFHpLDNXyex1AAAAAw=="
	imdm := "Kjy3O6fJ6w92DvLSY8nhmimHbf4/Dfs2CMGSF+jObcgQOy/Gbl6NMAFDkSTBSlI2F/eF/JTbkG5zGAtL"
	username := "mwpcheung@gmail.com"
	password := "password_text"
	status, token := GSALogin(username, password, udid, imd, imdm)
	logs.Debug("%+v \n%s", status, token)
}
