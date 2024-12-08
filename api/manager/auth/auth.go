package auth

import (
	"github.com/dstgo/kratosx"

	v1 "github.com/dstgo/manager/api/manager/auth/v1"
)

// GetAuthInfo 获取实名认证信息
func GetAuthInfo(ctx kratosx.Context) (*v1.AuthReply, error) {
	data := v1.AuthReply{}
	return &data, ctx.Authentication().ParseAuth(ctx, &data)
}
