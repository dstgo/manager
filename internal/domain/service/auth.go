package service

import (
	"github.com/dstgo/kratosx"
	"github.com/dstgo/kratosx/pkg/valx"

	"github.com/dstgo/manager/api/manager/errors"
	"github.com/dstgo/manager/internal/conf"
	"github.com/dstgo/manager/internal/pkg/md"
	"github.com/dstgo/manager/internal/types"
)

type Auth struct {
	conf *conf.Config
}

func NewAuth(conf *conf.Config) *Auth {
	return &Auth{
		conf: conf,
	}
}

// Auth 外部接口鉴权
func (u *Auth) Auth(ctx kratosx.Context, in *types.AuthRequest) (*md.Auth, error) {
	info := md.Get(ctx)

	if valx.InList(ctx.Config().App().Authentication.SkipRole, info.RoleKeyword) {
		return info, nil
	}

	author := ctx.Authentication()
	if author.IsWhitelist(in.Path, in.Method) {
		return info, nil
	}

	enforce := ctx.Authentication().Enforce()
	isAuth, _ := enforce.Enforce(info.RoleKeyword, in.Path, in.Method)
	if !isAuth {
		return nil, errors.ForbiddenError()
	}

	return info, nil
}
