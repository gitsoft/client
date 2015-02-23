package main

import (
	"fmt"

	"github.com/codegangsta/cli"
	"github.com/keybase/go/engine"
	"github.com/keybase/go/libcmdline"
	"github.com/keybase/go/libkb"
	"github.com/maxtaco/go-framed-msgpack-rpc/rpc2"
)

type CmdMykeySelect struct {
	query string
}

func (v *CmdMykeySelect) ParseArgv(ctx *cli.Context) (err error) {
	if nargs := len(ctx.Args()); nargs == 1 {
		v.query = ctx.Args()[0]
	} else if nargs != 0 {
		err = fmt.Errorf("mkey select takes 0 or 1 arguments")
	}
	return err
}

func (v *CmdMykeySelect) RunClient() error {
	c, err := GetMykeyClient()
	if err != nil {
		return err
	}
	protocols := []rpc2.Protocol{
		NewGPGUIProtocol(),
		NewLogUIProtocol(),
		NewSecretUIProtocol(),
	}
	if err = RegisterProtocols(protocols); err != nil {
		return err
	}

	return c.Select(v.query)
}

func (v *CmdMykeySelect) Run() error {
	ctx := &engine.Context{
		GPGUI:    G.UI.GetGPGUI(),
		SecretUI: G.UI.GetSecretUI(),
	}
	gpg := engine.NewGPG()
	arg := engine.GPGArg{Query: v.query, LoadDeviceKey: true}
	return engine.RunEngine(gpg, ctx, arg, nil)
}

func NewCmdMykeySelect(cl *libcmdline.CommandLine) cli.Command {
	return cli.Command{
		Name:        "select",
		Usage:       "keybase mykey select [<key-query>]",
		Description: "Select a key as your own and push it to the server",
		Action: func(c *cli.Context) {
			cl.ChooseCommand(&CmdMykeySelect{}, "select", c)
		},
	}
}

func (v *CmdMykeySelect) GetUsage() libkb.Usage {
	return libkb.Usage{
		Config:    true,
		KbKeyring: true,
		API:       true,
		Terminal:  true,
	}
}
