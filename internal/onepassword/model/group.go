package model

import (
	sdk "github.com/1password/onepassword-sdk-go"
)

type Group struct {
	ID          string
	Name        string
	Description string
	Type        string
	State       string
}

func (g *Group) FromSDKGroup(group *sdk.Group) {
	g.ID = group.ID
	g.Name = group.Title
	g.Description = group.Description
	g.Type = string(group.GroupType)
	g.State = string(group.State)
}
