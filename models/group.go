package models

type Group struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	CreationDate     string `json:"creation_date"`
	LastModifiedDate string `json:"last_modified_date"`
	Precedence       int    `json:"precedence"`
	RoleArn          string `json:"role_arn"`
	UserPoolID       string `json:"user_pool_id"`
}
