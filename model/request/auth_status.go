package request

type ChangeUserAuthStatus struct {
	Id             string `json:"id"`
	AuthStatusCode string `json:"authStatusCode"`
}
