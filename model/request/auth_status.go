package request

type ChangeUserAuthStatus struct {
	ID             string `json:"id"`
	AuthStatusCode string `json:"authStatusCode"`
}
