package controller

import (
	"bytes"
	"encoding/json"
	"net/http"
)

type Credentials struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	Domain     string `json:"domain"`
	ProjectID  string `json:"projectId"`
	AuthURL    string `json:"authUrl"`
	NeutronURL string `json:"neutronUrl"`
}

func getKeystoneToken(c Credentials) (string, error) {
	requestBodyJson := map[string]interface{}{
		"auth": map[string]interface{}{
			"identity": map[string]interface{}{
				"methods": []string{"password"},
				"password": map[string]interface{}{
					"user": map[string]interface{}{
						"name":     c.Username,
						"domain":   map[string]string{"name": c.Domain},
						"password": c.Password,
					},
				},
			},
			"scope": map[string]interface{}{
				"project": map[string]interface{}{
					"id": c.ProjectID,
				},
			},
		},
	}

	requestBody, _ := json.Marshal(requestBodyJson)
	request, err := http.NewRequest(
		"POST",
		c.AuthURL+"/v3/auth/tokens",
		bytes.NewReader(requestBody),
	)
	if err != nil {
		return "", err
	}

	request.Header.Set("Content-Type", "application/json")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return "", err
	}

	return response.Header.Get("X-Subject-Token"), nil
}
