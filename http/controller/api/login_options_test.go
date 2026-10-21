package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/lejianwen/rustdesk-api/v2/global"
	"github.com/lejianwen/rustdesk-api/v2/model"
	"github.com/lejianwen/rustdesk-api/v2/service"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestLoginOptionsResponseContract(t *testing.T) {
	// These upstream dependencies are package globals; do not parallelize these cases.
	for _, test := range []struct {
		name     string
		webSSO   bool
		provider string
		want     []string
	}{
		{"no-providers", false, "", []string{}},
		{"web-sso-enabled", true, "", []string{model.OauthTypeWebauth}},
		{"configured-provider", false, "synthetic-oidc", []string{"synthetic-oidc"}},
		{"provider-and-web-sso", true, "synthetic-oidc", []string{"synthetic-oidc", model.OauthTypeWebauth}},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
				Logger: logger.Default.LogMode(logger.Silent),
			})
			if err != nil {
				t.Fatal(err)
			}
			sqlDB, err := db.DB()
			if err != nil {
				t.Fatal(err)
			}
			sqlDB.SetMaxOpenConns(1)
			t.Cleanup(func() { sqlDB.Close() })
			if err := db.AutoMigrate(&model.Oauth{}); err != nil {
				t.Fatal(err)
			}
			if test.provider != "" {
				if err := db.Create(&model.Oauth{Op: test.provider, OauthType: model.OauthTypeOidc}).Error; err != nil {
					t.Fatal(err)
				}
			}
			oldDB, oldServices := service.DB, service.AllService
			oldWebSSO, oldGinMode := global.Config.App.WebSso, gin.Mode()
			service.DB, service.AllService = db, &service.Service{}
			global.Config.App.WebSso = test.webSSO
			gin.SetMode(gin.TestMode)
			t.Cleanup(func() {
				service.DB, service.AllService = oldDB, oldServices
				global.Config.App.WebSso = oldWebSSO
				gin.SetMode(oldGinMode)
			})

			router := gin.New()
			router.GET("/api/login-options", (&Login{}).LoginOptions)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/login-options", nil))
			if response.Code != http.StatusOK || !strings.HasPrefix(response.Header().Get("Content-Type"), "application/json") {
				t.Fatal("login options must return HTTP 200 JSON")
			}
			var options []string
			if err := json.Unmarshal(response.Body.Bytes(), &options); err != nil {
				t.Fatal(err)
			}
			if len(options) != len(test.want)+1 || !strings.HasPrefix(options[0], "common-oidc/") {
				t.Fatal("login options must retain the common and legacy option formats")
			}
			// Official 1.5.0 decodes this suffix as the return value of Future<List<dynamic>>.
			// A JSON null is not an empty list and violates that non-nullable contract.
			var common []map[string]string
			if err := json.Unmarshal([]byte(strings.TrimPrefix(options[0], "common-oidc/")), &common); err != nil {
				t.Fatal(err)
			}
			if common == nil || len(common) != len(test.want) {
				t.Fatal("common OIDC options must be an array, including when empty")
			}
			for i, name := range test.want {
				if common[i]["name"] != name || options[i+1] != "oidc/"+name {
					t.Fatal("configured login options changed")
				}
			}
		})
	}
}
