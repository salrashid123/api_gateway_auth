package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/lestrrat/go-jwx/jwk"

	"github.com/gorilla/mux"
	"golang.org/x/net/http2"

	"golang.org/x/net/context"
)

type contextKey string

const (
	contextEventKey contextKey = "jwtToken"
)

var (
	// Cloud Run/GoogleOIDC
	// jwksURL         = "https://www.googleapis.com/oauth2/v3/certs"
	// allowedIssuer   = "https://accounts.google.com"
	// allowedAudience = "https://iaprun-6w42z6vi3q-uc.a.run.app"

	// IAP
	// jwksURL         = "https://www.gstatic.com/iap/verify/public_key-jwk"
	// allowedAudience = "/projects/1071284184436/apps/mineral-minutia-820"
	// allowedIssuer   = "https://cloud.google.com/iap"

	jwtSet          *jwk.Set
	allowedIssuer   = flag.String("allowedIssuer", "https://accounts.google.com", "Isssuer to allow")
	allowedAudience = flag.String("allowedAudience", "https://apiserver-6w42z6vi3q-uc.a.run.app/todo", "Audience to allow")
	jwksURL         = flag.String("jwksURL", "https://www.googleapis.com/oauth2/v3/certs", "JWK URL")
	httpport        = flag.String("httpport", ":8080", "httpport")
)

type gcpIdentityDoc struct {
	Google struct {
		ComputeEngine struct {
			InstanceCreationTimestamp int64  `json:"instance_creation_timestamp,omitempty"`
			InstanceID                string `json:"instance_id,omitempty"`
			InstanceName              string `json:"instance_name,omitempty"`
			ProjectID                 string `json:"project_id,omitempty"`
			ProjectNumber             int64  `json:"project_number,omitempty"`
			Zone                      string `json:"zone,omitempty"`
		} `json:"compute_engine"`
	} `json:"google"`
	Email           string `json:"email,omitempty"`
	EmailVerified   bool   `json:"email_verified,omitempty"`
	AuthorizedParty string `json:"azp,omitempty"`
	jwt.StandardClaims
}

func getKey(token *jwt.Token) (interface{}, error) {
	keyID, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("expecting JWT header to have string kid")
	}
	if key := jwtSet.LookupKeyID(keyID); len(key) == 1 {
		log.Printf("     Found OIDC KeyID  " + keyID)
		return key[0].Materialize()
	}
	return nil, errors.New("unable to find key")
}

func verifyGoogleIDToken(ctx context.Context, rawToken string) (gcpIdentityDoc, error) {
	token, err := jwt.ParseWithClaims(rawToken, &gcpIdentityDoc{}, getKey)
	if err != nil {
		log.Printf("     Error parsing JWT %v", err)
		return gcpIdentityDoc{}, err
	}
	if claims, ok := token.Claims.(*gcpIdentityDoc); ok && token.Valid {
		log.Printf("     OIDC doc has Audience [%s]   Issuer [%s] and SubjectEmail [%s]", claims.Audience, claims.StandardClaims.Issuer, claims.Email)
		return *claims, nil
	}
	return gcpIdentityDoc{}, errors.New("Error parsing JWT Claims")
}

type server struct{}

func authMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		requestDump, err := httputil.DumpRequest(r, true)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf(string(requestDump))

		authHeader := r.Header.Get("Authorization")

		if authHeader == "" {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		splitToken := strings.Split(authHeader, "Bearer")
		if len(splitToken) == 2 {
			tok := strings.TrimSpace(splitToken[1])
			idDoc, err := verifyGoogleIDToken(r.Context(), tok)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}

			if idDoc.Audience != *allowedAudience {
				http.Error(w, "Audience value not allowed", http.StatusUnauthorized)
				return
			}

			if idDoc.Issuer != *allowedIssuer {
				http.Error(w, "Issuer value not allowed", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), contextEventKey, idDoc)
			h.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	})
}

func fronthandler(w http.ResponseWriter, r *http.Request) {
	log.Println("/ called")
	subject := r.Context().Value(contextKey("jwtToken")).(gcpIdentityDoc)
	fmt.Fprint(w, "ok "+subject.Email)
}

func listhandler(w http.ResponseWriter, r *http.Request) {
	log.Println("/listhandler called")
	subject := r.Context().Value(contextKey("jwtToken")).(gcpIdentityDoc)
	fmt.Fprint(w, "list "+subject.Email)
}

func main() {
	flag.Parse()
	var err error
	jwtSet, err = jwk.FetchHTTP(*jwksURL)
	if err != nil {
		log.Fatal("Unable to load JWK Set: ", err)
	}

	router := mux.NewRouter()
	router.Methods(http.MethodGet).Path("/todo").HandlerFunc(listhandler)

	var server *http.Server
	server = &http.Server{
		Addr:    *httpport,
		Handler: authMiddleware(router),
	}
	http2.ConfigureServer(server, &http2.Server{})
	fmt.Println("Starting Server..")
	err = server.ListenAndServe()
	if err != nil {
		log.Fatal("Unable to serve: ", err)
	}
}
