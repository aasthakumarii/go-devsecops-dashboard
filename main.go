package main

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"
)

type PageData struct {
	Application string
	Environment string
	Version     string
	ServerTime  string
	Status      string
}

type StatusResponse struct {
	Application string `json:"application"`
	Environment string `json:"environment"`
	Version     string `json:"version"`
	Status      string `json:"status"`
}

var pageTemplate *template.Template

func loadTemplate() {
	pageTemplate = template.Must(
		template.ParseFiles("templates/index.html"),
	)
}

func getEnvironment() string {
	value := os.Getenv("APP_ENV")

	if value == "" {
		return "development"
	}

	return value
}

func getVersion() string {
	value := os.Getenv("APP_VERSION")

	if value == "" {
		return "1.0.0"
	}

	return value
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	data := PageData{
		Application: "Go DevSecOps Dashboard",
		Environment: getEnvironment(),
		Version:     getVersion(),
		ServerTime:  time.Now().Format(time.RFC1123),
		Status:      "Healthy",
	}

	err := pageTemplate.Execute(w, data)

	if err != nil {
		http.Error(
			w,
			"Unable to render dashboard",
			http.StatusInternalServerError,
		)

		return
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	w.WriteHeader(http.StatusOK)

	response := map[string]string{
		"status": "healthy",
	}

	_ = json.NewEncoder(w).Encode(response)
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	response := StatusResponse{
		Application: "Go DevSecOps Dashboard",
		Environment: getEnvironment(),
		Version:     getVersion(),
		Status:      "running",
	}

	_ = json.NewEncoder(w).Encode(response)
}

func routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/", homeHandler)
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/api/status", statusHandler)

	mux.Handle(
		"/static/",
		http.StripPrefix(
			"/static/",
			http.FileServer(http.Dir("static")),
		),
	)

	return mux
}

func main() {
	loadTemplate()

	port := os.Getenv("PORT")

	if port == "" {
		port = "8080"
	}

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf(
		"Go DevSecOps Dashboard running on port %s",
		port,
	)

	err := server.ListenAndServe()

	if err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
