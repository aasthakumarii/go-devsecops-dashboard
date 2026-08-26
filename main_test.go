package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthEndpoint(t *testing.T) {
	request := httptest.NewRequest(
		http.MethodGet,
		"/health",
		nil,
	)

	recorder := httptest.NewRecorder()

	routes().ServeHTTP(
		recorder,
		request,
	)

	if recorder.Code != http.StatusOK {
		t.Fatalf(
			"expected status 200, got %d",
			recorder.Code,
		)
	}

	var response map[string]string

	err := json.Unmarshal(
		recorder.Body.Bytes(),
		&response,
	)

	if err != nil {
		t.Fatalf(
			"failed to decode response: %v",
			err,
		)
	}

	if response["status"] != "healthy" {
		t.Fatalf(
			"expected healthy status, got %s",
			response["status"],
		)
	}
}

func TestStatusEndpoint(t *testing.T) {
	request := httptest.NewRequest(
		http.MethodGet,
		"/api/status",
		nil,
	)

	recorder := httptest.NewRecorder()

	routes().ServeHTTP(
		recorder,
		request,
	)

	if recorder.Code != http.StatusOK {
		t.Fatalf(
			"expected status 200, got %d",
			recorder.Code,
		)
	}

	var response StatusResponse

	err := json.Unmarshal(
		recorder.Body.Bytes(),
		&response,
	)

	if err != nil {
		t.Fatalf(
			"failed to decode response: %v",
			err,
		)
	}

	if response.Application != "Go DevSecOps Dashboard" {
		t.Fatalf(
			"unexpected application name: %s",
			response.Application,
		)
	}

	if response.Status != "running" {
		t.Fatalf(
			"expected running status, got %s",
			response.Status,
		)
	}
}

func TestHomeEndpoint(t *testing.T) {
	loadTemplate()

	request := httptest.NewRequest(
		http.MethodGet,
		"/",
		nil,
	)

	recorder := httptest.NewRecorder()

	routes().ServeHTTP(
		recorder,
		request,
	)

	if recorder.Code != http.StatusOK {
		t.Fatalf(
			"expected status 200, got %d",
			recorder.Code,
		)
	}

	if !strings.Contains(
		recorder.Body.String(),
		"Go DevSecOps Dashboard",
	) {
		t.Fatal(
			"dashboard title was not found",
		)
	}
}

func TestUnknownEndpoint(t *testing.T) {
	loadTemplate()

	request := httptest.NewRequest(
		http.MethodGet,
		"/does-not-exist",
		nil,
	)

	recorder := httptest.NewRecorder()

	routes().ServeHTTP(
		recorder,
		request,
	)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf(
			"expected status 404, got %d",
			recorder.Code,
		)
	}
}
