package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os/exec"
	"strings"
)

func sshToPem(sshKey string) ([]byte, error) {
	cmd := exec.Command("ssh-keygen", "-e", "-f", "/dev/stdin", "-m", "PKCS8")
	cmd.Stdin = strings.NewReader(sshKey)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to convert SSH key using ssh-keygen: %v", err)
	}
	return out.Bytes(), nil
}

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	if r.Method == "OPTIONS" {
		return
	}
	if r.URL.Path == "/decrypt" && r.Method == "GET" {
		tmpl := template.Must(template.ParseFiles("decrypt.html"))
		if err := tmpl.Execute(w, nil); err != nil {
			http.Error(w, fmt.Sprintf(`{"error": "Failed to serve decrypt.html: %v"}`, err), http.StatusInternalServerError)
			return
		}
		return
	}

	if r.Method == "GET" {
		tmpl := template.Must(template.ParseFiles("index.html"))
		if err := tmpl.Execute(w, nil); err != nil {
			http.Error(w, fmt.Sprintf(`{"error": "Failed to serve index.html: %v"}`, err), http.StatusInternalServerError)
			return
		}
		return
	}

	if r.Method != "POST" {
		http.Error(w, `{"error": "Invalid request method"}`, http.StatusMethodNotAllowed)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Failed to read request body: %v"}`, err), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	pemKey, err := sshToPem(string(bodyBytes))
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error": "Failed to convert SSH key: %v"}`, err), http.StatusBadRequest)
		return
	}

	response := map[string]string{
		"pem_key": string(pemKey),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func main() {
	http.HandleFunc("/", handler)

	fmt.Println("Starting server on port 9000...")
	if err := http.ListenAndServe(":9000", nil); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}
