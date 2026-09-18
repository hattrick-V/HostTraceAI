package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

const (
	securityToolPackagesDirName = "data/security_tool_packages"
	securityToolIndexFileName   = "index.json"
	maxSecurityToolPackageBytes = 512 << 20
)

type SecurityToolsHandler struct {
	logger *zap.Logger
}

func NewSecurityToolsHandler(logger *zap.Logger) *SecurityToolsHandler {
	return &SecurityToolsHandler{logger: logger}
}

type SecurityToolPackage struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	FileName    string `json:"fileName"`
	Size        int64  `json:"size"`
	UploadedAt  string `json:"uploadedAt"`
}

func (h *SecurityToolsHandler) PublicList(c *gin.Context) {
	packages, err := h.listPackages()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"packages":  packages,
		"tools":     packages, // 兼容旧前端字段名；语义已改为“管理员发布的工具包”
		"count":     len(packages),
		"updatedAt": time.Now().UTC().Format(time.RFC3339),
	})
}

func (h *SecurityToolsHandler) PublicDownloadLatest(c *gin.Context) {
	packages, err := h.listPackages()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if len(packages) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "no published security tool packages"})
		return
	}
	h.sendPackage(c, packages[0].ID)
}

func (h *SecurityToolsHandler) PublicDownload(c *gin.Context) {
	h.sendPackage(c, c.Param("id"))
}

func (h *SecurityToolsHandler) List(c *gin.Context) {
	h.PublicList(c)
}

func (h *SecurityToolsHandler) Upload(c *gin.Context) {
	if err := c.Request.ParseMultipartForm(maxSecurityToolPackageBytes); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid multipart form"})
		return
	}
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing file"})
		return
	}
	defer file.Close()

	originalName := strings.TrimSpace(header.Filename)
	if originalName == "" {
		originalName = "security-tools.zip"
	}
	if !strings.HasSuffix(strings.ToLower(originalName), ".zip") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "only .zip packages are supported"})
		return
	}
	if header.Size > maxSecurityToolPackageBytes {
		c.JSON(http.StatusBadRequest, gin.H{"error": "package too large"})
		return
	}

	root, err := h.packagesRoot()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	id := time.Now().Format("20060102-150405") + "-" + safeSecurityToolFileName(strings.TrimSuffix(originalName, filepath.Ext(originalName)))
	fileName := id + ".zip"
	dstPath := filepath.Join(root, fileName)
	dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	written, copyErr := io.Copy(dst, io.LimitReader(file, maxSecurityToolPackageBytes+1))
	closeErr := dst.Close()
	if copyErr != nil || closeErr != nil {
		_ = os.Remove(dstPath)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save package"})
		return
	}
	if written > maxSecurityToolPackageBytes {
		_ = os.Remove(dstPath)
		c.JSON(http.StatusBadRequest, gin.H{"error": "package too large"})
		return
	}

	pkg := SecurityToolPackage{
		ID:          id,
		Name:        strings.TrimSpace(c.PostForm("name")),
		Description: strings.TrimSpace(c.PostForm("description")),
		FileName:    fileName,
		Size:        written,
		UploadedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	if pkg.Name == "" {
		pkg.Name = strings.TrimSuffix(originalName, filepath.Ext(originalName))
	}
	packages, _ := h.listPackages()
	packages = append([]SecurityToolPackage{pkg}, packages...)
	if err := h.savePackages(packages); err != nil {
		_ = os.Remove(dstPath)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"package": pkg})
}

func (h *SecurityToolsHandler) Delete(c *gin.Context) {
	id := strings.TrimSpace(c.Param("id"))
	packages, err := h.listPackages()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	next := make([]SecurityToolPackage, 0, len(packages))
	var removed *SecurityToolPackage
	for i := range packages {
		pkg := packages[i]
		if pkg.ID == id {
			removed = &pkg
			continue
		}
		next = append(next, pkg)
	}
	if removed == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "package not found"})
		return
	}
	if err := h.savePackages(next); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	root, _ := h.packagesRoot()
	_ = os.Remove(filepath.Join(root, filepath.Base(removed.FileName)))
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (h *SecurityToolsHandler) sendPackage(c *gin.Context, id string) {
	id = strings.TrimSpace(id)
	packages, err := h.listPackages()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	for _, pkg := range packages {
		if pkg.ID != id {
			continue
		}
		root, err := h.packagesRoot()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		path := filepath.Join(root, filepath.Base(pkg.FileName))
		if _, err := os.Stat(path); err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "package file not found"})
			return
		}
		downloadName := safeSecurityToolFileName(pkg.Name)
		if downloadName == "" {
			downloadName = pkg.ID
		}
		c.Header("Content-Type", "application/zip")
		c.Header("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": downloadName + ".zip"}))
		c.File(path)
		return
	}
	c.JSON(http.StatusNotFound, gin.H{"error": "package not found"})
}

func (h *SecurityToolsHandler) listPackages() ([]SecurityToolPackage, error) {
	root, err := h.packagesRoot()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(root, securityToolIndexFileName))
	if os.IsNotExist(err) {
		return []SecurityToolPackage{}, nil
	}
	if err != nil {
		return nil, err
	}
	var packages []SecurityToolPackage
	if err := json.Unmarshal(data, &packages); err != nil {
		return nil, fmt.Errorf("parse security tool index: %w", err)
	}
	sort.SliceStable(packages, func(i, j int) bool {
		return packages[i].UploadedAt > packages[j].UploadedAt
	})
	return packages, nil
}

func (h *SecurityToolsHandler) savePackages(packages []SecurityToolPackage) error {
	root, err := h.packagesRoot()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(packages, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, securityToolIndexFileName), data, 0o644)
}

func (h *SecurityToolsHandler) packagesRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.Abs(filepath.Join(cwd, securityToolPackagesDirName))
}

func safeSecurityToolFileName(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	replacer := strings.NewReplacer("/", "-", "\\", "-", ":", "-", "*", "-", "?", "-", "\"", "-", "<", "-", ">", "-", "|", "-", "\n", "-", "\r", "-")
	name = replacer.Replace(name)
	name = strings.Join(strings.Fields(name), "-")
	name = strings.Trim(name, ".-_")
	if len(name) > 96 {
		name = name[:96]
	}
	if name == "." || name == ".." {
		return ""
	}
	return name
}
