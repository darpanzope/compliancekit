package ui

// v1.12 phase 8 — /settings/backups UI.
//
// List existing backups, trigger a fresh dump, restore from a backup
// (download + restart guidance), delete a stale entry. Admin-only.

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/darpanzope/compliancekit/internal/server/auth"
	"github.com/darpanzope/compliancekit/internal/server/backups"
)

// backupMgr lazily-constructs the backups handle. The dir comes from
// CK_BACKUP_DIR env var; the daemon's CLI wires that through on boot
// via SetBackupDir.
func (u *UI) backupMgr() *backups.Manager {
	if u.backups == nil {
		dir := u.backupDir
		if dir == "" {
			dir = "./.backups"
		}
		u.backups = backups.New(u.store, dir, u.backupDSN)
	}
	return u.backups
}

// SetBackupConfig installs the dump-output directory + postgres DSN
// (empty for SQLite). Called by cmd/serve at boot.
func (u *UI) SetBackupConfig(dir, dsn string) {
	u.backupDir = dir
	u.backupDSN = dsn
	// Reset the lazy handle so the next call to backupMgr picks up the
	// new config.
	u.backups = nil
}

func (u *UI) mountBackupsRoutes(r chi.Router) {
	r.Get("/settings/backups", u.adminOnly(u.backupsList))
	r.Post("/settings/backups", u.adminOnly(u.backupsCreate))
	r.Get("/settings/backups/{id}/download", u.adminOnly(u.backupsDownload))
	r.Post("/settings/backups/{id}/delete", u.adminOnly(u.backupsDelete))
}

type backupsListView struct {
	View
	Backups []backupRow
	Dir     string
}

type backupRow struct {
	ID         string
	CreatedAgo string
	Kind       string
	Path       string
	SizeMB     string
	Status     string
	Note       string
}

func (u *UI) backupsList(w http.ResponseWriter, r *http.Request) {
	items, err := u.backupMgr().List(r.Context())
	if err != nil {
		u.fail(w, "list backups: "+err.Error())
		return
	}
	rows := make([]backupRow, 0, len(items))
	for _, b := range items {
		rows = append(rows, backupRow{
			ID:         b.ID,
			CreatedAgo: humanizeAgo(b.CreatedAt.UTC().Format("2006-01-02T15:04:05Z")),
			Kind:       b.Kind,
			Path:       b.Path,
			SizeMB:     fmt.Sprintf("%.2f", float64(b.SizeBytes)/(1024.0*1024.0)),
			Status:     b.Status,
			Note:       b.Note,
		})
	}
	view := backupsListView{
		View:    u.viewFor(r, "Backups", "settings", View{Flash: r.URL.Query().Get("flash")}),
		Backups: rows,
		Dir:     u.backupMgr().Dir(),
	}
	u.render(w, "backups_list.html", view)
}

func (u *UI) backupsCreate(w http.ResponseWriter, r *http.Request) {
	note := r.FormValue("note")
	triggeredBy := ""
	if sess := auth.FromContext(r.Context()); sess != nil {
		triggeredBy = sess.UserID
	}
	b, err := u.backupMgr().Create(r.Context(), note, triggeredBy)
	if err != nil {
		http.Redirect(w, r, "/settings/backups?flash=error", http.StatusSeeOther)
		return
	}
	u.AuditLog(r.Context(), "backup.create", "backup", b.ID, map[string]any{
		"path": b.Path,
		"kind": b.Kind,
	})
	http.Redirect(w, r, "/settings/backups?flash=created", http.StatusSeeOther)
}

func (u *UI) backupsDownload(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	b, err := u.backupMgr().ByID(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if b.Kind == "sqlite" {
		w.Header().Set("Content-Type", "application/x-sqlite3")
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+b.ID+`.dump"`)
	http.ServeFile(w, r, b.Path)
}

func (u *UI) backupsDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := u.backupMgr().Delete(r.Context(), id); err != nil {
		http.Redirect(w, r, "/settings/backups?flash=error", http.StatusSeeOther)
		return
	}
	u.AuditLog(r.Context(), "backup.delete", "backup", id, nil)
	http.Redirect(w, r, "/settings/backups?flash=deleted", http.StatusSeeOther)
}
