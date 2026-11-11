//! Repository discovery and temporary detached Git worktree management.
//!
//! Supports both standard `.git` checkouts (used by GitHub Actions and `git`
//! clones) and non-colocated Jujutsu (`.jj/repo/store/git`) workspaces.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
enum VcsBackend {
    Git,
    Jj { git_dir: PathBuf },
}

/// Temporary scratch directory holding detached worktrees and copied ELF outputs.
///
/// Automatically detaches any temporary `git worktree` checkouts and deletes
/// the scratch directory on [`Drop`].
pub(crate) struct ScratchWorkspace {
    repo_root: PathBuf,
    backend: VcsBackend,
    scratch_dir: PathBuf,
    elf_dir: PathBuf,
    worktrees: Vec<PathBuf>,
}

/// Resolved source tree for either `head` or `base`.
#[derive(Debug, Clone)]
pub(crate) struct ResolvedTree {
    pub(crate) label: String,
    pub(crate) root: PathBuf,
    pub(crate) target_dir: PathBuf,
}

impl ScratchWorkspace {
    pub(crate) fn new() -> Result<Self, String> {
        let repo_root = find_repo_root()?;
        let backend = detect_backend(&repo_root)?;
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let scratch_dir =
            std::env::temp_dir().join(format!("tpm-rs-size-{}-{stamp}", std::process::id()));
        let elf_dir = scratch_dir.join("elfs");
        fs::create_dir_all(&elf_dir).map_err(|err| {
            format!(
                "failed to create scratch directory `{}`: {err}",
                elf_dir.display()
            )
        })?;
        Ok(Self {
            repo_root,
            backend,
            scratch_dir,
            elf_dir,
            worktrees: Vec::new(),
        })
    }

    pub(crate) fn elf_dir(&self) -> &Path {
        &self.elf_dir
    }

    /// Resolves and prepares a revision directory (`slot` is `"head"` or `"base"`).
    ///
    /// Special revision `"WORKDIR"` always uses the live repository tree directly,
    /// as does `"HEAD"` / `"@"` inside a non-colocated Jujutsu workspace (where
    /// the working tree *is* `@`). All committed revisions are materialized into
    /// clean detached `git worktree` directories under `scratch_dir`.
    pub(crate) fn checkout(&mut self, slot: &str, rev: &str) -> Result<ResolvedTree, String> {
        if rev == "WORKDIR" {
            return Ok(ResolvedTree {
                label: String::from("WORKDIR"),
                target_dir: self.repo_root.join("target").join("size-harness"),
                root: self.repo_root.clone(),
            });
        }

        match &self.backend {
            VcsBackend::Git => {
                let sha = git_rev_parse(None, &self.repo_root, rev)?;
                let short = short_sha(&sha);
                let label = format!("{rev} ({short})");
                if rev == "HEAD" && is_clean_git_workdir(&self.repo_root) {
                    return Ok(ResolvedTree {
                        label,
                        target_dir: self.repo_root.join("target").join("size-harness"),
                        root: self.repo_root.clone(),
                    });
                }
                let wt_dir = self.scratch_dir.join(format!("wt-{slot}"));
                add_worktree(None, &self.repo_root, &wt_dir, &sha)?;
                self.worktrees.push(wt_dir.clone());
                Ok(ResolvedTree {
                    label,
                    target_dir: self.scratch_dir.join(format!("target-{slot}")),
                    root: wt_dir,
                })
            }
            VcsBackend::Jj { git_dir } => {
                let jj_rev = map_git_rev_to_jj(rev);
                if jj_rev == "@" {
                    let short = resolve_jj_commit_id(&self.repo_root, "@")
                        .map(|s| short_sha(&s).to_owned())
                        .unwrap_or_else(|_| String::from("working-copy"));
                    return Ok(ResolvedTree {
                        label: format!("{rev} ({short})"),
                        target_dir: self.repo_root.join("target").join("size-harness"),
                        root: self.repo_root.clone(),
                    });
                }
                let sha = resolve_jj_commit_id(&self.repo_root, jj_rev)
                    .or_else(|_| git_rev_parse(Some(git_dir), &self.repo_root, rev))?;
                let short = short_sha(&sha);
                let git_dir_clone = git_dir.clone();
                let wt_dir = self.scratch_dir.join(format!("wt-{slot}"));
                add_worktree(Some(&git_dir_clone), &self.repo_root, &wt_dir, &sha)?;
                self.worktrees.push(wt_dir.clone());
                Ok(ResolvedTree {
                    label: format!("{rev} ({short})"),
                    target_dir: self.scratch_dir.join(format!("target-{slot}")),
                    root: wt_dir,
                })
            }
        }
    }
}

impl Drop for ScratchWorkspace {
    fn drop(&mut self) {
        let git_dir = match &self.backend {
            VcsBackend::Git => None,
            VcsBackend::Jj { git_dir } => Some(git_dir.as_path()),
        };
        for wt in &self.worktrees {
            let mut cmd = git_cmd(git_dir, &self.repo_root);
            let _ = cmd.args(["worktree", "remove", "--force"]).arg(wt).output();
            let _ = fs::remove_dir_all(wt);
        }
        if !self.worktrees.is_empty() {
            let mut prune = git_cmd(git_dir, &self.repo_root);
            let _ = prune.args(["worktree", "prune"]).output();
        }
        let _ = fs::remove_dir_all(&self.scratch_dir);
    }
}

fn find_repo_root() -> Result<PathBuf, String> {
    if let Some(manifest_dir) = option_env!("CARGO_MANIFEST_DIR") {
        let candidate = Path::new(manifest_dir)
            .parent()
            .and_then(Path::parent)
            .map(Path::to_path_buf);
        if let Some(root) = candidate.filter(|p| p.join("Cargo.toml").is_file()) {
            return Ok(root);
        }
    }
    let cwd = std::env::current_dir().map_err(|e| format!("failed to read current_dir: {e}"))?;
    for ancestor in cwd.ancestors() {
        if ancestor.join("Cargo.toml").is_file()
            && (ancestor.join(".git").exists() || ancestor.join(".jj").is_dir())
        {
            return Ok(ancestor.to_path_buf());
        }
    }
    Err(String::from(
        "could not locate tpm-rs repository root containing Cargo.toml and .git/.jj",
    ))
}

fn detect_backend(repo_root: &Path) -> Result<VcsBackend, String> {
    if repo_root.join(".git").exists() {
        return Ok(VcsBackend::Git);
    }
    let jj_git = repo_root.join(".jj/repo/store/git");
    if jj_git.is_dir() {
        return Ok(VcsBackend::Jj { git_dir: jj_git });
    }
    // Support secondary `jj workspace add` checkouts where `.jj/repo` is a file
    // pointing to the primary repo's `.jj/repo` directory.
    let jj_repo_ptr = repo_root.join(".jj/repo");
    if jj_repo_ptr.is_file()
        && let Ok(ptr) = fs::read_to_string(&jj_repo_ptr)
    {
        let resolved = repo_root.join(".jj").join(ptr.trim()).join("store/git");
        if resolved.is_dir() {
            return Ok(VcsBackend::Jj { git_dir: resolved });
        }
    }
    Err(format!(
        "no `.git` or `.jj/repo/store/git` metadata found in `{}`",
        repo_root.display()
    ))
}

pub(crate) fn map_git_rev_to_jj(rev: &str) -> &str {
    match rev {
        "HEAD" => "@",
        "HEAD^" | "HEAD^1" | "HEAD~1" => "@-",
        other => other,
    }
}

fn short_sha(sha: &str) -> &str {
    sha.get(..12).unwrap_or(sha)
}

fn git_cmd(git_dir: Option<&Path>, repo_root: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.current_dir(repo_root);
    if let Some(dir) = git_dir {
        cmd.arg("--git-dir").arg(dir);
    }
    cmd
}

fn git_rev_parse(git_dir: Option<&Path>, repo_root: &Path, rev: &str) -> Result<String, String> {
    let spec = format!("{rev}^{{commit}}");
    let output = git_cmd(git_dir, repo_root)
        .args(["rev-parse", "--verify", "--quiet", &spec])
        .output()
        .map_err(|err| format!("failed to execute `git rev-parse`: {err}"))?;
    if !output.status.success() {
        return Err(format!("revision `{rev}` could not be resolved in Git"));
    }
    let sha = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if sha.is_empty() {
        return Err(format!("`git rev-parse` returned empty SHA for `{rev}`"));
    }
    Ok(sha)
}

fn resolve_jj_commit_id(repo_root: &Path, revset: &str) -> Result<String, String> {
    let output = Command::new("jj")
        .current_dir(repo_root)
        .args([
            "log",
            "--ignore-working-copy",
            "--no-graph",
            "-r",
            revset,
            "-T",
            "commit_id ++ \"\\n\"",
        ])
        .output()
        .map_err(|err| format!("failed to execute `jj`: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "jj could not resolve `{revset}`: {}",
            stderr.lines().next().unwrap_or("unknown error").trim()
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut lines = stdout.lines().filter(|l| !l.trim().is_empty());
    let first = lines
        .next()
        .ok_or_else(|| format!("jj returned no commits for `{revset}`"))?
        .trim();
    if lines.next().is_some() {
        return Err(format!("jj revset `{revset}` resolved to multiple commits"));
    }
    Ok(first.to_owned())
}

fn is_clean_git_workdir(repo_root: &Path) -> bool {
    Command::new("git")
        .current_dir(repo_root)
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()
        .is_ok_and(|out| out.status.success() && out.stdout.is_empty())
}

fn add_worktree(
    git_dir: Option<&Path>,
    repo_root: &Path,
    wt_dir: &Path,
    sha: &str,
) -> Result<(), String> {
    let output = git_cmd(git_dir, repo_root)
        .args(["worktree", "add", "--force", "--detach"])
        .arg(wt_dir)
        .arg(sha)
        .output()
        .map_err(|err| format!("failed to run `git worktree add`: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "`git worktree add` failed for `{sha}`: {}",
            stderr.trim()
        ));
    }
    Ok(())
}
