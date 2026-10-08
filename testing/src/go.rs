pub(crate) mod activate_credential;
pub(crate) mod audit;
pub(crate) mod certify;
pub(crate) mod clear;
pub(crate) mod combined_context;
pub(crate) mod commit;
pub(crate) mod create_loaded;
pub(crate) mod duplicate;
pub(crate) mod ecdh;
pub(crate) mod ek;
pub(crate) mod evict_control;
pub(crate) mod get_random;
pub(crate) mod get_time;
pub(crate) mod hash_sequence_hash;
pub(crate) mod hierarchy_change_auth;
pub(crate) mod hmac;
pub(crate) mod hmac_start;
pub(crate) mod import;
pub(crate) mod load_external;
pub(crate) mod names;
pub(crate) mod nv;
pub(crate) mod object_change_auth;
pub(crate) mod pcr;
pub(crate) mod policy;
pub(crate) mod read_public;
pub(crate) mod rsa_encryption;
pub(crate) mod sealing;
pub(crate) mod sign;
pub(crate) mod symmetric_encryption;
pub(crate) mod test_parms;

#[test]
fn test_every_go_test_has_original_go_test_comment() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/go");
    let dir = if dir.exists() {
        dir
    } else {
        std::path::Path::new(file!())
            .parent()
            .expect("file!() should have a parent directory")
            .join("go")
    };
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .expect("Failed to read src/go directory")
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.file_name());
    assert_eq!(entries.len(), 30, "Expected 30 Rust files in src/go/");

    for entry in entries {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let stem = path.file_stem().unwrap().to_str().unwrap();
        let expected_prefix = format!("// Original Go test: {}_test.go - ", stem);
        let content = std::fs::read_to_string(&path).expect("Failed to read Rust Go test file");
        let lines: Vec<&str> = content.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            if line.trim() == "#[test]" {
                assert!(
                    i > 0,
                    "File {:?} has #[test] at line 1 without preceding comment",
                    path
                );
                let prev_line = lines[i - 1].trim();
                assert!(
                    prev_line.starts_with(&expected_prefix),
                    "File {:?} line {} (#[test]) must be preceded by `{}` but found `{}`",
                    path,
                    i + 1,
                    expected_prefix,
                    prev_line
                );
            }
        }
    }
}
