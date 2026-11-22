use tempfile;
use zf_zebrachaos::{Hash, Item, Repository, Store, Tree};

#[test]
fn test_repository_snapshot_restore() {
    let expected_hash =
        Hash::from_z32(b"LLG9NEB5QGINAB9FGIPGKY4L69YO96PZHYRD4WVMX8DGYGO9TAIDFL74MNY5VZO6PZDKFVLC")
            .unwrap();

    let tmp1 = tempfile::TempDir::new().unwrap();
    let filename = tmp1.path().join("chaos.data");
    let mut store = Store::create(&filename).unwrap();
    let mut buf = Vec::new();
    let mut tree = Tree::new();

    tree.insert(String::from("tests"), Item::EmptyTree).unwrap();
    tree.insert(String::from("README.md"), Item::EmptyFile)
        .unwrap();
    let obj = tree.finalize_into(&mut buf).unwrap();
    assert!(store.save(&obj).unwrap());
    assert_eq!(obj.header().hash(), &expected_hash);

    let mut repo = Repository::new(store);
    let tmp2 = tempfile::TempDir::new().unwrap();
    repo.restore(&expected_hash, tmp2.path()).unwrap();
    assert_eq!(
        repo.snapshot(tmp2.path()).unwrap(),
        Item::Tree(expected_hash)
    );
}
