use tempfile;
use zf_zebrachaos::{HEADER, Hash, Item, Kind, Repository, Store, Tree, finalize_object};

#[test]
fn test_repository_snapshot_restore() {
    let expected_hash =
        Hash::from_z32(b"QKGAAQM4VOTLPF7K69GPSID4WBNNAHE7G99UBIMBOV4SJQPV4AFB5AJ8V5ZERXRNWU5KFEFC")
            .unwrap();

    let tmp1 = tempfile::TempDir::new().unwrap();
    let filename = tmp1.path().join("chaos.data");
    let mut store = Store::create(&filename).unwrap();
    let mut buf = vec![0x42; HEADER + 1];

    let file_hash = {
        let obj = finalize_object(Kind::Data as u8, &mut buf).unwrap();
        assert!(store.save(&obj).unwrap());
        *obj.header().hash()
    };

    let src_hash = {
        let mut src = Tree::new();
        src.insert(String::from("main.rs"), Item::File(file_hash.clone()))
            .unwrap();
        let obj = src.finalize_into(&mut buf).unwrap();
        assert!(store.save(&obj).unwrap());
        *obj.header().hash()
    };

    let tree_hash = {
        let mut tree = Tree::new();
        tree.insert(String::from("src"), Item::Tree(src_hash))
            .unwrap();
        tree.insert(String::from("one_byte.txt"), Item::File(file_hash.clone()))
            .unwrap();
        tree.insert(String::from("tests"), Item::EmptyTree).unwrap();
        tree.insert(String::from("README.md"), Item::EmptyFile)
            .unwrap();
        let obj = tree.finalize_into(&mut buf).unwrap();
        assert!(store.save(&obj).unwrap());
        *obj.header().hash()
    };
    assert_eq!(tree_hash, expected_hash);
    assert_eq!(store.count(), 3);

    let mut repo = Repository::new(store);
    let tmp2 = tempfile::TempDir::new().unwrap();
    repo.restore(&expected_hash, tmp2.path()).unwrap();
    assert_eq!(
        repo.snapshot(tmp2.path()).unwrap(),
        Item::Tree(expected_hash)
    );
}
