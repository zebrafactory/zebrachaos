use std::io::ErrorKind;
use tempfile;
use zf_zebrachaos::{Kind, MutObject, ObjectError, Store};

#[test]
fn test_store_create_open() {
    let tmp = tempfile::TempDir::new().unwrap();
    let filename = tmp.path().join("chaos.data");

    assert_eq!(
        Store::open(&filename).unwrap_err().kind(),
        ErrorKind::NotFound
    );

    let store = Store::create(&filename).unwrap();
    assert_eq!(store.count(), 0);
    assert_eq!(store.data_total(), 0);
    assert_eq!(store.total(), 0);

    assert_eq!(
        Store::create(&filename).unwrap_err().kind(),
        ErrorKind::AlreadyExists
    );

    let store = Store::open(&filename).unwrap();
    assert_eq!(store.count(), 0);
    assert_eq!(store.data_total(), 0);
    assert_eq!(store.total(), 0);
}

#[test]
fn test_store_load_kind() {
    let tmp = tempfile::TempDir::new().unwrap();
    let filename = tmp.path().join("chaos.data");
    let mut store = Store::create(&filename).unwrap();
    let mut buf = Vec::new();
    let mut obj = MutObject::new(Kind::Data, &mut buf);
    obj.try_extend_from_slice(b"hello, world").unwrap();
    let obj = obj.finalize().unwrap();
    let hash = *obj.header().hash();

    assert!(store.load_kind(Kind::Data, &hash, &mut vec![]).is_none());
    assert!(
        store
            .load_kind(Kind::MegaData, &hash, &mut vec![])
            .is_none()
    );
    store.save(&obj).unwrap();

    let obj = store
        .load_kind(Kind::Data, &hash, &mut buf)
        .unwrap()
        .unwrap();
    assert_eq!(obj.as_data(), b"hello, world");
    assert_eq!(obj.header().try_kind().unwrap(), Kind::Data);

    assert_eq!(
        store
            .load_kind(Kind::MegaData, &hash, &mut buf)
            .unwrap()
            .unwrap_err()
            .into_inner()
            .unwrap()
            .downcast()
            .unwrap(),
        Box::new(ObjectError::ExpectedKind(Kind::MegaData, Kind::Data))
    );
}
